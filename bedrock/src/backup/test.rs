use crate::backup::backup_format::v0::{V0Backup, V0BackupFile};
use crate::backup::backup_format::BackupFormat;
use crate::backup::BackupManager;
use crate::backup::BackupManifest;
use crate::backup::BackupModule;
use crate::backup::FactorType;
use crate::backup::OxideKey;
use crate::backup::PersonalCustodyKeypair;
use chrono::Utc;
use crypto_box::{PublicKey, SecretKey};
use dryoc::rng;
use std::str::FromStr;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

fn helper_write_manifest_file(
    file_system: &dyn DeviceFileSystem,
    module_name: &str,
    data: Option<Vec<u8>>,
    custom_file_path: Option<String>,
) {
    let file_path = custom_file_path.unwrap_or_else(|| {
        format!(
            "/somewhere/{}/{module_name}_{}.bin",
            hex::encode(rng::randombytes_buf(4)),
            hex::encode(rng::randombytes_buf(4))
        )
    });

    let manifest = BackupManifest::new(
        file_path.clone(),
        Utc::now(),
        1024,
        module_name.to_string(),
    )
    .unwrap();

    // write the manifest
    file_system.write_file(
        format!(
            "{}/backup_manifests/{module_name}",
            file_system.get_user_data_directory()
        ),
        serde_json::to_vec(&manifest).unwrap(),
    );

    if let Some(data) = data {
        // write the actual file
        file_system.write_file(
            format!("{}{file_path}", file_system.get_user_data_directory()),
            data,
        );
    }
}

#[test]
fn test_backup_module_enum() {
    assert_eq!(
        BackupModule::PersonalCustody.to_string(),
        "personal_custody".to_string()
    );
    assert_eq!(
        BackupModule::DocumentPersonalCustody.to_string(),
        "document_personal_custody".to_string()
    );

    assert_eq!(
        BackupModule::from_str("personal_custody").unwrap(),
        BackupModule::PersonalCustody
    );
    assert_eq!(
        BackupModule::from_str("document_personal_custody").unwrap(),
        BackupModule::DocumentPersonalCustody
    );

    assert_eq!(
        serde_json::to_string(&BackupModule::PersonalCustody).unwrap(),
        "\"personal_custody\""
    );
    assert_eq!(
        serde_json::to_string(&BackupModule::DocumentPersonalCustody).unwrap(),
        "\"document_personal_custody\""
    );
}

#[test]
fn test_create_sealed_backup_with_prf_for_new_user() {
    let manager = BackupManager::new();

    // Example root secret seed
    let root_secret =
        "1810f739487f5447c01df40e57d38885caad51912851f1cbdd69117fe3641d1b".to_string();
    // Example passkey PRF result - converted from base64url "Z6myXXzS4Ry6eBrx1L6Rxz01YeWo-8KQTLbC8nSsrjc=" to hex
    let prf_result =
        "67a9b25d7cd2e11cba781af1d4be91c73d3561e5a8fbc2904cb6c2f274acae37".to_string();

    let result = manager
        .create_sealed_backup_for_new_user(
            root_secret.clone(),
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
        PersonalCustodyKeypair::from_private_key_bytes(decrypted_backup_keypair_bytes);
    let decrypted_backup = decrypted_backup_keypair
        .sk()
        .unseal(&result.sealed_backup_data)
        .unwrap();
    assert_eq!(
        BackupFormat::from_bytes(&decrypted_backup).unwrap(),
        BackupFormat::V0(V0Backup {
            root_secret: OxideKey::decode(root_secret.clone()).unwrap(),
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
        root_secret: OxideKey::decode(root_secret).unwrap(),
        files: vec![V0BackupFile {
            data: b"Hello, World!".to_vec(),
            checksum: hex::decode(
                "288a86a79f20a3d6dccdca7713beaed178798296bdfa7913fa2a62d9727bf8f8",
            )
            .unwrap(),
            path: "/documents/file1.txt".to_string(),
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
    let root_secret =
        "1810f739487f5447c01df40e57d38885caad51912851f1cbdd69117fe3641d1b".to_string();
    // Example passkey PRF result - converted from base64url "Z6myXXzS4Ry6eBrx1L6Rxz01YeWo-8KQTLbC8nSsrjc=" to hex
    let prf_result =
        "67a9b25d7cd2e11cba781af1d4be91c73d3561e5a8fbc2904cb6c2f274acae37".to_string();

    let create_result = manager
        .create_sealed_backup_for_new_user(
            root_secret.clone(),
            prf_result.clone(),
            FactorType::Prf,
        )
        .expect("Failed to create sealed backup with PRF for new user");

    // Decrypt it
    let decrypted = manager
        .decrypt_sealed_backup(
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
        decrypted.backup,
        BackupFormat::V0(V0Backup {
            root_secret: OxideKey::decode(root_secret).unwrap(),
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
        .decrypt_sealed_backup(
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
fn test_re_encrypt_backup() {
    let manager = BackupManager::new();

    // Example root secret seed
    let root_secret =
        "1810f739487f5447c01df40e57d38885caad51912851f1cbdd69117fe3641d1b".to_string();
    // Example passkey PRF result - converted from base64url "Z6myXXzS4Ry6eBrx1L6Rxz01YeWo-8KQTLbC8nSsrjc=" to hex
    let prf_result =
        "67a9b25d7cd2e11cba781af1d4be91c73d3561e5a8fbc2904cb6c2f274acae37".to_string();
    // New factor secret
    let new_factor_secret = SecretKey::generate(&mut rand::thread_rng());

    let create_result = manager
        .create_sealed_backup_for_new_user(
            root_secret.clone(),
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
        PersonalCustodyKeypair::from_private_key_bytes(decrypted_backup_keypair_bytes);
    let decrypted_backup = decrypted_backup_keypair
        .sk()
        .unseal(&create_result.sealed_backup_data)
        .expect("Failed to decrypt backup data");

    assert_eq!(
        BackupFormat::from_bytes(&decrypted_backup).unwrap(),
        BackupFormat::V0(V0Backup {
            root_secret: OxideKey::decode(root_secret).unwrap(),
            files: vec![]
        })
    );

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

#[test]
fn test_update_backup_end_to_end_success() {
    let manager = BackupManager::new();

    let file_system = Arc::new(TestInMemoryDeviceFileSystem::new());

    // Example root secret seed
    let root_secret =
        "1810f739487f5447c01df40e57d38885caad51912851f1cbdd69117fe3641d1b".to_string();
    // Example passkey PRF result - converted from base64url "Z6myXXzS4Ry6eBrx1L6Rxz01YeWo-8KQTLbC8nSsrjc=" to hex
    let prf_result =
        "67a9b25d7cd2e11cba781af1d4be91c73d3561e5a8fbc2904cb6c2f274acae37".to_string();

    // First create a backup
    let create_result = manager
        .create_sealed_backup_for_new_user(
            root_secret,
            prf_result.clone(),
            FactorType::Prf,
        )
        .expect("Failed to create sealed backup with PRF for new user");

    // Create a new root secret to update the backup
    let root_secret =
        "2910f739487f5447c01df40e57d38885caad51912851f1cbdd69117fe3641d1c".to_string();

    // Add some files to the backup
    helper_write_manifest_file(
        file_system.as_ref(),
        "personal_custody",
        Some(b"Hello, World!".to_vec()),
        None,
    );
    helper_write_manifest_file(
        file_system.as_ref(),
        "document_personal_custody",
        Some(b"{\"key\": \"value\"}".to_vec()),
        None,
    );

    // Add a red herring manifest to make sure it is ignored
    let red_herring_manifest = "{\"V0\":{\"file_path\":\"/somewhere/red_herring.bin\",\"save_as\":\"red_herring.bin\",\"manifest_last_updated_at\":\"2025-07-31T16:45:33.900104Z\",\"max_file_size_kb\":1024,\"module_name\":\"red_herring\"}}";

    file_system.write_file(
        "/backup_manifests/red_herring".to_string(),
        red_herring_manifest.as_bytes().to_vec(),
    );

    // Update the backup
    let updated_backup = manager
        .new_updated_sealed_backup(
            root_secret.clone(),
            file_system.clone(),
            create_result.backup_keypair_public_key.clone(),
        )
        .expect("Failed to update sealed backup")
        .expect("This operation should require a file update.");

    // acknowledge the backup update and ensure it's properly stored
    manager.acknowledge_backup_update(
        file_system.clone(),
        updated_backup.backup_update_id,
    );

    let latest_backup_checkpoint = file_system
        .read_file(format!(
            "{}/backup/checkpoint/latest.json",
            file_system.get_user_data_directory()
        ))
        .unwrap();

    let latest_backup_checkpoint: LocalBackupCheckpoint =
        serde_json::from_slice(&latest_backup_checkpoint).unwrap();
    let LocalBackupCheckpoint::V0(files) = latest_backup_checkpoint;
    assert_eq!(
        files[0].checksum,
        blake3::hash(b"{\"key\": \"value\"}").as_bytes().to_vec()
    );

    // Verify the backup has been updated by decrypting it
    let decrypted = manager
        .decrypt_sealed_backup(
            &updated_backup.sealed_backup_data,
            create_result.encrypted_backup_keypair.clone(),
            prf_result,
            FactorType::Prf,
        )
        .unwrap();

    assert_eq!(
        decrypted.backup_keypair_public_key,
        create_result.backup_keypair_public_key
    );

    // Verify the updated backup has the new root secret and files
    match decrypted.backup {
        BackupFormat::V0(backup) => {
            assert_eq!(
                backup.root_secret,
                OxideKey::decode(root_secret.clone()).unwrap()
            );
            assert_eq!(backup.files.len(), 2); // note how red_herring is not included
            assert_eq!(backup.files[0].name, "document_personal_custody.bin");
            assert_eq!(backup.files[0].data, b"{\"key\": \"value\"}".to_vec());
            assert_eq!(
                backup.files[0].checksum,
                blake3::hash(b"{\"key\": \"value\"}").as_bytes().to_vec()
            );
            assert_eq!(
                backup.files[0].module_name,
                BackupModule::DocumentPersonalCustody
            );
            assert_eq!(backup.files[1].name, "personal_custody.bin");
            assert_eq!(backup.files[1].data, b"Hello, World!".to_vec());
            assert_eq!(
                backup.files[1].checksum,
                hex::decode(
                    "288a86a79f20a3d6dccdca7713beaed178798296bdfa7913fa2a62d9727bf8f8"
                )
                .unwrap()
            );
            assert_eq!(backup.files[1].module_name, BackupModule::PersonalCustody);
        }
    }

    // Test with invalid backup keypair public key
    helper_write_manifest_file(
        file_system.as_ref(),
        "document_personal_custody",
        Some(b"{\"key\": \"new_value\"}".to_vec()),
        None,
    );
    let invalid_public_key = "invalid_key".to_string();
    let update_error = manager
        .new_updated_sealed_backup(root_secret, file_system, invalid_public_key)
        .expect_err("Expected update to fail with invalid backup keypair public key");
    assert_eq!(update_error.to_string(), "Failed to decode backup keypair");
}

#[test]
fn test_update_backup_when_no_update_is_required_success() {
    let manager = BackupManager::new();

    let file_system = Arc::new(TestInMemoryDeviceFileSystem::new());

    // Example root secret seed
    let root_secret =
        "1810f739487f5447c01df40e57d38885caad51912851f1cbdd69117fe3641d1b".to_string();
    // Example passkey PRF result - converted from base64url "Z6myXXzS4Ry6eBrx1L6Rxz01YeWo-8KQTLbC8nSsrjc=" to hex
    let prf_result =
        "67a9b25d7cd2e11cba781af1d4be91c73d3561e5a8fbc2904cb6c2f274acae37".to_string();

    // First create a backup
    let create_result = manager
        .create_sealed_backup_for_new_user(
            root_secret,
            prf_result.clone(),
            FactorType::Prf,
        )
        .expect("Failed to create sealed backup with PRF for new user");

    // Create a new root secret to update the backup
    let root_secret =
        "2910f739487f5447c01df40e57d38885caad51912851f1cbdd69117fe3641d1c".to_string();

    // Add some files to the backup
    helper_write_manifest_file(
        file_system.as_ref(),
        "personal_custody",
        Some(b"Hallo, Welt!".to_vec()),
        None,
    );

    // Initial update to create the backup checkpoint
    let updated_backup = manager
        .new_updated_sealed_backup(
            root_secret.clone(),
            file_system.clone(),
            create_result.backup_keypair_public_key.clone(),
        )
        .expect("Failed to update sealed backup")
        .expect("This operation should require a file update.");

    // check the backup checkpoint candidate was created
    let backup_checkpoint_candidate = file_system
        .read_file(format!(
            "{}/backup/checkpoint/{}.json",
            file_system.get_user_data_directory(),
            updated_backup.backup_update_id
        ))
        .unwrap();

    let backup_checkpoint_candidate: LocalBackupCheckpoint =
        serde_json::from_slice(&backup_checkpoint_candidate).unwrap();
    let LocalBackupCheckpoint::V0(files) = backup_checkpoint_candidate;
    assert_eq!(files.len(), 1);
    assert_eq!(files[0].name, "personal_custody.bin");
    assert!(files[0].data.is_empty());
    assert_eq!(
        files[0].checksum,
        blake3::hash(b"Hallo, Welt!").as_bytes().to_vec()
    );

    // Now we acknowledge the backup update
    manager.acknowledge_backup_update(
        file_system.clone(),
        updated_backup.backup_update_id,
    );

    // now ensure the backup checkpoint candidate was deleted and the latest backup checkpoint was promoted
    assert!(file_system
        .read_file(format!(
            "{}/backup/checkpoint/{}.json",
            file_system.get_user_data_directory(),
            updated_backup.backup_update_id
        ))
        .is_err());

    let latest_backup_checkpoint = file_system
        .read_file(format!(
            "{}/backup/checkpoint/latest.json",
            file_system.get_user_data_directory()
        ))
        .unwrap();

    let latest_backup_checkpoint: LocalBackupCheckpoint =
        serde_json::from_slice(&latest_backup_checkpoint).unwrap();
    let LocalBackupCheckpoint::V0(files) = latest_backup_checkpoint;
    assert_eq!(
        files[0].checksum,
        blake3::hash(b"Hallo, Welt!").as_bytes().to_vec()
    );

    // Verify the backup has been updated by decrypting it
    let decrypted = manager
        .decrypt_sealed_backup(
            &updated_backup.sealed_backup_data,
            create_result.encrypted_backup_keypair.clone(),
            prf_result,
            FactorType::Prf,
        )
        .unwrap();

    assert_eq!(
        decrypted.backup_keypair_public_key,
        create_result.backup_keypair_public_key
    );

    // Verify the updated backup has the new root secret and files
    match decrypted.backup {
        BackupFormat::V0(backup) => {
            assert_eq!(
                backup.root_secret,
                OxideKey::decode(root_secret.clone()).unwrap()
            );
            assert_eq!(backup.files.len(), 1);
            assert_eq!(backup.files[0].name, "personal_custody.bin");
            assert_eq!(backup.files[0].data, b"Hallo, Welt!".to_vec());
            assert_eq!(
                backup.files[0].checksum,
                blake3::hash(b"Hallo, Welt!").as_bytes().to_vec()
            );
            assert_eq!(backup.files[0].module_name, BackupModule::PersonalCustody);
        }
    }

    // Now we test that the backup is not updated as the files are the same
    let result = manager
        .new_updated_sealed_backup(
            root_secret,
            file_system,
            create_result.backup_keypair_public_key,
        )
        .unwrap();
    assert!(result.is_none()); // No update required
}

#[test]
fn test_update_backup_success_file_checksum_has_changed() {
    let manager = BackupManager::new();
    let file_system = Arc::new(TestInMemoryDeviceFileSystem::new());

    let root_secret =
        "1810f739487f5447c01df40e57d38885caad51912851f1cbdd69117fe3641d1b".to_string();
    let prf_result =
        "67a9b25d7cd2e11cba781af1d4be91c73d3561e5a8fbc2904cb6c2f274acae37".to_string();

    let create_result = manager
        .create_sealed_backup_for_new_user(
            root_secret.clone(),
            prf_result.clone(),
            FactorType::Prf,
        )
        .expect("Failed to create sealed backup with PRF for new user");

    helper_write_manifest_file(
        file_system.as_ref(),
        "personal_custody",
        Some(b"Initial content".to_vec()),
        None,
    );

    manager
        .new_updated_sealed_backup(
            root_secret.clone(),
            file_system.clone(),
            create_result.backup_keypair_public_key.clone(),
        )
        .expect("Failed to update sealed backup")
        .expect("This operation should require a file update.");

    helper_write_manifest_file(
        file_system.as_ref(),
        "personal_custody",
        Some(b"Changed content".to_vec()),
        None,
    );

    let updated_backup = manager
        .new_updated_sealed_backup(
            root_secret,
            file_system.clone(),
            create_result.backup_keypair_public_key.clone(),
        )
        .expect("Failed to update sealed backup")
        .expect("This operation should require a file update due to checksum change.");

    manager.acknowledge_backup_update(file_system, updated_backup.backup_update_id);

    let decrypted = manager
        .decrypt_sealed_backup(
            &updated_backup.sealed_backup_data,
            create_result.encrypted_backup_keypair,
            prf_result,
            FactorType::Prf,
        )
        .unwrap();

    match decrypted.backup {
        BackupFormat::V0(backup) => {
            assert_eq!(backup.files.len(), 1);
            assert_eq!(backup.files[0].name, "personal_custody.bin");
            assert_eq!(backup.files[0].data, b"Changed content".to_vec());
            assert_eq!(
                backup.files[0].checksum,
                blake3::hash(b"Changed content").as_bytes().to_vec()
            );
            assert_eq!(backup.files[0].module_name, BackupModule::PersonalCustody);
        }
    }
}

#[test]
fn test_update_backup_failure_two_manifests_attempt_to_backup_the_same_file() {
    let manager = BackupManager::new();
    let file_system = Arc::new(TestInMemoryDeviceFileSystem::new());

    let root_secret =
        "1810f739487f5447c01df40e57d38885caad51912851f1cbdd69117fe3641d1b".to_string();

    let create_result = manager
        .create_sealed_backup_for_new_user(
            root_secret.clone(),
            "67a9b25d7cd2e11cba781af1d4be91c73d3561e5a8fbc2904cb6c2f274acae37"
                .to_string(),
            FactorType::Prf,
        )
        .expect("Failed to create sealed backup with PRF for new user");

    // Create two different manifests that both declare the same save_as file name
    helper_write_manifest_file(
        file_system.as_ref(),
        "personal_custody",
        Some(b"Same file content".to_vec()),
        Some("/documents/first_file.bin".to_string()),
    );
    helper_write_manifest_file(
        file_system.as_ref(),
        "document_personal_custody",
        Some(b"Same file content".to_vec()),
        Some("/documents/first_file.bin".to_string()),
    );

    let update_error = manager
        .new_updated_sealed_backup(
            root_secret,
            file_system,
            create_result.backup_keypair_public_key,
        )
        .expect_err("Expected update to fail with conflicting file names");

    assert_eq!(
        update_error.to_string(),
        "Failed to parse backup manifest personal_custody: Duplicate save_as found in backup manifest."
    );
}

#[test]
fn test_update_backup_failure_unable_to_parse_manifest() {
    let manager = BackupManager::new();
    let file_system = Arc::new(TestInMemoryDeviceFileSystem::new());

    let root_secret =
        "1810f739487f5447c01df40e57d38885caad51912851f1cbdd69117fe3641d1b".to_string();

    let create_result = manager
        .create_sealed_backup_for_new_user(
            root_secret.clone(),
            "67a9b25d7cd2e11cba781af1d4be91c73d3561e5a8fbc2904cb6c2f274acae37"
                .to_string(),
            FactorType::Prf,
        )
        .expect("Failed to create sealed backup with PRF for new user");

    file_system.write_file(
        format!(
            "{}/backup_manifests/personal_custody",
            file_system.get_user_data_directory()
        ),
        b"invalid json content".to_vec(),
    );

    let update_error = manager
        .new_updated_sealed_backup(
            root_secret,
            file_system,
            create_result.backup_keypair_public_key,
        )
        .expect_err("Expected update to fail with invalid manifest");

    assert_eq!(
        update_error.to_string(),
        "Failed to parse backup manifest /personal_custody: expected value at line 1 column 1"
    );
}

#[test]
fn test_update_backup_failure_file_does_not_exist() {
    let manager = BackupManager::new();
    let file_system = Arc::new(TestInMemoryDeviceFileSystem::new());

    let root_secret =
        "1810f739487f5447c01df40e57d38885caad51912851f1cbdd69117fe3641d1b".to_string();

    let create_result = manager
        .create_sealed_backup_for_new_user(
            root_secret.clone(),
            "67a9b25d7cd2e11cba781af1d4be91c73d3561e5a8fbc2904cb6c2f274acae37"
                .to_string(),
            FactorType::Prf,
        )
        .expect("Failed to create sealed backup with PRF for new user");

    let manifest = BackupManifest::new(
        format!(
            "{}/nonexistent/file.bin",
            file_system.get_user_data_directory()
        ),
        Utc::now(),
        1024,
        "personal_custody".to_string(),
    )
    .unwrap();

    file_system.write_file(
        format!(
            "{}/backup_manifests/personal_custody",
            file_system.get_user_data_directory()
        ),
        serde_json::to_vec(&manifest).unwrap(),
    );

    let update_error = manager
        .new_updated_sealed_backup(
            root_secret,
            file_system,
            create_result.backup_keypair_public_key,
        )
        .expect_err("Expected update to fail with missing file");

    assert_eq!(
            update_error.to_string(),
            "Invalid file for backup: High Impact. Failed to load file from personal_custody: tried to read a file that doesn't exist"
        );
}

#[test]
fn test_update_backup_failure_file_exceeds_max_size() {
    let manager = BackupManager::new();
    let file_system = Arc::new(TestInMemoryDeviceFileSystem::new());

    let root_secret =
        "1810f739487f5447c01df40e57d38885caad51912851f1cbdd69117fe3641d1b".to_string();

    let create_result = manager
        .create_sealed_backup_for_new_user(
            root_secret.clone(),
            "67a9b25d7cd2e11cba781af1d4be91c73d3561e5a8fbc2904cb6c2f274acae37"
                .to_string(),
            FactorType::Prf,
        )
        .expect("Failed to create sealed backup with PRF for new user");

    let large_file_path = format!(
        "{}/somewhere/large_file.bin",
        file_system.get_user_data_directory()
    );
    let large_content = vec![1u8; 1024 + 1]; // 1KB file + 1 byte

    file_system.write_file(
        format!("/user/test/data_directory{large_file_path}"),
        large_content,
    );

    let manifest = BackupManifest::new(
        large_file_path,
        Utc::now(),
        1,
        "personal_custody".to_string(),
    )
    .unwrap();

    file_system.write_file(
        "/user/test/data_directory/backup_manifests/personal_custody".to_string(),
        serde_json::to_vec(&manifest).unwrap(),
    );

    let update_error = manager
        .new_updated_sealed_backup(
            root_secret,
            file_system,
            create_result.backup_keypair_public_key,
        )
        .expect_err("Expected update to fail with oversized file");

    assert!(update_error
        .to_string()
        .contains("exceeds the maximum defined file size"));
}

/// In particular, this test also ensures that the file is unpacked to the correct final destination.
#[test]
fn test_unpack_unsealed_backup_to_file_system() {
    let manager = BackupManager::new();
    let file_system = Arc::new(TestInMemoryDeviceFileSystem::new());

    // Create test files to include in backup
    let test_files = vec![
        V0BackupFile {
            data: b"test file 1 content".to_vec(),
            checksum: blake3::hash(b"test file 1 content").as_bytes().to_vec(),
            path: "/documents/test1.txt".to_string(),
        },
        V0BackupFile {
            data: b"test file 2 content".to_vec(),
            checksum: blake3::hash(b"test file 2 content").as_bytes().to_vec(),
            path: "/my_custom/nested/path/file2.txt".to_string(),
        },
    ];

    // Create a mock backup
    let root_secret = Arc::new(OxideKey::test_key());
    let backup = BackupFormat::new_v0(V0Backup::new(root_secret, test_files));

    let result =
        manager.unpack_unsealed_backup_to_file_system(&backup, file_system.clone());
    assert!(result.is_ok());

    // Check that files were written to the file system
    let user_data_dir = file_system
        .get_user_data_directory()
        .trim_end_matches('/')
        .to_string();

    // Verify file1 was written
    let file1_path = format!("{user_data_dir}/documents/test1.txt");
    let file1_content = file_system.read_file(file1_path).unwrap();
    assert_eq!(file1_content, b"test file 1 content".to_vec());

    // Verify file2 was written
    let file2_path = format!("{user_data_dir}/my_custom/nested/path/file2.txt");
    let file2_content = file_system.read_file(file2_path).unwrap();
    assert_eq!(file2_content, b"test file 2 content".to_vec());

    // Check that the latest backup meta was created
    let latest_backup_checkpoint = file_system
        .read_file(format!("{user_data_dir}/backup/checkpoint/latest.json"))
        .unwrap();
    let latest_backup_checkpoint: LocalBackupCheckpoint =
        serde_json::from_slice(&latest_backup_checkpoint).unwrap();
    let LocalBackupCheckpoint::V0(files) = latest_backup_checkpoint;
    assert_eq!(files.len(), 2);
    assert_eq!(files[0].name, "test1.txt");
    assert_eq!(files[1].name, "test2.txt");
    assert_eq!(files[0].module_name, BackupModule::PersonalCustody);
    assert_eq!(files[1].module_name, BackupModule::PersonalCustody);
    assert_eq!(
        files[0].checksum,
        blake3::hash(b"test file 1 content").as_bytes().to_vec()
    );
    assert_eq!(
        files[1].checksum,
        blake3::hash(b"test file 2 content").as_bytes().to_vec()
    );
    assert_eq!(files[0].data, vec![] as Vec<u8>); // explicitly the data is not saved in the backup meta
    assert_eq!(files[1].data, vec![] as Vec<u8>); // explicitly the data is not saved in the backup meta
}

#[test]
fn test_unpack_unsealed_backup_to_file_system_with_existing_file() {
    let manager = BackupManager::new();
    let file_system = Arc::new(TestInMemoryDeviceFileSystem::new());

    // Create a file that already exists in the file system
    let user_data_dir = file_system.get_user_data_directory();
    let existing_file_path = format!("{user_data_dir}/documents/existing.txt");
    let existing_content = b"existing content".to_vec();
    file_system.write_file(existing_file_path.clone(), existing_content.clone());

    // Create test files for the backup including the existing file but with different content
    let test_files = vec![
        V0BackupFile {
            data: b"new content".to_vec(),
            checksum: blake3::hash(b"new content").as_bytes().to_vec(),
            path: "/documents/existing.txt".to_string(),
        },
        V0BackupFile {
            data: b"new file content".to_vec(),
            checksum: blake3::hash(b"new file content").as_bytes().to_vec(),
            path: "/my/path/new_file.txt".to_string(),
        },
    ];

    helper_write_manifest_file(&(*file_system), "personal_custody", None, None);
    helper_write_manifest_file(
        &(*file_system),
        "document_personal_custody",
        None,
        None,
    );

    // Create a mock backup
    let root_secret = Arc::new(OxideKey::test_key());
    let backup = BackupFormat::new_v0(V0Backup::new(root_secret, test_files));

    let result =
        manager.unpack_unsealed_backup_to_file_system(&backup, file_system.clone());
    assert!(result.is_ok());

    // Check that existing file wasn't overwritten
    let existing_file_content = file_system.read_file(existing_file_path).unwrap();
    assert_eq!(existing_file_content, existing_content);

    // Check that new file was written
    let new_file_path = format!("{user_data_dir}/my/path/new_file.txt");
    let new_file_content = file_system.read_file(new_file_path).unwrap();
    assert_eq!(new_file_content, b"new file content".to_vec());

    // Check that the latest backup meta was created
    let latest_backup_checkpoint = file_system
        .read_file(format!("{user_data_dir}/backup/checkpoint/latest.json"))
        .unwrap();
    let latest_backup_checkpoint: LocalBackupCheckpoint =
        serde_json::from_slice(&latest_backup_checkpoint).unwrap();
    let LocalBackupCheckpoint::V0(files) = latest_backup_checkpoint;
    assert_eq!(files.len(), 2);
    assert_eq!(files[0].name, "existing.txt");
    assert_eq!(files[1].name, "new_file.txt");
    assert_eq!(files[0].module_name, BackupModule::PersonalCustody);
    assert_eq!(files[1].module_name, BackupModule::DocumentPersonalCustody);
    // note that the checksum is the one for the new content, as this is what is actually in the latest backup,
    // even if the file was not unpacked into the file system
    assert_eq!(
        files[0].checksum,
        blake3::hash(b"new content").as_bytes().to_vec()
    );
}
