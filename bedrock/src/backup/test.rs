use crate::backup::backup_format::v0::{V0Backup, V0BackupFile};
use crate::backup::backup_format::BackupFormat;
use crate::backup::BackupManager;
use crate::backup::BackupModule;
use crate::backup::FactorType;
use crate::root_key::RootKey;
use crypto_box::{PublicKey, SecretKey};
use std::str::FromStr;

fn helper_compare_backups(source: &BackupFormat, target: &BackupFormat) -> bool {
    let BackupFormat::V0(source_backup) = source;
    let BackupFormat::V0(target_backup) = target;
    source_backup.root_secret == target_backup.root_secret
        && source_backup.files == target_backup.files
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
fn test_re_encrypt_backup() {
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
