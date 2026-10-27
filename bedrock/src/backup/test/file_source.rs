use super::*;
use crate::backup::file_source::TestHandlersGuard;
use crate::backup::{
    set_backup_file_handlers, BackupError, BackupFileSink, BackupFileSource,
    BackupFileSourceError, ClientEventsReporter, RestoredBackupFile,
};
use std::collections::HashMap;

#[derive(Default)]
struct HostFiles {
    files: Mutex<HashMap<(BackupFileDesignator, String), Vec<u8>>>,
    reads: Mutex<Vec<(BackupFileDesignator, String)>>,
    read_failure: Mutex<Option<BackupFileSourceError>>,
    sink_failure: Mutex<Option<BackupFileSourceError>>,
    restore_calls: Mutex<usize>,
}

impl HostFiles {
    fn put(&self, designator: BackupFileDesignator, path: &str, data: &[u8]) {
        self.files
            .lock()
            .unwrap()
            .insert((designator, path.into()), data.to_vec());
    }

    fn register(
        self: &Arc<Self>,
        designators: Vec<BackupFileDesignator>,
    ) -> TestHandlersGuard {
        set_backup_file_handlers(designators, self.clone(), self.clone()).unwrap();
        TestHandlersGuard
    }
}

impl BackupFileSource for HostFiles {
    fn read(
        &self,
        designator: BackupFileDesignator,
        path: String,
    ) -> Result<Vec<u8>, BackupFileSourceError> {
        let failure = *self.read_failure.lock().unwrap();
        if let Some(failure) = failure {
            return Err(failure);
        }
        self.reads
            .lock()
            .unwrap()
            .push((designator.clone(), path.clone()));
        self.files
            .lock()
            .unwrap()
            .get(&(designator, path))
            .cloned()
            .ok_or(BackupFileSourceError::NotFound)
    }
}

impl BackupFileSink for HostFiles {
    fn restore(
        &self,
        files: Vec<RestoredBackupFile>,
    ) -> Result<(), BackupFileSourceError> {
        *self.restore_calls.lock().unwrap() += 1;
        // Model a host that commits before an interruption. Replaying must upsert.
        for file in files {
            self.put(file.designator, &file.path, &file.data);
        }
        let failure = *self.sink_failure.lock().unwrap();
        if let Some(failure) = failure {
            return Err(failure);
        }
        Ok(())
    }
}

fn entry(
    designator: BackupFileDesignator,
    path: &str,
    data: &[u8],
) -> V0BackupManifestEntry {
    V0BackupManifestEntry {
        designator,
        file_path: path.into(),
        checksum_hex: hex::encode(blake3::hash(data).as_bytes()),
    }
}

fn restored_file(
    designator: BackupFileDesignator,
    path: &str,
    data: &[u8],
) -> V0BackupFile {
    V0BackupFile {
        designator,
        path: path.into(),
        data: data.to_vec(),
        checksum: blake3::hash(data).into(),
    }
}

#[tokio::test]
#[serial]
async fn source_put_mixed_sync_rereads_unchanged_entries_and_refreshes_vault() {
    use BackupFileDesignator::{CredentialVault, DocumentPkg, OrbPkg};
    let api = init_test_globals();
    api.reset();
    let host = Arc::new(HostFiles::default());
    let _guard = host.register(vec![OrbPkg, CredentialVault]);
    let prefix = "backup_source_sync";
    write_manifest_with_prefix(&BackupManifest::default(), prefix);
    api.set_no_remote_backup();
    host.put(OrbPkg, "source_only/orb.bin", b"SEALED PCP");
    host.put(CredentialVault, "source_only/vault.bin", b"VAULT 1");
    write_global_file("source_disk/document.bin", b"DOCUMENT 1");
    let manager = ManifestManager::new_with_prefix(prefix);
    let key = SecretKey::generate(&mut rand::thread_rng());
    let root = RootKey::new_random().danger_to_json().unwrap();
    let public_key = hex::encode(key.public_key().as_bytes());
    manager
        .sync_changes(
            &root,
            public_key.clone(),
            vec![
                BackupFileChange::Put {
                    designator: OrbPkg,
                    path: "././source_only/orb.bin".into(),
                },
                BackupFileChange::Put {
                    designator: CredentialVault,
                    path: "/source_only/vault.bin".into(),
                },
                BackupFileChange::Put {
                    designator: DocumentPkg,
                    path: "source_disk/document.bin".into(),
                },
            ],
        )
        .await
        .unwrap();
    assert!(!unscoped_filesystem()
        .file_exists("source_only/orb.bin")
        .unwrap());
    assert!(!unscoped_filesystem()
        .file_exists("source_only/vault.bin")
        .unwrap());
    host.reads.lock().unwrap().clear();
    host.put(CredentialVault, "source_only/vault.bin", b"VAULT 2");
    write_global_file("source_disk/document.bin", b"DOCUMENT 2");
    manager
        .sync_changes(
            &root,
            public_key,
            vec![
                BackupFileChange::Put {
                    designator: CredentialVault,
                    path: "source_only/vault.bin".into(),
                },
                BackupFileChange::Put {
                    designator: DocumentPkg,
                    path: "source_disk/document.bin".into(),
                },
            ],
        )
        .await
        .unwrap();
    // The unchanged entry is read once to build the archive; the report reuses its size.
    let orb_reads = host
        .reads
        .lock()
        .unwrap()
        .iter()
        .filter(|read| **read == (OrbPkg, "source_only/orb.bin".into()))
        .count();
    assert_eq!(orb_reads, 1);
    let BackupManifest::V0(manifest) = get_manifest_from_disk(prefix);
    assert_eq!(
        manifest
            .files
            .iter()
            .find(|e| e.designator == CredentialVault)
            .unwrap()
            .checksum_hex,
        hex::encode(blake3::hash(b"VAULT 2").as_bytes())
    );
    let request = api.state.lock().unwrap().last_sync.clone().unwrap();
    let unsealed = key.unseal(&request.sealed_backup).unwrap();
    let backup = V0Backup::from_bytes(&unsealed).unwrap();
    assert_eq!(
        backup.files,
        vec![
            restored_file(OrbPkg, "source_only/orb.bin", b"SEALED PCP"),
            restored_file(CredentialVault, "source_only/vault.bin", b"VAULT 2"),
            restored_file(DocumentPkg, "source_disk/document.bin", b"DOCUMENT 2"),
        ]
    );
}

#[tokio::test]
#[serial]
async fn source_read_failures_and_checksum_mismatch_do_not_upload_or_commit() {
    use BackupFileDesignator::{DocumentPkg, FacePkg};
    let api = init_test_globals();
    let host = Arc::new(HostFiles::default());
    let _guard = host.register(vec![FacePkg]);
    let prefix = "backup_source_failures";
    let path = "source_failures/private-identity.bin";
    let initial = BackupManifest::V0(V0BackupManifest {
        files: vec![entry(FacePkg, path, b"ORIGINAL")],
    });
    let manager = ManifestManager::new_with_prefix(prefix);
    let key = SecretKey::generate(&mut rand::thread_rng());
    // Even with a disk file present, a missing host entry must fail.
    write_global_file(path, b"ORIGINAL");
    write_global_file("source_failures/document.bin", b"DOCUMENT");
    for failure in [
        None,
        Some(BackupFileSourceError::Unavailable),
        Some(BackupFileSourceError::UnexpectedCallback),
    ] {
        api.reset();
        api.set_remote_hash(compute_manifest_hash(&initial));
        write_manifest_with_prefix(&initial, prefix);
        *host.read_failure.lock().unwrap() = failure;
        let error = manager
            .sync_changes(
                &RootKey::new_random().danger_to_json().unwrap(),
                hex::encode(key.public_key().as_bytes()),
                vec![BackupFileChange::Put {
                    designator: DocumentPkg,
                    path: "source_failures/document.bin".into(),
                }],
            )
            .await
            .unwrap_err();
        assert!(matches!(error, BackupError::InvalidFileForBackup(_)));
        assert!(error.to_string().contains("face_pkg"));
        assert!(!error.to_string().contains(path));
        assert_eq!(api.state.lock().unwrap().sync_count, 0);
        assert_eq!(get_manifest_from_disk(prefix), initial);
        // Put must propagate the same missing-entry/callback failure.
        assert!(matches!(
            manager
                .store_file(
                    FacePkg,
                    path.into(),
                    &RootKey::new_random().danger_to_json().unwrap(),
                    hex::encode(key.public_key().as_bytes())
                )
                .await,
            Err(BackupError::InvalidFileForBackup(_))
        ));
    }
    *host.read_failure.lock().unwrap() = None;
    host.put(FacePkg, path, b"CHANGED");
    let error = manager
        .store_file(
            DocumentPkg,
            "source_failures/document.bin".into(),
            &RootKey::new_random().danger_to_json().unwrap(),
            hex::encode(key.public_key().as_bytes()),
        )
        .await
        .unwrap_err();
    assert!(
        matches!(error, BackupError::InvalidChecksumError { designator } if designator == "face_pkg")
    );
    assert_eq!(api.state.lock().unwrap().sync_count, 0);
    assert_eq!(get_manifest_from_disk(prefix), initial);
}

#[test]
#[serial]
fn disk_and_source_produce_identical_backup_bytes() {
    ensure_fs_initialized();
    let path = "source_equivalence/orb.bin";
    let data = b"SEALED BYTES";
    write_global_file(path, data);
    let manager = ManifestManager::new();
    let manifest = V0BackupManifest {
        files: vec![entry(BackupFileDesignator::OrbPkg, path, data)],
    };
    let disk_files = manager
        .build_unsealed_backup_files_from_manifest(&manifest)
        .unwrap();
    let host = Arc::new(HostFiles::default());
    host.put(BackupFileDesignator::OrbPkg, path, data);
    let _guard = host.register(vec![BackupFileDesignator::OrbPkg]);
    unscoped_filesystem().delete_file(path).unwrap();
    let source_files = manager
        .build_unsealed_backup_files_from_manifest(&manifest)
        .unwrap();
    assert_eq!(source_files, disk_files);
    let root = RootKey::new_random().danger_to_json().unwrap();
    let disk = V0Backup::new(RootKey::from_json(&root).unwrap(), disk_files);
    let source = V0Backup::new(RootKey::from_json(&root).unwrap(), source_files);
    // Tar mtimes are an input too; hold them constant for the full blob comparison.
    assert_eq!(
        disk.to_bytes_with_clock(|| 123).unwrap(),
        source.to_bytes_with_clock(|| 123).unwrap()
    );
}

#[test]
#[serial]
fn restore_routes_owned_entries_and_reports_their_sizes_without_disk() {
    use BackupFileDesignator::{DocumentPkg, OrbPkg};
    ensure_fs_initialized();
    let host = Arc::new(HostFiles::default());
    let _guard = host.register(vec![OrbPkg]);
    let files = vec![
        restored_file(OrbPkg, "./source_restore/orb.bin", &vec![1; 2049]),
        restored_file(OrbPkg, "source_restore/second.bin", b"SECOND"),
        restored_file(DocumentPkg, "./source_restore/document.bin", b"DOCUMENT"),
    ];
    let (sealed, encrypted_keypair, factor_secret) = seal_backup_for_unpacking(files);
    BackupManager::new()
        .decrypt_and_unpack_sealed_backup(
            &sealed,
            encrypted_keypair,
            factor_secret,
            FactorType::Prf,
        )
        .unwrap();
    assert_eq!(*host.restore_calls.lock().unwrap(), 1);
    let BackupManifest::V0(manifest) = get_manifest_from_disk("backup_manager");
    assert_eq!(manifest.files[0].file_path, "source_restore/orb.bin");
    assert_eq!(manifest.files[2].file_path, "./source_restore/document.bin");
    assert_eq!(
        host.read(OrbPkg, "source_restore/orb.bin".into()).unwrap(),
        vec![1; 2049]
    );
    assert!(!unscoped_filesystem()
        .file_exists("source_restore/orb.bin")
        .unwrap());
    assert_eq!(
        unscoped_filesystem()
            .read_file("source_restore/document.bin")
            .unwrap(),
        b"DOCUMENT"
    );
    ClientEventsReporter::new()
        .sync_base_report_with_manifest()
        .unwrap();
    let bytes = unscoped_filesystem()
        .read_file("backup_client_events/base_report.json")
        .unwrap();
    let base: crate::backup::BaseReport = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(base.backup_size_kb, Some(3));
    let hash = compute_manifest_hash_from_disk("backup_manager");
    assert!(!BackupManager::new().is_local_backup_stale(&hash).unwrap());
    assert_eq!(
        BackupManager::new()
            .debug_get_local_manifest()
            .unwrap()
            .manifest_hash,
        hash
    );
}

#[test]
#[serial]
fn sink_partial_failure_preserves_manifest_and_restore_can_be_retried() {
    use BackupFileDesignator::{DocumentPkg, OrbPkg};
    ensure_fs_initialized();
    let host = Arc::new(HostFiles::default());
    let _guard = host.register(vec![OrbPkg]);
    let manager = ManifestManager::new();
    manager.write_manifest(&BackupManifest::default()).unwrap();
    let original = read_manifest_bytes("backup_manager");
    let backup = BackupFormat::V0(V0Backup::new(
        RootKey::new_random(),
        vec![
            restored_file(OrbPkg, "source_retry/orb.bin", b"ORB"),
            restored_file(DocumentPkg, "source_retry/document.bin", b"DOCUMENT"),
        ],
    ));
    *host.sink_failure.lock().unwrap() = Some(BackupFileSourceError::Failure);
    assert!(BackupManager::unpack_backup_to_filesystem(&backup).is_err());
    assert_eq!(read_manifest_bytes("backup_manager"), original);
    assert!(!unscoped_filesystem()
        .file_exists("source_retry/document.bin")
        .unwrap());
    manager.danger_delete_manifest().unwrap();
    assert!(BackupManager::unpack_backup_to_filesystem(&backup).is_err());
    assert!(matches!(
        manager.read_manifest(),
        Err(BackupError::ManifestNotFound)
    ));
    *host.sink_failure.lock().unwrap() = None;
    BackupManager::unpack_backup_to_filesystem(&backup).unwrap();
    assert_eq!(host.files.lock().unwrap().len(), 1);
    assert_eq!(get_manifest_from_disk("backup_manager").entries_length(), 2);
}

#[test]
#[serial]
fn restore_validates_every_path_and_duplicate_before_calling_sink() {
    ensure_fs_initialized();
    let host = Arc::new(HostFiles::default());
    let _guard = host.register(vec![BackupFileDesignator::OrbPkg]);
    for path in [
        "../escape.bin",
        "SOURCE_VALIDATE/orb.bin",
        "./source_validate/orb.bin",
    ] {
        let backup = BackupFormat::V0(V0Backup::new(
            RootKey::new_random(),
            vec![
                restored_file(
                    BackupFileDesignator::OrbPkg,
                    "source_validate/orb.bin",
                    b"ORB",
                ),
                restored_file(BackupFileDesignator::DocumentPkg, path, b"BAD"),
            ],
        ));
        assert!(BackupManager::unpack_backup_to_filesystem(&backup).is_err());
        assert_eq!(*host.restore_calls.lock().unwrap(), 0);
    }
}

#[test]
#[serial]
fn registration_is_paired_and_cannot_be_replaced() {
    let host = Arc::new(HostFiles::default());
    let _guard = host.register(vec![BackupFileDesignator::OrbPkg]);
    assert!(matches!(
        set_backup_file_handlers(
            vec![BackupFileDesignator::DocumentPkg],
            host.clone(),
            host
        ),
        Err(BackupError::BackupFileHandlersAlreadyRegistered)
    ));
    let error = BackupFileSourceError::from(uniffi::UnexpectedUniFFICallbackError {
        reason: "private/path and secret data".into(),
    });
    assert_eq!(error.to_string(), "unexpected_callback");
}

#[test]
#[serial]
fn disk_failure_after_sink_leaves_manifest_unchanged_and_replays_safely() {
    use BackupFileDesignator::{DocumentPkg, OrbPkg};
    ensure_fs_initialized();
    let host = Arc::new(HostFiles::default());
    let _guard = host.register(vec![OrbPkg]);
    let manager = ManifestManager::new();
    manager.write_manifest(&BackupManifest::default()).unwrap();
    let original = read_manifest_bytes("backup_manager");
    let fs = unscoped_filesystem();
    fs.write_file("source_disk_failure/parent", b"BLOCKER")
        .unwrap();
    let backup = BackupFormat::V0(V0Backup::new(
        RootKey::new_random(),
        vec![
            restored_file(OrbPkg, "source_disk_failure/orb.bin", b"ORB"),
            restored_file(
                DocumentPkg,
                "source_disk_failure/parent/document.bin",
                b"DOCUMENT",
            ),
        ],
    ));
    assert!(BackupManager::unpack_backup_to_filesystem(&backup).is_err());
    assert_eq!(host.files.lock().unwrap().len(), 1);
    assert_eq!(read_manifest_bytes("backup_manager"), original);
    fs.delete_file("source_disk_failure/parent").unwrap();
    BackupManager::unpack_backup_to_filesystem(&backup).unwrap();
    assert_eq!(host.files.lock().unwrap().len(), 1);
    assert_eq!(get_manifest_from_disk("backup_manager").entries_length(), 2);
}

#[test]
#[serial]
fn reporting_surfaces_source_failure_without_replacing_the_base_report() {
    ensure_fs_initialized();
    let host = Arc::new(HostFiles::default());
    let _guard = host.register(vec![BackupFileDesignator::OrbPkg]);
    let manifest = BackupManifest::V0(V0BackupManifest {
        files: vec![entry(
            BackupFileDesignator::OrbPkg,
            "source_report/orb.bin",
            b"ORB",
        )],
    });
    host.put(
        BackupFileDesignator::OrbPkg,
        "source_report/orb.bin",
        b"ORB",
    );
    ManifestManager::new().write_manifest(&manifest).unwrap();
    let reporter = ClientEventsReporter::new();
    reporter.sync_base_report_with_manifest().unwrap();
    let path = "backup_client_events/base_report.json";
    let original = unscoped_filesystem().read_file(path).unwrap();
    *host.read_failure.lock().unwrap() = Some(BackupFileSourceError::Unavailable);
    let error = reporter.sync_base_report_with_manifest().unwrap_err();
    assert!(error.to_string().contains("orb_pkg: unavailable"));
    assert_eq!(unscoped_filesystem().read_file(path).unwrap(), original);
}
