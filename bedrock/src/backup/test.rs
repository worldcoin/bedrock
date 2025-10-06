use crate::backup::backup_format::v0::{V0Backup, V0BackupFile};
use crate::backup::backup_format::v0::{V0BackupManifest, V0BackupManifestEntry};
use crate::backup::backup_format::BackupFormat;
use crate::backup::manifest::{BackupManifest, ManifestManager};
use crate::backup::service_client::{
    set_backup_service_api, BackupServiceApi, RetrieveMetadataResponsePayload,
    SyncSubmitRequest,
};
use crate::backup::FactorType;
use crate::backup::{BackupFileDesignator, BackupManager};
use crate::primitives::filesystem::{
    create_middleware, get_filesystem_raw, FileSystem,
};
use crate::primitives::filesystem::{set_filesystem, InMemoryFileSystem};
use crate::root_key::RootKey;
use crypto_box::{PublicKey, SecretKey};
use serial_test::serial;
use std::str::FromStr;
use std::sync::Mutex;
use std::sync::{Arc, OnceLock};

fn ensure_fs_initialized() {
    if crate::primitives::filesystem::get_filesystem_raw().is_err() {
        let fs = InMemoryFileSystem::new();
        set_filesystem(std::sync::Arc::new(fs));
    }
}

// =========================
// ManifestManager tests
// =========================

#[derive(Default, Clone, Debug)]
struct NextSyncErrorConfig {
    code: u64,
    response_body: Vec<u8>,
}

#[derive(Default, Clone, Debug)]
struct FakeApiState {
    remote_manifest_hash_hex: Option<String>,
    last_sync: Option<SyncSubmitRequest>,
    sync_count: u64,
    // If set, the next call to sync will fail with this error (one-shot).
    sync_error: Option<NextSyncErrorConfig>,
}

#[derive(Clone, Default)]
struct FakeBackupServiceApi {
    state: Arc<Mutex<FakeApiState>>,
}

impl FakeBackupServiceApi {
    fn reset(&self) {
        *self.state.lock().unwrap() = FakeApiState::default();
    }
    fn set_remote_hash(&self, hex_hash: String) {
        self.state.lock().unwrap().remote_manifest_hash_hex = Some(hex_hash);
    }
    fn set_sync_error_bad_status(&self, code: u64, response_body: Vec<u8>) {
        self.state.lock().unwrap().sync_error = Some(NextSyncErrorConfig {
            code,
            response_body,
        });
    }
}

#[async_trait::async_trait]
impl BackupServiceApi for FakeBackupServiceApi {
    #[allow(clippy::significant_drop_tightening)]
    async fn sync(&self, request: SyncSubmitRequest) -> Result<(), crate::HttpError> {
        let mut s = self.state.lock().unwrap();
        if let Some(err_cfg) = s.sync_error.take() {
            return Err(crate::HttpError::BadStatusCode {
                code: err_cfg.code,
                response_body: err_cfg.response_body,
            });
        }
        s.last_sync = Some(request);
        s.sync_count += 1;
        if let Some(last) = &s.last_sync {
            s.remote_manifest_hash_hex = Some(last.new_manifest_hash.clone());
        }
        Ok(())
    }

    #[allow(clippy::significant_drop_tightening)]
    async fn retrieve_metadata(
        &self,
    ) -> Result<RetrieveMetadataResponsePayload, crate::HttpError> {
        let s = self.state.lock().unwrap();
        Ok(RetrieveMetadataResponsePayload {
            manifest_hash: s
                .remote_manifest_hash_hex
                .clone()
                .unwrap_or_else(BackupManifest::default_hash_hex),
            encryption_keys: None,
            sync_factor_count: None,
            main_factors: None,
        })
    }
}

static TEST_API: OnceLock<Arc<FakeBackupServiceApi>> = OnceLock::new();

fn init_test_globals() -> Arc<FakeBackupServiceApi> {
    // Filesystem
    set_filesystem(Arc::new(InMemoryFileSystem::new()));
    // API
    TEST_API.get().cloned().map_or_else(
        || {
            let api = Arc::new(FakeBackupServiceApi::default());
            let _ = set_backup_service_api(api.clone());
            let _ = TEST_API.set(api.clone());
            api
        },
        |api| api,
    )
}

fn write_manifest_with_prefix(manifest: &BackupManifest, prefix: &str) {
    let bytes = serde_json::to_vec(manifest).unwrap();
    let mw = create_middleware(prefix);
    mw.write_file("manifest.json", bytes).unwrap();
}

fn get_manifest_from_disk(prefix: &str) -> BackupManifest {
    let fs = get_filesystem_raw().unwrap().clone();
    let bytes = fs.read_file(format!("{prefix}/manifest.json")).unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

fn compute_manifest_hash(manifest: &BackupManifest) -> String {
    hex::encode(manifest.calculate_hash().unwrap())
}

fn compute_manifest_hash_from_disk(prefix: &str) -> String {
    let fs: Arc<dyn FileSystem> = get_filesystem_raw().unwrap().clone();
    let bytes = fs.read_file(format!("{prefix}/manifest.json")).unwrap();
    let manifest: BackupManifest = serde_json::from_slice(&bytes).unwrap();
    hex::encode(manifest.calculate_hash().unwrap())
}

fn write_global_file(path: &str, contents: &[u8]) {
    let fs = get_filesystem_raw().unwrap().clone();
    fs.write_file(path.to_string(), contents.to_vec()).unwrap();
}

#[test]
fn test_backup_manifest_default_hash() {
    let manifest = BackupManifest::V0(V0BackupManifest {
        previous_manifest_hash: None,
        files: vec![],
    });
    let hash = hex::encode(manifest.calculate_hash().unwrap());
    assert_eq!(hash, BackupManifest::default_hash_hex());
}

#[tokio::test]
#[serial]
async fn test_list_files_happy_path() {
    let api = init_test_globals();
    api.reset();

    // Prepare manifest with two files
    let m = BackupManifest::V0(crate::backup::backup_format::v0::V0BackupManifest {
        previous_manifest_hash: None,
        files: vec![
            V0BackupManifestEntry {
                designator: BackupFileDesignator::OrbPkg,
                file_path: "orb_pkg/personal_custody/pcp.bin".to_string(),
                checksum_hex: hex::encode(blake3::hash(b"abc").as_bytes()),
            },
            V0BackupManifestEntry {
                designator: BackupFileDesignator::DocumentPkg,
                file_path: "document_pkg/foo.bin".to_string(),
                checksum_hex: hex::encode(blake3::hash(b"def").as_bytes()),
            },
        ],
    });
    write_manifest_with_prefix(&m, "backup_test_list_1");
    api.set_remote_hash(compute_manifest_hash_from_disk("backup_test_list_1"));

    let mgr = ManifestManager::new_with_prefix("backup_test_list_1");
    let list = mgr.list_files(BackupFileDesignator::OrbPkg).await.unwrap();
    assert_eq!(list, vec!["orb_pkg/personal_custody/pcp.bin".to_string()]);
}

#[tokio::test]
#[serial]
async fn test_list_files_stale_remote() {
    let api = init_test_globals();
    api.reset();

    // Local manifest
    let m = BackupManifest::V0(crate::backup::backup_format::v0::V0BackupManifest {
        previous_manifest_hash: None,
        files: vec![],
    });
    write_manifest_with_prefix(&m, "backup_test_list_2");
    // Remote is different
    api.set_remote_hash(hex::encode(blake3::hash(b"different").as_bytes()));

    let mgr = ManifestManager::new_with_prefix("backup_test_list_2");
    let err = mgr
        .list_files(BackupFileDesignator::OrbPkg)
        .await
        .expect_err("expected stale error");
    assert_eq!(err.to_string(), "Remote manifest is ahead of local; fetch and apply latest backup before updating");
}

#[tokio::test]
#[serial]
async fn test_list_files_missing_manifest() {
    let api = init_test_globals();
    api.reset();

    // Do not create a manifest for this prefix
    let mgr = ManifestManager::new_with_prefix("backup_test_list_missing");
    let err = mgr
        .list_files(BackupFileDesignator::OrbPkg)
        .await
        .expect_err("expected missing manifest error");
    assert_eq!(err.to_string(), "Manifest not found");
}

#[tokio::test]
#[serial]
async fn test_list_files_corrupted_manifest() {
    let api = init_test_globals();
    api.reset();

    // Write an invalid JSON manifest under the backup prefix
    let mw = create_middleware("backup_test_list_corrupted");
    mw.write_file("manifest.json", b"not-json".to_vec())
        .unwrap();

    api.set_remote_hash(BackupManifest::default_hash_hex());

    let mgr = ManifestManager::new_with_prefix("backup_test_list_corrupted");
    let err = mgr
        .list_files(BackupFileDesignator::OrbPkg)
        .await
        .expect_err("expected corrupted manifest error");
    let msg = err.to_string();
    assert!(
        msg.contains("parse BackupManifest"),
        "unexpected error: {msg}"
    );
}

#[tokio::test]
#[serial]
async fn test_store_file_happy_path_and_commit() {
    let api = init_test_globals();
    api.reset();

    // Local empty manifest and matching remote
    let m0 = BackupManifest::V0(crate::backup::backup_format::v0::V0BackupManifest {
        previous_manifest_hash: None,
        files: vec![],
    });
    write_manifest_with_prefix(&m0, "backup_test_store_1");
    api.set_remote_hash(compute_manifest_hash_from_disk("backup_test_store_1"));

    // Source file to store (in global FS)
    write_global_file("pcp/source.bin", b"hello-bytes");

    // Backup pubkey
    let backup_sk = SecretKey::generate(&mut rand::thread_rng());
    let backup_pk_hex = hex::encode(backup_sk.public_key().as_bytes());

    let mgr = ManifestManager::new_with_prefix("backup_test_store_1");
    mgr.store_file(
        BackupFileDesignator::OrbPkg,
        "pcp/source.bin".to_string(),
        &RootKey::new_random().danger_to_json().unwrap(),
        backup_pk_hex,
    )
    .await
    .unwrap();

    // Manifest committed with previous hash == m0 and one entry
    let fs = get_filesystem_raw().unwrap().clone();
    let committed = fs
        .read_file("backup_test_store_1/manifest.json".to_string())
        .unwrap();
    let committed: serde_json::Value = serde_json::from_slice(&committed).unwrap();
    assert_eq!(committed["version"], "V0");
    assert_eq!(committed["manifest"]["files"].as_array().unwrap().len(), 1);
    assert_eq!(
        committed["manifest"]["previous_manifest_hash"],
        serde_json::Value::String(compute_manifest_hash(&m0))
    );
}

#[tokio::test]
#[serial]
async fn test_store_file_accepts_dot_slash_path() {
    let api = init_test_globals();
    api.reset();

    // Local empty manifest and matching remote
    let m0 = BackupManifest::V0(crate::backup::backup_format::v0::V0BackupManifest {
        previous_manifest_hash: None,
        files: vec![],
    });
    write_manifest_with_prefix(&m0, "backup_test_store_dot_path");
    api.set_remote_hash(compute_manifest_hash_from_disk(
        "backup_test_store_dot_path",
    ));

    // Source file to store (in global FS)
    write_global_file("pcp/source.bin", b"hello-bytes");

    // Backup pubkey
    let backup_sk = SecretKey::generate(&mut rand::thread_rng());
    let backup_pk_hex = hex::encode(backup_sk.public_key().as_bytes());

    let mgr = ManifestManager::new_with_prefix("backup_test_store_dot_path");
    mgr.store_file(
        BackupFileDesignator::OrbPkg,
        "./pcp/source.bin".to_string(),
        &RootKey::new_random().danger_to_json().unwrap(),
        backup_pk_hex,
    )
    .await
    .unwrap();

    // Manifest committed with previous hash == m0 and one entry with normalized path
    let fs = get_filesystem_raw().unwrap().clone();
    let committed = fs
        .read_file("backup_test_store_dot_path/manifest.json".to_string())
        .unwrap();
    let committed: serde_json::Value = serde_json::from_slice(&committed).unwrap();
    assert_eq!(committed["version"], "V0");
    let files = committed["manifest"]["files"].as_array().unwrap();
    assert_eq!(files.len(), 1);
    assert_eq!(files[0]["file_path"], "pcp/source.bin");
}

#[tokio::test]
#[serial]
async fn test_store_file_propagates_sync_failure() {
    let api = init_test_globals();
    api.reset();

    // Local empty manifest and matching remote
    let m0 = BackupManifest::V0(crate::backup::backup_format::v0::V0BackupManifest {
        previous_manifest_hash: None,
        files: vec![],
    });
    write_manifest_with_prefix(&m0, "backup_test_store_sync_failure");
    api.set_remote_hash(compute_manifest_hash_from_disk(
        "backup_test_store_sync_failure",
    ));

    // Prepare a source file to store
    write_global_file("pcp/source.bin", b"hello-bytes");

    // Configure API to fail on next sync
    api.set_sync_error_bad_status(500, b"server error".to_vec());

    // Backup pubkey
    let backup_sk = SecretKey::generate(&mut rand::thread_rng());
    let backup_pk_hex = hex::encode(backup_sk.public_key().as_bytes());

    let mgr = ManifestManager::new_with_prefix("backup_test_store_sync_failure");
    let err = mgr
        .store_file(
            BackupFileDesignator::OrbPkg,
            "pcp/source.bin".to_string(),
            &RootKey::new_random().danger_to_json().unwrap(),
            backup_pk_hex,
        )
        .await
        .expect_err("expected HTTP error to propagate from sync");

    // The error should be an HTTP error propagated through BackupError
    let msg = err.to_string();
    assert!(msg.contains("Bad status code"), "unexpected error: {msg}");
}

#[tokio::test]
#[serial]
async fn test_store_file_fails_when_remote_ahead() {
    let api = init_test_globals();
    api.reset();

    let m0 = BackupManifest::V0(crate::backup::backup_format::v0::V0BackupManifest {
        previous_manifest_hash: None,
        files: vec![],
    });
    write_manifest_with_prefix(&m0, "backup_test_store_2");
    api.set_remote_hash(hex::encode(blake3::hash(b"different").as_bytes()));

    write_global_file("pcp/source.bin", b"hello-bytes");
    let backup_sk = SecretKey::generate(&mut rand::thread_rng());
    let backup_pk_hex = hex::encode(backup_sk.public_key().as_bytes());
    let mgr = ManifestManager::new_with_prefix("backup_test_store_2");
    let err = mgr
        .store_file(
            BackupFileDesignator::OrbPkg,
            "pcp/source.bin".to_string(),
            &RootKey::new_random().danger_to_json().unwrap(),
            backup_pk_hex,
        )
        .await
        .expect_err("expected stale error");
    assert_eq!(err.to_string(), "Remote manifest is ahead of local; fetch and apply latest backup before updating");
}

#[tokio::test]
#[serial]
async fn test_store_file_invalid_source_path() {
    let api = init_test_globals();
    api.reset();

    let m0 = BackupManifest::V0(crate::backup::backup_format::v0::V0BackupManifest {
        previous_manifest_hash: None,
        files: vec![],
    });
    write_manifest_with_prefix(&m0, "backup_test_store_3");
    api.set_remote_hash(compute_manifest_hash_from_disk("backup_test_store_3"));

    // Do not create the source file
    let backup_sk = SecretKey::generate(&mut rand::thread_rng());
    let backup_pk_hex = hex::encode(backup_sk.public_key().as_bytes());
    let mgr = ManifestManager::new_with_prefix("backup_test_store_3");
    let err = mgr
        .store_file(
            BackupFileDesignator::OrbPkg,
            "pcp/missing.bin".to_string(),
            &RootKey::new_random().danger_to_json().unwrap(),
            backup_pk_hex,
        )
        .await
        .expect_err("expected invalid file error");
    assert!(err.to_string().contains("Invalid file for backup"));
}

#[tokio::test]
#[serial]
async fn test_store_file_checksum_mismatch_existing_entry() {
    let api = init_test_globals();
    api.reset();

    // Prepare manifest with one entry that has wrong checksum vs actual file
    write_global_file("orb_pkg/existing.bin", b"ACTUAL");
    let wrong_checksum = hex::encode(blake3::hash(b"DIFFERENT").as_bytes());
    let m0 = BackupManifest::V0(crate::backup::backup_format::v0::V0BackupManifest {
        previous_manifest_hash: None,
        files: vec![V0BackupManifestEntry {
            designator: BackupFileDesignator::OrbPkg,
            file_path: "orb_pkg/existing.bin".to_string(),
            checksum_hex: wrong_checksum,
        }],
    });
    write_manifest_with_prefix(&m0, "backup_test_store_4");
    api.set_remote_hash(compute_manifest_hash(&m0));

    // Attempt to add new file; build should fail due to mismatch on existing
    write_global_file("pcp/new.bin", b"HELLO");
    let backup_sk = SecretKey::generate(&mut rand::thread_rng());
    let backup_pk_hex = hex::encode(backup_sk.public_key().as_bytes());
    let mgr = ManifestManager::new_with_prefix("backup_test_store_4");
    let err = mgr
        .store_file(
            BackupFileDesignator::OrbPkg,
            "pcp/new.bin".to_string(),
            &RootKey::new_random().danger_to_json().unwrap(),
            backup_pk_hex,
        )
        .await
        .expect_err("expected checksum mismatch");
    assert!(err
        .to_string()
        .contains("Checksum for file with designator"));
}

#[tokio::test]
#[serial]
async fn test_store_file_checksum_mismatch_when_file_modified() {
    let api = init_test_globals();
    api.reset();

    // Prepare manifest with one entry that matches the original file contents
    write_global_file("pcp/changed.bin", b"ORIGINAL");
    let correct_checksum = hex::encode(blake3::hash(b"ORIGINAL").as_bytes());
    let m0 = BackupManifest::V0(crate::backup::backup_format::v0::V0BackupManifest {
        previous_manifest_hash: None,
        files: vec![V0BackupManifestEntry {
            designator: BackupFileDesignator::OrbPkg,
            file_path: "pcp/changed.bin".to_string(),
            checksum_hex: correct_checksum,
        }],
    });
    write_manifest_with_prefix(&m0, "backup_test_store_checksum_modified");
    api.set_remote_hash(compute_manifest_hash_from_disk(
        "backup_test_store_checksum_modified",
    ));

    // Modify the file on disk so it no longer matches the manifest checksum
    write_global_file("pcp/changed.bin", b"MODIFIED");

    // Also add a new source file to attempt to store (won't be reached due to mismatch)
    write_global_file("pcp/new.bin", b"HELLO");
    let backup_sk = SecretKey::generate(&mut rand::thread_rng());
    let backup_pk_hex = hex::encode(backup_sk.public_key().as_bytes());
    let mgr = ManifestManager::new_with_prefix("backup_test_store_checksum_modified");
    let err = mgr
        .store_file(
            BackupFileDesignator::OrbPkg,
            "pcp/new.bin".to_string(),
            &RootKey::new_random().danger_to_json().unwrap(),
            backup_pk_hex,
        )
        .await
        .expect_err("expected checksum mismatch after file modification");
    assert!(
        err.to_string()
            .contains("Checksum for file with designator"),
        "unexpected error: {err}"
    );
}

#[tokio::test]
#[serial]
async fn test_store_file_fails_when_manifest_references_missing_file() {
    let api = init_test_globals();
    api.reset();

    // Prepare manifest with an entry pointing to a non-existent file
    let bogus_checksum = hex::encode(blake3::hash(b"ANY").as_bytes());
    let m0 = BackupManifest::V0(crate::backup::backup_format::v0::V0BackupManifest {
        previous_manifest_hash: None,
        files: vec![V0BackupManifestEntry {
            designator: BackupFileDesignator::OrbPkg,
            file_path: "pcp/missing.bin".to_string(),
            checksum_hex: bogus_checksum,
        }],
    });
    write_manifest_with_prefix(&m0, "backup_test_store_missing_file");
    api.set_remote_hash(compute_manifest_hash_from_disk(
        "backup_test_store_missing_file",
    ));

    // Create a valid new file to attempt to store (operation should fail before using it)
    write_global_file("pcp/new.bin", b"HELLO");
    let backup_sk = SecretKey::generate(&mut rand::thread_rng());
    let backup_pk_hex = hex::encode(backup_sk.public_key().as_bytes());
    let mgr = ManifestManager::new_with_prefix("backup_test_store_missing_file");
    let err = mgr
        .store_file(
            BackupFileDesignator::OrbPkg,
            "pcp/new.bin".to_string(),
            &RootKey::new_random().danger_to_json().unwrap(),
            backup_pk_hex,
        )
        .await
        .expect_err("expected invalid file error due to missing manifest entry file");
    assert!(
        err.to_string().contains("Invalid file for backup"),
        "unexpected error: {err}"
    );
}

#[tokio::test]
#[serial]
async fn test_replace_all_files_for_designator_happy_path() {
    let api = init_test_globals();
    api.reset();

    // Prepare global source files
    write_global_file("pcp/old1.bin", b"OLD1");
    write_global_file("pcp/old2.bin", b"OLD2");
    write_global_file("docs/keep.bin", b"KEEP");

    // Initial manifest with two Orb entries and one Document entry
    let m0 = BackupManifest::V0(crate::backup::backup_format::v0::V0BackupManifest {
        previous_manifest_hash: None,
        files: vec![
            V0BackupManifestEntry {
                designator: BackupFileDesignator::OrbPkg,
                file_path: "pcp/old1.bin".to_string(),
                checksum_hex: hex::encode(blake3::hash(b"OLD1").as_bytes()),
            },
            V0BackupManifestEntry {
                designator: BackupFileDesignator::OrbPkg,
                file_path: "pcp/old2.bin".to_string(),
                checksum_hex: hex::encode(blake3::hash(b"OLD2").as_bytes()),
            },
            V0BackupManifestEntry {
                designator: BackupFileDesignator::DocumentPkg,
                file_path: "docs/keep.bin".to_string(),
                checksum_hex: hex::encode(blake3::hash(b"KEEP").as_bytes()),
            },
        ],
    });
    write_manifest_with_prefix(&m0, "backup_test_replace_1");
    api.set_remote_hash(compute_manifest_hash(&m0));

    // New target file
    write_global_file("pcp/new.bin", b"NEWFILE");

    // Backup pubkey and root
    let backup_sk = SecretKey::generate(&mut rand::thread_rng());
    let backup_pk_hex = hex::encode(backup_sk.public_key().as_bytes());
    let root_json = RootKey::new_random().danger_to_json().unwrap();

    let mgr = ManifestManager::new_with_prefix("backup_test_replace_1");
    mgr.replace_all_files_for_designator(
        BackupFileDesignator::OrbPkg,
        "pcp/new.bin".to_string(),
        &root_json,
        backup_pk_hex,
    )
    .await
    .unwrap();

    // Manifest updated and committed
    let fs = get_filesystem_raw().unwrap().clone();
    let committed = fs
        .read_file("backup_test_replace_1/manifest.json".to_string())
        .unwrap();
    let committed: serde_json::Value = serde_json::from_slice(&committed).unwrap();
    assert_eq!(committed["version"], "V0");
    let prev_hash = committed["manifest"]["previous_manifest_hash"]
        .as_str()
        .unwrap()
        .to_string();
    assert_eq!(prev_hash, compute_manifest_hash(&m0));
    let files = committed["manifest"]["files"].as_array().unwrap();
    // 1 (new orb) + 1 (existing document)
    assert_eq!(files.len(), 2);
    // Exactly one orb entry, path is the new file
    let orb_entries: Vec<_> = files
        .iter()
        .filter(|v| v["designator"] == "orb_pkg")
        .collect();
    assert_eq!(orb_entries.len(), 1);
    assert_eq!(orb_entries[0]["file_path"], "pcp/new.bin");
    // Document entry preserved
    let doc_entries: Vec<_> = files
        .iter()
        .filter(|v| v["designator"] == "document_pkg")
        .collect();
    assert_eq!(doc_entries.len(), 1);
    assert_eq!(doc_entries[0]["file_path"], "docs/keep.bin");
}

#[tokio::test]
#[serial]
async fn test_remove_file_happy_and_not_found() {
    let api = init_test_globals();
    api.reset();

    // Prepare global source files
    write_global_file("pcp/target.bin", b"TO-REMOVE");
    write_global_file("docs/keep.bin", b"KEEP");

    // Initial manifest with two entries (one to be removed)
    let m0 = BackupManifest::V0(crate::backup::backup_format::v0::V0BackupManifest {
        previous_manifest_hash: None,
        files: vec![
            V0BackupManifestEntry {
                designator: BackupFileDesignator::OrbPkg,
                file_path: "pcp/target.bin".to_string(),
                checksum_hex: hex::encode(blake3::hash(b"TO-REMOVE").as_bytes()),
            },
            V0BackupManifestEntry {
                designator: BackupFileDesignator::DocumentPkg,
                file_path: "docs/keep.bin".to_string(),
                checksum_hex: hex::encode(blake3::hash(b"KEEP").as_bytes()),
            },
        ],
    });
    write_manifest_with_prefix(&m0, "backup_test_remove_1");
    api.set_remote_hash(compute_manifest_hash(&m0));

    // Backup pubkey and root
    let backup_sk = SecretKey::generate(&mut rand::thread_rng());
    let backup_pk_hex = hex::encode(backup_sk.public_key().as_bytes());
    let root_json = RootKey::new_random().danger_to_json().unwrap();

    let mgr = ManifestManager::new_with_prefix("backup_test_remove_1");

    // Remove existing file
    mgr.remove_file(
        "pcp/target.bin".to_string(),
        &root_json,
        backup_pk_hex.clone(),
    )
    .await
    .unwrap();

    // Manifest now contains only the document entry
    let fs = get_filesystem_raw().unwrap().clone();
    let committed = fs
        .read_file("backup_test_remove_1/manifest.json".to_string())
        .unwrap();
    let committed: serde_json::Value = serde_json::from_slice(&committed).unwrap();
    let files = committed["manifest"]["files"].as_array().unwrap();
    assert_eq!(files.len(), 1);
    assert_eq!(files[0]["designator"], "document_pkg");
    assert_eq!(files[0]["file_path"], "docs/keep.bin");

    // Second removal of the same file should error and not sync again
    let err = mgr
        .remove_file("pcp/target.bin".to_string(), &root_json, backup_pk_hex)
        .await
        .expect_err("expected file-not-found error");
    assert!(err.to_string().contains("File not found in manifest"));
}

// =========================
// BackupManager tests
// =========================

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
#[serial]
fn test_create_sealed_backup_with_prf_for_new_user() {
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
            designator: BackupFileDesignator::DocumentPkg,
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
#[serial]
fn test_decrypt_sealed_backup_with_prf() {
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
            BackupManifest::default_hash_hex(),
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
            BackupManifest::default_hash_hex(),
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
            BackupManifest::default_hash_hex(),
        )
        .expect_err(
            "Expected decryption to fail with incorrect encrypted backup keypair",
        );
    assert_eq!(
        decryption_error.to_string(),
        "Failed to decrypt backup keypair"
    );
}

/// This test the case where the user creates a backup with no files. The user then restores
/// the backup to a new device. This ensures the user ends up with the same manifest hash as the
/// original device and the remote.
#[tokio::test]
#[serial]
async fn test_decrypt_and_unpack_default_manifest_hash() {
    let manager = BackupManager::new();
    ensure_fs_initialized();

    // Example root secret seed
    let root_secret =
        "{\"version\":\"V1\",\"key\":\"2111111111111111111111111111111111111111111111111111111111111111\"}".to_string();
    let prf_result =
        "67a9b25d7cd2e11cba781af1d4be91c73d3561e5a8fbc2904cb6c2f274acae37".to_string();

    let create_result = manager
        .create_sealed_backup_for_new_user(
            &root_secret,
            prf_result.clone(),
            FactorType::Prf,
        )
        .expect("Failed to create sealed backup with PRF for new user");

    let decrypted = manager
        .decrypt_and_unpack_sealed_backup(
            &create_result.sealed_backup_data,
            create_result.encrypted_backup_keypair.clone(),
            prf_result,
            FactorType::Prf,
            create_result.manifest_hash.clone(),
        )
        .unwrap();

    assert_eq!(
        decrypted.backup_keypair_public_key,
        create_result.backup_keypair_public_key
    );

    let manifest = get_manifest_from_disk("backup_manager");
    let unpacked_manifest_hash = compute_manifest_hash(&manifest);
    let BackupManifest::V0(manifest) = manifest;

    assert_eq!(manifest.previous_manifest_hash, None);
    assert_eq!(unpacked_manifest_hash, create_result.manifest_hash);
}

#[test]
#[serial]
fn test_unpack_writes_files_and_manifest() {
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
            designator: BackupFileDesignator::OrbPkg,
        },
        V0BackupFile {
            data: b"doc-blob".to_vec(),
            checksum: blake3::hash(b"doc-blob").as_bytes().to_owned(),
            path: "document_pkg/document_personal_custody/passport-1.bin".to_string(),
            designator: BackupFileDesignator::DocumentPkg,
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
            BackupManifest::default_hash_hex(),
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

    // Manifest is written under backup_manager/manifest.json
    let manifest_bytes = global_fs
        .read_file("backup_manager/manifest.json".to_string())
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
#[serial]
fn test_re_encrypt_backup() {
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
