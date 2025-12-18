use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::str::FromStr;
use strum::Display;

use super::manifest::ManifestManager;
use crate::backup::manifest::BackupManifest;
use crate::backup::BackupFileDesignator;
use crate::primitives::config::Os;
use crate::primitives::filesystem::{
    create_middleware, get_filesystem_raw, FileSystemError, FileSystemExt,
    FileSystemMiddleware,
};
use crate::primitives::http_client::{get_http_client, HttpHeader};
use crate::HttpMethod;

/// Errors that can occur when reporting client events.
#[derive(Debug, thiserror::Error)]
pub enum ClientEventsError {
    /// HTTP client has not been initialized
    #[error("HTTP client not initialized. Call set_http_client() first.")]
    HttpClientNotInitialized,

    /// JSON serialization/deserialization error
    #[error("JSON error")]
    Json,

    /// Random number generation error
    #[error("RNG error")]
    Rng,

    /// HTTP error when sending events
    #[error(transparent)]
    HttpError(#[from] crate::primitives::http_client::HttpError),

    /// `FileSystem` error
    #[error(transparent)]
    FileSystemError(#[from] crate::primitives::filesystem::FileSystemError),
}

/// High-level event kinds we care to report
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, uniffi::Enum, Display)]
#[serde(rename_all = "snake_case")]
#[strum(serialize_all = "snake_case")]
pub enum BackupReportEventKind {
    /// Backup sync or any backup file changes (store/remove)
    Sync,
    /// Add main factor
    AddMainFactor,
    /// Remove main factor
    RemoveMainFactor,
    /// Triggered when a user performs a log in (prev. called restore) with the new system
    LogIn,
}

/// Minimal representation of an OIDC factor for reporting
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, uniffi::Record)]
pub struct BackupReportMainFactor {
    /// Factor kind, e.g. OIDC
    pub kind: String,
    /// Account type, e.g. GOOGLE
    pub account: String,
    /// ISO 8601 string
    #[serde(rename = "createdAt")]
    pub created_at: String,
}

/// Kinds of encryption keys present in backup metadata
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, uniffi::Enum)]
#[serde(rename_all = "snake_case")]
pub enum BackupReportEncryptionKeyKind {
    /// Passkey PRF-derived key
    Prf,
    /// Turnkey-stored random key
    Turnkey,
    /// iCloud Keychain-stored random key (iOS < 18 path)
    IcloudKeychain,
}

/// Base report stored locally and merged into outgoing events.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct BaseReport {
    /// User PKID
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_pkid: Option<String>,
    /// Installation ID (low entropy, cached, cleared on uninstall)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub installation_id: Option<String>,
    /// Whether backup is enabled
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_backup_enabled: Option<bool>,
    /// Whether orb verification happened after Oct 2025
    #[serde(skip_serializing_if = "Option::is_none")]
    pub orb_verified_after_oct_25: Option<bool>,
    /// Whether the user is Orb verified
    pub is_user_orb_verified: Option<bool>,
    /// Whether user is document verified
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_user_document_verified: Option<bool>,
    /// Whether user has Turnkey account
    #[serde(skip_serializing_if = "Option::is_none")]
    pub has_turnkey_account: Option<bool>,
    /// Number of sync factors
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sync_factor_count: Option<u32>,
    /// Encryption keys present (e.g., prf, turnkey)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub encryption_keys: Option<Vec<BackupReportEncryptionKeyKind>>,
    /// Main factors present
    #[serde(skip_serializing_if = "Option::is_none")]
    pub main_factors: Option<Vec<BackupReportMainFactor>>,
    /// Backup file designators present
    #[serde(skip_serializing_if = "Option::is_none")]
    pub backup_file_designators: Option<Vec<BackupFileDesignator>>,
    /// Approx backup size in KB
    #[serde(skip_serializing_if = "Option::is_none")]
    pub backup_size_kb: Option<u64>,
    /// Number of times the user has synced their backup in this device (counter tracked locally)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_sync_count: Option<u32>,
    /// App version
    #[serde(skip_serializing_if = "Option::is_none")]
    pub app_version: Option<String>,
    /// Platform
    #[serde(skip_serializing_if = "Option::is_none")]
    pub platform: Option<Os>,
    /// Last synced at (ISO-8601)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_synced_at: Option<String>,
}

/// Inputs supplied by foreign code (native app) for fields that cannot be derived internally
#[derive(Debug, Clone, uniffi::Record, Default)]
pub struct BackupReportInput {
    /// Whether backup is enabled
    pub is_backup_enabled: Option<bool>,
    /// User PKID
    pub user_pkid: Option<String>,
    /// Whether orb verification happened after 2025-10-01
    pub orb_verified_after_oct_25: Option<bool>,
    /// Whether the user is Orb verified
    pub is_user_orb_verified: Option<bool>,
    /// Whether user is document verified
    pub is_user_document_verified: Option<bool>,
    /// Whether user has Turnkey account
    pub has_turnkey_account: Option<bool>,
    /// Number of sync factors
    pub sync_factor_count: Option<u32>,
    /// Encryption keys present (e.g., prf, turnkey)
    pub encryption_keys: Option<Vec<BackupReportEncryptionKeyKind>>,
    /// Main factors present
    pub main_factors: Option<Vec<BackupReportMainFactor>>,
    /// App version
    pub app_version: Option<String>,
    /// Platform (OS where the app is running)
    pub platform: Option<Os>,
}

/// Payload for a single event
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct EventPayload {
    /// Event ID (e.g., `UUIDv4`)
    id: String,
    /// Timestamp (`ISO 8601`)
    timestamp: String,
    /// Event kind string
    event: String,
    /// Whether the event was successful
    success: bool,
    /// Generic error message if any
    #[serde(skip_serializing_if = "Option::is_none")]
    latest_error: Option<String>,

    // merged base report fields
    #[serde(skip_serializing_if = "Option::is_none")]
    user_pkid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    installation_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    is_backup_enabled: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    orb_verified_after_oct_25: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    is_user_orb_verified: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    is_user_document_verified: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    has_turnkey_account: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    sync_factor_count: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    encryption_keys: Option<Vec<BackupReportEncryptionKeyKind>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    main_factors: Option<Vec<BackupReportMainFactor>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    backup_files_modules: Option<Vec<BackupFileDesignator>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    backup_file_size_kb: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    device_sync_count: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    app_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    platform: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    last_synced_at: Option<String>,
}

/// Reports client events with a base report persisted under a prefixed folder.
pub struct ClientEventsReporter {
    /// Scoped filesystem middleware for this module (prefixes paths).
    fs: FileSystemMiddleware,
}

impl ClientEventsReporter {
    #[must_use]
    /// Constructs a new `ClientEventsReporter` with a scoped filesystem middleware.
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns the installation ID, generating and persisting it if missing.
    ///
    /// # Errors
    /// Returns an error if reading or writing the base report fails, or if the RNG fails.
    pub fn installation_id(&self) -> Result<String, ClientEventsError> {
        self.ensure_installation_id()
    }

    /// Set non-dynamic report attributes provided by the native layer.
    ///
    /// # Errors
    /// Returns an error if serialization or filesystem write fails.
    pub fn set_backup_report_attributes(
        &self,
        input: BackupReportInput,
    ) -> Result<(), ClientEventsError> {
        let mut base = self.read_base_report().unwrap_or_default();
        base.user_pkid = input.user_pkid.or(base.user_pkid);
        base.orb_verified_after_oct_25 = input
            .orb_verified_after_oct_25
            .or(base.orb_verified_after_oct_25);
        base.is_user_orb_verified =
            input.is_user_orb_verified.or(base.is_user_orb_verified);
        base.is_user_document_verified = input
            .is_user_document_verified
            .or(base.is_user_document_verified);
        base.has_turnkey_account =
            input.has_turnkey_account.or(base.has_turnkey_account);
        base.sync_factor_count = input.sync_factor_count.or(base.sync_factor_count);
        base.encryption_keys = input.encryption_keys.or(base.encryption_keys);
        base.main_factors = input.main_factors.or(base.main_factors);
        base.app_version = input.app_version.or(base.app_version);
        base.platform = input.platform.or(base.platform);
        base.is_backup_enabled = input.is_backup_enabled.or(base.is_backup_enabled);

        // If no installation ID provided and none persisted yet, generate and persist now.
        if base.installation_id.is_none() {
            base.installation_id = Some(Self::generate_installation_id()?);
        }

        self.write_base_report(&base)
    }

    /// Send a single event by merging with base report and posting to backend.
    ///
    /// Sends events to the REST API endpoint `/v1/backup/status`.
    ///
    /// # Errors
    /// Returns an error if HTTP client is not initialized or network/serialization fails.
    pub async fn send_event(
        &self,
        kind: BackupReportEventKind,
        success: bool,
        error_message: Option<String>,
        timestamp_iso8601: String,
        is_public: bool,
    ) -> Result<(), ClientEventsError> {
        // Ensure installation ID exists before sending
        let ensured_installation_id = self.ensure_installation_id()?;

        let http =
            get_http_client().ok_or(ClientEventsError::HttpClientNotInitialized)?;

        let mut base = self.read_base_report().unwrap_or_default();

        if matches!(kind, BackupReportEventKind::Sync) && success {
            let current_count = base.device_sync_count.unwrap_or(0);
            base.device_sync_count = Some(current_count.saturating_add(1));
            base.last_synced_at = Some(timestamp_iso8601.clone());
            // Persist updated base report before emitting the event so payload reflects new values.
            self.write_base_report(&base)?;
        }

        let event = EventPayload {
            id: uuid::Uuid::new_v4().to_string(),
            timestamp: timestamp_iso8601,
            event: kind.to_string(),
            success,
            latest_error: error_message,
            user_pkid: base.user_pkid,
            installation_id: Some(ensured_installation_id),
            is_backup_enabled: base.is_backup_enabled,
            orb_verified_after_oct_25: base.orb_verified_after_oct_25,
            is_user_orb_verified: base.is_user_orb_verified,
            is_user_document_verified: base.is_user_document_verified,
            has_turnkey_account: base.has_turnkey_account,
            sync_factor_count: base.sync_factor_count,
            encryption_keys: base.encryption_keys,
            main_factors: base.main_factors,
            backup_files_modules: base.backup_file_designators,
            backup_file_size_kb: base.backup_size_kb,
            device_sync_count: base.device_sync_count,
            app_version: base.app_version,
            platform: base.platform.map(|p| p.as_str().to_string()),
            last_synced_at: base.last_synced_at,
        };

        let body = serde_json::to_vec(&event).map_err(|_| ClientEventsError::Json)?;

        let mut headers: Vec<HttpHeader> = vec![HttpHeader {
            name: "Content-Type".to_string(),
            value: "application/json".to_string(),
        }];

        let endpoint = if is_public {
            headers.push(HttpHeader {
                name: "Authorization".to_string(),
                value: String::new(),
            });
            Self::PUBLIC_EVENTS_ENDPOINT.to_string()
        } else {
            Self::EVENTS_ENDPOINT.to_string()
        };

        http.fetch_from_app_backend(endpoint, HttpMethod::Post, headers, Some(body))
            .await?;

        Ok(())
    }
}

impl Default for ClientEventsReporter {
    fn default() -> Self {
        Self {
            fs: create_middleware(Self::FS_PREFIX),
        }
    }
}

impl ClientEventsReporter {
    const FS_PREFIX: &'static str = "backup_client_events";
    const BASE_FILE: &'static str = "base_report.json";
    const EVENTS_ENDPOINT: &'static str = "/v1/backup/events";
    const PUBLIC_EVENTS_ENDPOINT: &'static str = "/public/v1/backup/events";

    /// Ensure an installation ID exists and is persisted. Returns the ID.
    fn ensure_installation_id(&self) -> Result<String, ClientEventsError> {
        let mut base = self.read_base_report().unwrap_or_default();
        if let Some(id) = &base.installation_id {
            return Ok(id.clone());
        }

        let id = Self::generate_installation_id()?;
        base.installation_id = Some(id.clone());
        self.write_base_report(&base)?;
        Ok(id)
    }

    /// Generate a new 3-byte lowercase hex installation ID.
    fn generate_installation_id() -> Result<String, ClientEventsError> {
        let mut buf = [0u8; 3];
        match rand::rngs::OsRng.try_fill_bytes(&mut buf) {
            Ok(()) => Ok(hex::encode(buf)),
            Err(_) => Err(ClientEventsError::Rng),
        }
    }

    fn read_base_report(&self) -> Result<BaseReport, ClientEventsError> {
        let file_result = self.fs.read_file(Self::BASE_FILE);
        match file_result {
            Ok(bytes) => {
                serde_json::from_slice(&bytes).map_err(|_| ClientEventsError::Json)
            }
            Err(e) => {
                if matches!(e, FileSystemError::FileDoesNotExist) {
                    Ok(BaseReport::default())
                } else {
                    Err(ClientEventsError::FileSystemError(e))
                }
            }
        }
    }

    fn write_base_report(&self, base: &BaseReport) -> Result<(), ClientEventsError> {
        let serialized =
            serde_json::to_vec(base).map_err(|_| ClientEventsError::Json)?;
        self.fs
            .write_file(Self::BASE_FILE, serialized)
            .map_err(ClientEventsError::FileSystemError)
    }

    /// Delete the persisted base report file, if present.
    ///
    /// This is used when the backup is disabled/deleted so that any backup-related
    /// state (e.g., designators, size, counters) is cleared. Missing file is treated
    /// as a no-op.
    ///
    /// # Errors
    /// Returns an error if deleting the base report fails for reasons other than the
    /// file not existing.
    pub fn delete_base_report(&self) -> Result<(), ClientEventsError> {
        match self.fs.delete_file(Self::BASE_FILE) {
            Ok(()) => Ok(()),
            Err(e) => {
                if matches!(e, FileSystemError::FileDoesNotExist) {
                    // Treat missing file as a successful delete.
                    Ok(())
                } else {
                    Err(ClientEventsError::FileSystemError(e))
                }
            }
        }
    }

    /// Sync the base report with the current manifest contents.
    ///
    /// Iterates all files listed in the global manifest, streams each file to calculate
    /// its size, and writes the aggregate (in KB, rounded up) to `backup_size_kb`.
    /// Also updates `is_backup_enabled` and `backup_file_designators`.
    ///
    /// # Errors
    /// Returns an error if manifest or base report cannot be read/written.
    pub fn sync_base_report_with_manifest(&self) -> Result<(), ClientEventsError> {
        let fs = get_filesystem_raw()?;
        let mut base = self.read_base_report().unwrap_or_default();

        // Load manifest via manager (unchecked, no remote gate as it's not mutating the state)
        let mgr = ManifestManager::new();
        let Ok((manifest, _checksum)) = mgr.read_manifest() else {
            base.is_backup_enabled = Some(false);
            base.backup_file_designators = Some(Vec::new());
            base.backup_size_kb = Some(0);
            self.write_base_report(&base)?;
            return Ok(());
        };
        let BackupManifest::V0(manifest) = manifest;

        let mut designators: std::collections::BTreeSet<String> =
            std::collections::BTreeSet::new();
        let mut total_size_bytes: u64 = 0;

        for entry in manifest.files {
            designators.insert(entry.designator.to_string());
            let (_checksum, size_bytes) =
                fs.calculate_checksum_and_size(&entry.file_path)?;
            total_size_bytes = total_size_bytes.saturating_add(size_bytes);
        }

        base.is_backup_enabled = Some(true);
        base.backup_file_designators = Some(
            designators
                .into_iter()
                .filter_map(|s| BackupFileDesignator::from_str(&s).ok())
                .collect(),
        );
        base.backup_size_kb = Some(total_size_bytes.div_ceil(1024));

        self.write_base_report(&base)?;
        Ok(())
    }
}
