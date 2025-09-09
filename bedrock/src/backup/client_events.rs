use bedrock_macros::{bedrock_error, bedrock_export};
use rand::RngCore;
use serde::{Deserialize, Serialize};

use super::manifest::ManifestManager;
use crate::primitives::filesystem::create_middleware;
use crate::primitives::filesystem::get_filesystem_raw;
use crate::primitives::filesystem::FileSystemMiddleware;
use crate::primitives::http_client::{get_http_client, HttpHeader};
use crate::primitives::platform::PlatformKind;
use crate::HttpMethod;

/// Errors that can occur when reporting client events.
#[bedrock_error]
pub enum ClientEventsError {
    /// HTTP client has not been initialized
    #[error("HTTP client not initialized. Call set_http_client() first.")]
    HttpClientNotInitialized,

    /// JSON serialization/deserialization error
    #[error("JSON error: {message}")]
    Json {
        /// The JSON error message
        message: String,
    },

    /// Random number generation error
    #[error("RNG error: {message}")]
    Rng {
        /// The RNG error message
        message: String,
    },

    /// HTTP error when sending events
    #[error(transparent)]
    HttpError(#[from] crate::primitives::http_client::HttpError),
}

/// High-level event kinds we care to report
#[derive(
    Debug,
    Clone,
    Copy,
    Serialize,
    Deserialize,
    PartialEq,
    Eq,
    uniffi::Enum,
    strum::Display,
)]
#[serde(rename_all = "snake_case")]
#[strum(serialize_all = "snake_case")]
pub enum EventKind {
    /// Backup sync or any backup file changes (store/remove)
    Sync,
    /// Backup enabled
    Enable,
    /// Backup disabled
    Disable,
    /// Add main factor
    AddMainFactor,
    /// Remove main factor
    RemoveMainFactor,
    /// Add sync factor
    AddSyncFactor,
    /// Remove sync factor
    RemoveSyncFactor,
}

/// Minimal representation of an OIDC factor for reporting
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, uniffi::Record)]
pub struct MainFactor {
    /// Factor kind, e.g. OIDC
    pub kind: String,
    /// Account type, e.g. GOOGLE
    pub account: String,
    /// ISO 8601 string
    #[serde(rename = "createdAt")]
    pub created_at: String,
}

/// Base report stored locally and merged into outgoing events.
#[derive(Debug, Clone, Serialize, Deserialize, Default, uniffi::Record)]
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
    /// Whether user is orb verified
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_user_orb_verified: Option<bool>,
    /// Whether orb verification happened after Sep 2025
    #[serde(skip_serializing_if = "Option::is_none")]
    pub orb_verified_after_sep25: Option<bool>,
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
    pub encryption_keys: Option<Vec<String>>,
    /// Main factors present
    #[serde(skip_serializing_if = "Option::is_none")]
    pub main_factors: Option<Vec<MainFactor>>,
    /// Backup file designators present
    #[serde(skip_serializing_if = "Option::is_none")]
    pub backup_file_designators: Option<Vec<String>>,
    /// Approx backup size in KB
    #[serde(skip_serializing_if = "Option::is_none")]
    pub backup_size_kb: Option<u64>,
    /// Device-local sync counter
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_sync_count: Option<u32>,
    /// App version
    #[serde(skip_serializing_if = "Option::is_none")]
    pub app_version: Option<String>,
    /// Platform
    #[serde(skip_serializing_if = "Option::is_none")]
    pub platform: Option<PlatformKind>,
    /// Last synced at (ISO8601)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_synced_at: Option<String>,
}

/// Inputs supplied by native for fields that cannot be derived internally
#[derive(Debug, Clone, uniffi::Record)]
pub struct RecalculateInput {
    /// User PKID
    pub user_pkid: Option<String>,
    /// Installation ID (low entropy, cached, cleared on uninstall)
    pub installation_id: Option<String>,
    /// Whether user is orb verified
    pub is_user_orb_verified: Option<bool>,
    /// Whether orb verification happened after Sep 2025
    pub orb_verified_after_sep25: Option<bool>,
    /// Whether user is document verified
    pub is_user_document_verified: Option<bool>,
    /// Whether user has Turnkey account
    pub has_turnkey_account: Option<bool>,
    /// Number of sync factors
    pub sync_factor_count: Option<u32>,
    /// Encryption keys present (e.g., prf, turnkey)
    pub encryption_keys: Option<Vec<String>>,
    /// Main factors present
    pub main_factors: Option<Vec<MainFactor>>,
    /// Device-local sync counter
    pub device_sync_count: Option<u32>,
    /// App version
    pub app_version: Option<String>,
    /// Platform
    pub platform: Option<PlatformKind>,
    /// Last synced at (ISO8601)
    pub last_synced_at: Option<String>,
}

/// Payload for a single event
#[derive(Debug, Serialize, Deserialize)]
struct EventPayload {
    /// Event ID (e.g., `UUIDv4`)
    #[serde(rename = "id")]
    id: String,
    /// Timestamp (`ISO 8601`)
    #[serde(rename = "timestamp")]
    timestamp: String,
    /// Event kind string
    #[serde(rename = "event")]
    event: String,
    /// Whether the event was successful
    #[serde(rename = "success")]
    success: bool,
    /// Generic error message if any
    #[serde(rename = "latestError", skip_serializing_if = "Option::is_none")]
    latest_error: Option<String>,

    // merged base report fields
    #[serde(rename = "userPkId", skip_serializing_if = "Option::is_none")]
    user_pk_id: Option<String>,
    #[serde(rename = "installationId", skip_serializing_if = "Option::is_none")]
    installation_id: Option<String>,
    #[serde(rename = "isBackupEnabled", skip_serializing_if = "Option::is_none")]
    is_backup_enabled: Option<bool>,
    #[serde(rename = "isUserOrbVerified", skip_serializing_if = "Option::is_none")]
    is_user_orb_verified: Option<bool>,
    #[serde(
        rename = "orbVerifiedAfterJul25",
        skip_serializing_if = "Option::is_none"
    )]
    orb_verified_after_jul25: Option<bool>,
    #[serde(
        rename = "isUserDocumentVerified",
        skip_serializing_if = "Option::is_none"
    )]
    is_user_document_verified: Option<bool>,
    #[serde(rename = "hasTurnkeyAccount", skip_serializing_if = "Option::is_none")]
    has_turnkey_account: Option<bool>,
    #[serde(rename = "syncFactorCount", skip_serializing_if = "Option::is_none")]
    sync_factor_count: Option<u32>,
    #[serde(rename = "encryptionKeys", skip_serializing_if = "Option::is_none")]
    encryption_keys: Option<Vec<String>>,
    #[serde(rename = "mainFactors", skip_serializing_if = "Option::is_none")]
    main_factors: Option<Vec<MainFactor>>, // same shape
    #[serde(rename = "backupFilesModules", skip_serializing_if = "Option::is_none")]
    backup_files_modules: Option<Vec<String>>,
    #[serde(rename = "backupFileSizeKb", skip_serializing_if = "Option::is_none")]
    backup_file_size_kb: Option<u64>,
    #[serde(rename = "deviceSyncCount", skip_serializing_if = "Option::is_none")]
    device_sync_count: Option<u32>,
    #[serde(rename = "appVersion", skip_serializing_if = "Option::is_none")]
    app_version: Option<String>,
    #[serde(rename = "platform", skip_serializing_if = "Option::is_none")]
    platform: Option<String>,
    #[serde(rename = "lastSyncedAt", skip_serializing_if = "Option::is_none")]
    last_synced_at: Option<String>,
}

/// Reports client events with a base report persisted under a prefixed folder.
#[derive(uniffi::Object)]
pub struct ClientEventsReporter {
    /// Scoped filesystem middleware for this module (prefixes paths).
    fs: FileSystemMiddleware,
}

#[bedrock_export]
impl ClientEventsReporter {
    #[uniffi::constructor]
    #[must_use]
    /// Constructs a new `ClientEventsReporter` with a scoped filesystem middleware.
    pub fn new() -> Self {
        Self {
            fs: create_middleware("backup_client_events"),
        }
    }

    /// Returns the installation ID, generating and persisting it if missing.
    ///
    /// # Errors
    /// Returns an error if reading or writing the base report fails, or if the RNG fails.
    pub fn installation_id(&self) -> Result<String, ClientEventsError> {
        self.ensure_installation_id()
    }

    /// Set non-dynamic report attributes provided by native.
    ///
    /// # Errors
    /// Returns an error if serialization or filesystem write fails.
    pub fn set_backup_report_attributes(
        &self,
        input: RecalculateInput,
    ) -> Result<(), ClientEventsError> {
        let mut base = self.read_base_report().unwrap_or_default();
        base.user_pkid = input.user_pkid.or(base.user_pkid);
        base.installation_id = input.installation_id.or(base.installation_id);
        base.is_user_orb_verified =
            input.is_user_orb_verified.or(base.is_user_orb_verified);
        base.orb_verified_after_sep25 = input
            .orb_verified_after_sep25
            .or(base.orb_verified_after_sep25);
        base.is_user_document_verified = input
            .is_user_document_verified
            .or(base.is_user_document_verified);
        base.has_turnkey_account =
            input.has_turnkey_account.or(base.has_turnkey_account);
        base.sync_factor_count = input.sync_factor_count.or(base.sync_factor_count);
        base.encryption_keys = input.encryption_keys.or(base.encryption_keys);
        base.main_factors = input.main_factors.or(base.main_factors);
        base.device_sync_count = input.device_sync_count.or(base.device_sync_count);
        base.app_version = input.app_version.or(base.app_version);
        base.platform = input.platform.or(base.platform);
        base.last_synced_at = input.last_synced_at.or(base.last_synced_at);

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
        kind: EventKind,
        success: bool,
        error_message: Option<String>,
        timestamp_iso8601: String,
    ) -> Result<(), ClientEventsError> {
        // Ensure installation ID exists before sending
        let ensured_installation_id = self.ensure_installation_id()?;

        let http =
            get_http_client().ok_or(ClientEventsError::HttpClientNotInitialized)?;

        let base = self.read_base_report().unwrap_or_default();

        let event = EventPayload {
            id: uuid::Uuid::new_v4().to_string(),
            timestamp: timestamp_iso8601,
            event: kind.to_string(),
            success,
            latest_error: error_message,
            user_pk_id: base.user_pkid,
            installation_id: Some(ensured_installation_id),
            is_backup_enabled: base.is_backup_enabled,
            is_user_orb_verified: base.is_user_orb_verified,
            orb_verified_after_jul25: base.orb_verified_after_sep25,
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

        let body = serde_json::to_vec(&event).map_err(|e| ClientEventsError::Json {
            message: e.to_string(),
        })?;

        let headers: Vec<HttpHeader> = vec![HttpHeader {
            name: "Content-Type".to_string(),
            value: "application/json".to_string(),
        }];
        http.fetch_from_app_backend(
            Self::EVENTS_ENDPOINT.to_string(),
            HttpMethod::Post,
            headers,
            Some(body),
        )
        .await?;

        Ok(())
    }
}

impl Default for ClientEventsReporter {
    fn default() -> Self {
        Self {
            fs: create_middleware("client_events"),
        }
    }
}

impl ClientEventsReporter {
    const BASE_FILE: &'static str = "base_report.json";
    const EVENTS_ENDPOINT: &'static str = "/v1/backup/status";

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
            Err(e) => Err(ClientEventsError::Rng {
                message: e.to_string(),
            }),
        }
    }

    fn read_base_report(&self) -> Result<BaseReport, ClientEventsError> {
        self.fs.read_file(Self::BASE_FILE).map_or_else(
            |_| Ok(BaseReport::default()),
            |bytes| {
                serde_json::from_slice(&bytes).map_err(|e| ClientEventsError::Json {
                    message: e.to_string(),
                })
            },
        )
    }

    fn write_base_report(&self, base: &BaseReport) -> Result<(), ClientEventsError> {
        let serialized =
            serde_json::to_vec(base).map_err(|e| ClientEventsError::Json {
                message: e.to_string(),
            })?;
        self.fs
            .write_file(Self::BASE_FILE, serialized)
            .map_err(|e| ClientEventsError::from(anyhow::Error::from(e)))
    }

    /// Recalculate backup size from manifest and update base report.
    ///
    /// Iterates all files listed in the global manifest, streams each file to calculate
    /// its size, and writes the aggregate (in KB, rounded up) to `backup_size_kb`.
    /// Also updates `is_backup_enabled` and `backup_file_designators`.
    ///
    /// # Errors
    /// Returns an error if manifest or base report cannot be read/written.
    pub fn recalculate_backup_size(&self) -> Result<(), ClientEventsError> {
        let fs = get_filesystem_raw()?;
        let mut base = self.read_base_report().unwrap_or_default();

        // Load manifest via manager (unchecked, no remote gate)
        let mgr = ManifestManager::new();
        let Ok(manifest) = mgr.load_manifest_unchecked() else {
            base.is_backup_enabled = Some(false);
            base.backup_file_designators = Some(Vec::new());
            base.backup_size_kb = Some(0);
            self.write_base_report(&base)?;
            return Ok(());
        };

        let mut designators: std::collections::BTreeSet<String> =
            std::collections::BTreeSet::new();
        let mut total_size_bytes: u64 = 0;

        for entry in manifest.files {
            designators.insert(entry.designator.to_string());

            // Stream file to count its size
            let mut offset: u64 = 0;
            let chunk_size: u64 = 65_536;
            loop {
                let chunk = fs
                    .read_file_range(entry.file_path.clone(), offset, chunk_size)
                    .map_err(|e| ClientEventsError::from(anyhow::Error::from(e)))?;
                if chunk.is_empty() {
                    break;
                }
                total_size_bytes = total_size_bytes
                    .saturating_add(u64::try_from(chunk.len()).unwrap_or(0));
                offset = offset.saturating_add(u64::try_from(chunk.len()).unwrap_or(0));
            }
        }

        base.is_backup_enabled = Some(true);
        base.backup_file_designators = Some(designators.into_iter().collect());
        base.backup_size_kb = Some(total_size_bytes.div_ceil(1024));

        self.write_base_report(&base)?;
        Ok(())
    }
}
