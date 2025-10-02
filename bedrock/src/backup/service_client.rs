use crate::{backup::BackupError, HttpError};
use std::sync::{Arc, OnceLock};

/// Global instance of a foreign-implemented `BackupServiceApi` used by Bedrock if provided.
static BACKUP_SERVICE_API_INSTANCE: OnceLock<Arc<dyn BackupServiceApi>> =
    OnceLock::new();

/// Foreign trait that native layers implement to perform backup-service network calls.
///
/// If set, this will be used by Bedrock instead of any internal HTTP client.
#[uniffi::export(with_foreign)]
#[async_trait::async_trait]
pub trait BackupServiceApi: Send + Sync {
    /// Uploads an updated backup using the `/v1/sync` endpoint.
    ///
    /// Reference: <https://github.com/worldcoin/backup-service/blob/main/src/routes/sync_backup.rs>
    async fn sync(&self, request: SyncSubmitRequest) -> Result<(), HttpError>;

    /// Retrieves metadata (manifest head) using the `/v1/retrieve_metadata` endpoint.
    ///
    /// Reference: <https://github.com/worldcoin/backup-service/blob/main/src/routes/retrieve_metadata.rs>
    ///
    /// # Notes
    /// This expects specific attributes from the response, not all the response is returned to Bedrock (avoids additional memory allocations)
    async fn retrieve_metadata(
        &self,
    ) -> Result<RetrieveMetadataResponsePayload, HttpError>;
}

/// Response body for retrieve metadata call.
///
/// # Notes
/// Only the required attributes are returned to Bedrock (avoids additional memory allocations)
#[derive(Debug, Clone, uniffi::Record)]
pub struct RetrieveMetadataResponsePayload {
    /// The hex-encoded manifest hash.
    pub manifest_hash: String,
}

/// Request body for `/v1/sync` (i.e. backup upload)
///
/// Reference: <https://github.com/worldcoin/backup-service/blob/main/src/routes/sync_backup.rs>
///
/// # Notes
/// `authorization` and `challenge_token` are skipped because they are handled by the Native App.
#[derive(Debug, Clone, uniffi::Record)]
pub struct SyncSubmitRequest {
    /// Hex-encoded current manifest hash (client state before the update).
    pub current_manifest_hash: String,
    /// Hex-encoded new manifest hash (client state after applying the update).
    pub new_manifest_hash: String,
    /// Sealed backup bytes to upload.
    pub sealed_backup: Vec<u8>,
}

/// Sets the global `BackupServiceApi` instance.
#[uniffi::export]
pub fn set_backup_service_api(api: Arc<dyn BackupServiceApi>) -> bool {
    BACKUP_SERVICE_API_INSTANCE.set(api).is_ok()
}

/// Returns whether a foreign `BackupServiceApi` has been configured.
#[uniffi::export]
#[must_use]
pub fn is_backup_service_api_initialized() -> bool {
    BACKUP_SERVICE_API_INSTANCE.get().is_some()
}

/// Get a reference to the foreign API or return an error.
fn get_api() -> Result<&'static Arc<dyn BackupServiceApi>, BackupError> {
    BACKUP_SERVICE_API_INSTANCE
        .get()
        .ok_or(BackupError::BackupApiNotInitialized)
}

pub struct BackupServiceClient;

impl BackupServiceClient {
    /// See `BackupServiceApi::sync`.
    pub async fn sync(
        current_manifest_hash: String,
        new_manifest_hash: String,
        sealed_backup: Vec<u8>,
    ) -> Result<(), BackupError> {
        let api = get_api()?;
        let req = SyncSubmitRequest {
            current_manifest_hash,
            new_manifest_hash,
            sealed_backup,
        };
        api.sync(req).await?;
        Ok(())
    }

    /// See `BackupServiceApi::retrieve_metadata`.
    pub async fn get_remote_manifest_hash() -> Result<[u8; 32], BackupError> {
        let api = get_api()?;
        let response = api.retrieve_metadata().await?;

        let hash: [u8; 32] = hex::decode(response.manifest_hash)
            .map_err(|_| BackupError::Generic {
                message: "[BackupServiceApi] invalid response from retrieve_metadata"
                    .to_string(),
            })?
            .try_into()
            .map_err(|_| BackupError::Generic {
                message: "[BackupServiceApi] invalid response from retrieve_metadata"
                    .to_string(),
            })?;
        Ok(hash)
    }
}
