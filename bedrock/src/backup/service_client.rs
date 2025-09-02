use serde::Deserialize;

use crate::backup::manifest::SyncSigner;
use crate::HttpError;
use std::sync::{Arc, OnceLock};

/// Challenge payload returned by backup-service challenge endpoints.
#[derive(Debug, Clone, uniffi::Record)]
pub struct ChallengeResponsePayload {
    /// The raw ASCII challenge string to be signed by the sync factor.
    pub challenge: String,
    /// The opaque token that must accompany the signed challenge when submitting a request.
    pub token: String,
}

/// Authorization using an EC keypair for backup-service endpoints.
#[derive(Debug, Clone, uniffi::Record)]
pub struct KeypairAuthorization {
    /// The sync factor public key in uncompressed SEC1 form, base64 (standard) encoded.
    pub public_key_base64: String,
    /// DER-encoded ECDSA P-256 signature over the provided challenge, base64 (standard) encoded.
    pub signature_base64: String,
}

/// Request body for retrieve-metadata using keypair authorization.
#[derive(Debug, Clone, uniffi::Record)]
pub struct RetrieveMetadataRequestPayload {
    /// Authorization payload with public key and signature.
    pub authorization: KeypairAuthorization,
    /// Challenge token obtained from the challenge endpoint.
    pub challenge_token: String,
}

/// Response body for retrieve-metadata call.
#[derive(Debug, Clone, uniffi::Record)]
pub struct RetrieveMetadataResponsePayload {
    /// Hex-encoded, 32-byte BLAKE3 manifest hash.
    pub manifest_hash_hex: String,
}

/// Request body for sync submit using keypair authorization.
#[derive(Debug, Clone, uniffi::Record)]
pub struct SyncSubmitRequest {
    /// Authorization payload with public key and signature.
    pub authorization: KeypairAuthorization,
    /// Challenge token obtained from the challenge endpoint.
    pub challenge_token: String,
    /// Hex-encoded current manifest hash (client view before the update).
    pub current_manifest_hash_hex: String,
    /// Hex-encoded new manifest hash (client view after applying the update).
    pub new_manifest_hash_hex: String,
    /// Sealed backup bytes to upload.
    pub sealed_backup: Vec<u8>,
}

/// Foreign trait that native layers implement to perform backup-service network calls.
///
/// If set, this will be used by Bedrock instead of any internal HTTP client.
#[uniffi::export(with_foreign)]
#[async_trait::async_trait]
pub trait BackupServiceApi: Send + Sync {
    /// Begins a sync by requesting a keypair challenge from backup-service.
    async fn get_sync_challenge_keypair(
        &self,
    ) -> Result<ChallengeResponsePayload, HttpError>;

    /// Submits a sync update with keypair authorization and sealed backup bytes.
    async fn post_sync_with_keypair(
        &self,
        request: SyncSubmitRequest,
    ) -> Result<(), HttpError>;

    /// Requests a keypair challenge for retrieving metadata (manifest head).
    async fn get_retrieve_metadata_challenge_keypair(
        &self,
    ) -> Result<ChallengeResponsePayload, HttpError>;

    /// Retrieves metadata (manifest head) using keypair authorization.
    async fn post_retrieve_metadata_with_keypair(
        &self,
        request: RetrieveMetadataRequestPayload,
    ) -> Result<RetrieveMetadataResponsePayload, HttpError>;
}

/// Global instance of a foreign-implemented `BackupServiceApi` used by Bedrock if provided.
static BACKUP_SERVICE_API_INSTANCE: OnceLock<Arc<dyn BackupServiceApi>> =
    OnceLock::new();

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

#[derive(Debug, Deserialize)]
pub struct ChallengeResponse {
    pub challenge: String,
    pub token: String,
}

/// Get a reference to the foreign API or return an error.
fn get_api() -> Result<&'static Arc<dyn BackupServiceApi>, HttpError> {
    BACKUP_SERVICE_API_INSTANCE
        .get()
        .ok_or(HttpError::BackupApiNotInitialized)
}

/// POST /v1/sync/challenge/keypair → { challenge, token }
pub async fn api_get_sync_challenge_keypair() -> Result<ChallengeResponse, HttpError> {
    let api = get_api()?;
    let ch = api.get_sync_challenge_keypair().await?;
    Ok(ChallengeResponse {
        challenge: ch.challenge,
        token: ch.token,
    })
}

/// POST /v1/sync with multipart payload via foreign API.
pub async fn api_post_sync_with_keypair(
    signer: &dyn SyncSigner,
    challenge: &ChallengeResponse,
    current_manifest_hash: String,
    new_manifest_hash: String,
    sealed_backup: Vec<u8>,
) -> Result<(), HttpError> {
    let api = get_api()?;
    let sig_b64 = signer.sign_challenge_base64(challenge.challenge.clone());
    let pk_b64 = signer.public_key_base64();
    let req = SyncSubmitRequest {
        authorization: KeypairAuthorization {
            public_key_base64: pk_b64,
            signature_base64: sig_b64,
        },
        challenge_token: challenge.token.clone(),
        current_manifest_hash_hex: current_manifest_hash,
        new_manifest_hash_hex: new_manifest_hash,
        sealed_backup,
    };
    api.post_sync_with_keypair(req).await
}

/// Retrieves remote manifest hash using foreign API and the provided signer.
pub async fn api_get_remote_manifest_hash(
    signer: &dyn SyncSigner,
) -> Result<[u8; 32], HttpError> {
    let api = get_api()?;
    let ch = api.get_retrieve_metadata_challenge_keypair().await?;
    let sig_b64 = signer.sign_challenge_base64(ch.challenge);
    let pk_b64 = signer.public_key_base64();
    let resp = api
        .post_retrieve_metadata_with_keypair(RetrieveMetadataRequestPayload {
            authorization: KeypairAuthorization {
                public_key_base64: pk_b64,
                signature_base64: sig_b64,
            },
            challenge_token: ch.token,
        })
        .await?;
    let hash: [u8; 32] = hex::decode(resp.manifest_hash_hex)
        .map_err(|_| HttpError::Generic {
            message: "unable to hex decode manifest hash".to_string(),
        })?
        .try_into()
        .map_err(|_| HttpError::Generic {
            message: "unable to convert hex encoded manifest hash to [u8; 32]"
                .to_string(),
        })?;
    Ok(hash)
}
