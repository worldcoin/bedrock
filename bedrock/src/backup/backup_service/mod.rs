//! The module contains all logic to interact with the [backup-service](https://github.com/worldcoin/backup-service).

mod wire;
pub use wire::{
    BackupEncryptionKey, BackupFactor, BackupFactorKind, BackupMetadata,
    BackupOidcAccount, DeleteFactorResponse,
};

use std::time::Duration;

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use reqwest::header::CONTENT_TYPE;
use reqwest::StatusCode;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use wire::{
    Authorization, ChallengeResponse, DeleteBackupRequest, DeleteFactorRequest,
    FactorScope, RetrieveMetadataRequest, ServiceErrorBody,
};

use crate::backup::{BackupOperationError, NeedsReauthReason};
use crate::primitives::attestation::get_attestation_gateway;
use crate::primitives::config::BedrockEnvironment;
use crate::primitives::retry::{retry_with_backoff, RetryError, RetryPolicy};
use crate::primitives::{KeypairSignerError, P256Signer};
use crate::HttpError;

/// Header carrying the body-bound attestation-gateway token.
const ATTESTATION_HEADER: &str = "attestation-token";

const DELETE_FACTOR_CHALLENGE_PATH: &str = "/v1/delete-factor/challenge/keypair";
const DELETE_FACTOR_PATH: &str = "/v1/delete-factor";
const DELETE_BACKUP_CHALLENGE_PATH: &str = "/v1/delete-backup/challenge/keypair";
const DELETE_BACKUP_PATH: &str = "/v1/delete-backup";
const RETRIEVE_METADATA_CHALLENGE_PATH: &str =
    "/v1/retrieve-metadata/challenge/keypair";
const RETRIEVE_METADATA_PATH: &str = "/v1/retrieve-metadata";

/// Per-request timeout. A degraded backup service must not hang the operation.
///
/// NOTE: Backup creation and sync will require larger timeouts, it'll be added once that
/// feature is supported.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(7);

/// Max timeout for fetching challenges. Fail fast!
const CHALLENGE_TIMEOUT: Duration = Duration::from_secs(5);

/// Deadline for the foreign attestation callback, which Bedrock cannot otherwise
/// bound and which sits in the commit path.
const ATTESTATION_TIMEOUT: Duration = Duration::from_secs(10);

/// HTTP client for the backup service, owning its own `reqwest` transport.
#[derive(Debug)]
pub struct BackupServiceClient {
    http: reqwest::Client,
    base_url: String,
}

impl BackupServiceClient {
    /// Builds a client targeting `environment`'s backup service.
    ///
    /// # Errors
    /// Very unexpected. Something went wrong creating an HTTP client.
    pub fn new(environment: BedrockEnvironment) -> Result<Self, BackupOperationError> {
        Self::with_base_url(environment.backup_service_base_url().to_string())
    }

    /// Builds a client targeting an explicit `base_url`, for pointing the real
    /// client at a mock server in tests.
    #[cfg(test)]
    pub fn with_base_url_for_test(
        base_url: String,
    ) -> Result<Self, BackupOperationError> {
        Self::with_base_url(base_url)
    }

    fn with_base_url(base_url: String) -> Result<Self, BackupOperationError> {
        // Bedrock-owned outbound HTTPS must go through the shared trust policy: on
        // Android that is the bundled `webpki-roots`, since the native store needs a
        // JNI `Context` that does not cross the FFI boundary.
        let http = crate::primitives::tls::client_builder()
            .map_err(|error| {
                crate::error!("backup_service.tls_config_failed err={error}");
                BackupOperationError::Network { retryable: false }
            })?
            .timeout(REQUEST_TIMEOUT)
            .build()
            .map_err(|error| {
                crate::error!("backup_service.client_build_failed err={error}");
                BackupOperationError::Network { retryable: false }
            })?;
        Ok(Self { http, base_url })
    }

    /// Retrieves the current backup metadata.
    ///
    /// # Errors
    /// See [`BackupOperationError`].
    pub async fn retrieve_metadata(
        &self,
        sync_factor: &P256Signer,
        backup_id: &str,
    ) -> Result<BackupMetadata, BackupOperationError> {
        let challenge = self
            .fetch_challenge(RETRIEVE_METADATA_CHALLENGE_PATH, &json!({}))
            .await?;
        let authorization =
            ec_keypair_authorization(sync_factor, &challenge.challenge)?;
        let request = RetrieveMetadataRequest {
            authorization,
            challenge_token: challenge.token,
            backup_id: backup_id.to_string(),
        };
        let body =
            serde_json::to_vec(&request).map_err(|error| serialize_error(&error))?;

        let bytes = self
            .post_bytes(
                "retrieve_metadata",
                RETRIEVE_METADATA_PATH,
                body,
                &[],
                false, // Single-use challenge token (no retries)
            )
            .await?;
        serde_json::from_slice(&bytes).map_err(|error| deserialize_error(&error))
    }

    /// Deletes a factor via the attestation-gated `delete-factor` endpoint.
    ///
    /// `encryption_key` is sent only when removing the last OIDC factor, to drop the
    /// Turnkey encryption key from the metadata.
    ///
    /// # Errors
    /// See [`BackupOperationError`].
    pub async fn delete_factor(
        &self,
        sync_factor: &P256Signer,
        factor_id: &str,
        encryption_key: Option<BackupEncryptionKey>,
    ) -> Result<DeleteFactorResponse, BackupOperationError> {
        let challenge = self
            .fetch_challenge(
                DELETE_FACTOR_CHALLENGE_PATH,
                &json!({ "factorId": factor_id }),
            )
            .await?;
        let authorization =
            ec_keypair_authorization(sync_factor, &challenge.challenge)?;
        let request = DeleteFactorRequest {
            authorization,
            challenge_token: challenge.token,
            factor_id: factor_id.to_string(),
            encryption_key,
            scope: FactorScope::Main,
        };

        let body =
            serde_json::to_vec(&request).map_err(|error| serialize_error(&error))?;

        let provider = get_attestation_gateway().ok_or_else(|| {
            crate::error!("backup_service.attestation.provider_missing");
            BackupOperationError::Generic {
                error_message: "attestation token provider not initialized".to_string(),
            }
        })?;

        let token = match tokio::time::timeout(
            ATTESTATION_TIMEOUT,
            provider.assert_json_request("POST", DELETE_FACTOR_PATH, &body),
        )
        .await
        {
            Ok(token) => token.map_err(|error| attestation_error(&error))?,
            Err(_elapsed) => {
                crate::warn!("backup_service.attestation.timed_out");
                return Err(BackupOperationError::Attestation);
            }
        };

        let bytes = self
            .post_bytes(
                "delete_factor",
                DELETE_FACTOR_PATH,
                body,
                &[(ATTESTATION_HEADER, token)],
                false,
            )
            .await?;
        serde_json::from_slice(&bytes).map_err(|error| deserialize_error(&error))
    }

    /// Deletes the entire backup.
    ///
    /// # Errors
    /// See [`BackupOperationError`].
    pub async fn delete_backup(
        &self,
        sync_factor: &P256Signer,
    ) -> Result<(), BackupOperationError> {
        let challenge = self
            .fetch_challenge(DELETE_BACKUP_CHALLENGE_PATH, &json!({}))
            .await?;
        let authorization =
            ec_keypair_authorization(sync_factor, &challenge.challenge)?;
        let request = DeleteBackupRequest {
            authorization,
            challenge_token: challenge.token,
        };
        let body =
            serde_json::to_vec(&request).map_err(|error| serialize_error(&error))?;

        self.post_bytes(
            "delete_backup",
            DELETE_BACKUP_PATH,
            body,
            &[],
            false, // Single-use challenge token (no retries)
        )
        .await
        .map(|_| ())
    }

    /// Fetches a keypair challenge from `path`
    async fn fetch_challenge(
        &self,
        path: &str,
        body: &Value,
    ) -> Result<ChallengeResponse, BackupOperationError> {
        let bytes =
            serde_json::to_vec(body).map_err(|error| serialize_error(&error))?;
        let fetch = self.post_bytes("challenge", path, bytes, &[], true);
        let Ok(raw) = tokio::time::timeout(CHALLENGE_TIMEOUT, fetch).await else {
            crate::warn!("backup_service.challenge_timed_out path={path}");
            return Err(BackupOperationError::Network { retryable: true });
        };
        serde_json::from_slice(&raw?).map_err(|error| deserialize_error(&error))
    }

    /// POSTs raw `body` bytes, retrying transient failures when `retry` is set.
    async fn post_bytes(
        &self,
        op: &str,
        path: &str,
        body: Vec<u8>,
        headers: &[(&str, String)],
        retry: bool,
    ) -> Result<Vec<u8>, BackupOperationError> {
        let url = format!("{}{}", self.base_url, path);
        retry_with_backoff(
            &RetryPolicy::default(),
            op,
            |error| {
                retry
                    && matches!(
                        error,
                        BackupOperationError::Network { retryable: true }
                    )
            },
            || self.send_once(&url, &body, headers),
        )
        .await
        .map_err(|e| match e {
            RetryError::Timeout => BackupOperationError::Timeout,
            RetryError::Operation(e) => e,
        })
    }

    /// Sends a single POST and maps the outcome to bytes or a typed error.
    async fn send_once(
        &self,
        url: &str,
        body: &[u8],
        headers: &[(&str, String)],
    ) -> Result<Vec<u8>, BackupOperationError> {
        let mut request = self
            .http
            .post(url)
            .header(CONTENT_TYPE, "application/json")
            .body(body.to_vec());
        for (name, value) in headers {
            request = request.header(*name, value);
        }
        let response = request.send().await.map_err(transport_error)?;
        let status = response.status();
        let bytes = response.bytes().await.map_err(transport_error)?.to_vec();
        if status.is_success() {
            Ok(bytes)
        } else {
            Err(status_error(status, &bytes))
        }
    }
}

/// Builds an `EC_KEYPAIR` authorization: the uncompressed SEC1 public key and a DER
/// signature over `SHA256(challenge)`, both base64-encoded.
fn ec_keypair_authorization(
    sync_factor: &P256Signer,
    challenge_base64: &str,
) -> Result<Authorization, BackupOperationError> {
    let challenge = STANDARD.decode(challenge_base64).map_err(|error| {
        crate::error!("backup_service.challenge.decode_failed err={error}");
        BackupOperationError::BackupService {
            code: "invalid_challenge".to_string(),
        }
    })?;
    let digest = Sha256::digest(&challenge);
    let signature = sync_factor.sign_digest(digest.to_vec())?;
    let public_key = uncompressed_public_key(sync_factor)?;
    Ok(Authorization::EcKeypair {
        public_key: STANDARD.encode(public_key),
        signature: STANDARD.encode(signature.to_der()),
    })
}

/// Expands the signer's compressed SEC1 key (hex-encoded) to the 65-byte uncompressed encoding the
/// backup service requires (will be base64-encoded).
fn uncompressed_public_key(
    sync_factor: &P256Signer,
) -> Result<Vec<u8>, BackupOperationError> {
    let compressed = hex::decode(sync_factor.public_key_hex()).map_err(|_| {
        BackupOperationError::Signer {
            inner: KeypairSignerError::InvalidKey,
        }
    })?;
    let point = p256::PublicKey::from_sec1_bytes(&compressed).map_err(|error| {
        BackupOperationError::Signer {
            inner: KeypairSignerError::InvalidPublicKey {
                error_message: error.to_string(),
            },
        }
    })?;
    Ok(point.to_encoded_point(false).as_bytes().to_vec())
}

/// Maps a transport failure to a retryable/non-retryable network error, never
/// leaking the URL.
fn transport_error(error: reqwest::Error) -> BackupOperationError {
    // `is_body`/`is_request` cover a connection reset while the response body is being
    // read: the request never completed, so a retry is as safe as for a timeout.
    let retryable = error.is_timeout()
        || error.is_connect()
        || error.is_body()
        || error.is_request();
    crate::warn!(
        "backup_service.transport retryable={retryable} err={}",
        error.without_url()
    );
    BackupOperationError::Network { retryable }
}

/// Whether `status` will plausibly succeed on a later attempt.
///
/// 5xx is a degraded service; 429 is backpressure and 408 a server-side timeout, both
/// of which clear on their own. Classifying those two as terminal is what would make
/// [`BackupServiceClient::fetch_challenge`] silently skip the bounded retry it opts
/// into.
fn is_transient_status(status: StatusCode) -> bool {
    status.is_server_error()
        || status == StatusCode::TOO_MANY_REQUESTS
        || status == StatusCode::REQUEST_TIMEOUT
}

/// Classifies a non-2xx backup-service response.
///
/// `unauthorized_factor` means the sync factor is no longer authorized and the
/// caller must re-authenticate. Transient statuses become retryable network failures
/// whether or not the body parses.
fn status_error(status: StatusCode, body: &[u8]) -> BackupOperationError {
    if let Ok(parsed) = serde_json::from_slice::<ServiceErrorBody>(body) {
        let code = parsed.error.code;
        if code == "unauthorized_factor" {
            crate::warn!("backup_service.unauthorized_factor");
            return BackupOperationError::NeedsReauth {
                reason: NeedsReauthReason::SyncFactorInvalid,
            };
        }
        if is_transient_status(status) {
            // The generic retry log carries neither, and they are what distinguishes
            // a 500 from a 503 during an incident.
            crate::warn!(
                "backup_service.transient code={code} status={}",
                status.as_u16()
            );
            return BackupOperationError::Network { retryable: true };
        }
        crate::warn!(
            "backup_service.rejected code={code} status={}",
            status.as_u16()
        );
        return BackupOperationError::BackupService { code };
    }
    if is_transient_status(status) {
        crate::warn!("backup_service.transient status={}", status.as_u16());
        BackupOperationError::Network { retryable: true }
    } else {
        crate::warn!("backup_service.client_error status={}", status.as_u16());
        BackupOperationError::BackupService {
            code: format!("http_{}", status.as_u16()),
        }
    }
}

/// Maps any attestation-provider failure to [`BackupOperationError::Attestation`].
///
/// The failure originates in the native attestation client, which owns the gateway
/// exchange and the user-facing handling of it. Bedrock does not re-derive meaning
/// from a response it did not make.
fn attestation_error(error: &HttpError) -> BackupOperationError {
    crate::warn!("backup_service.attestation.failed err={error}");
    BackupOperationError::Attestation
}

fn serialize_error(error: &serde_json::Error) -> BackupOperationError {
    crate::error!("backup_service.serialize_failed err={error}");
    BackupOperationError::Generic {
        error_message: "failed to serialize backup service request".to_string(),
    }
}

fn deserialize_error(error: &serde_json::Error) -> BackupOperationError {
    crate::error!("backup_service.deserialize_failed err={error}");
    BackupOperationError::Generic {
        error_message: "failed to parse backup service response".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backup::turnkey::test::TestSigner;
    use p256::ecdsa::signature::Verifier;
    use p256::ecdsa::{Signature, VerifyingKey};
    use std::sync::Arc;

    /// Proves the authorization Bedrock builds verifies exactly how the backup
    /// service's `verify_signature` checks it: a 65-byte uncompressed SEC1 key and a
    /// DER signature (<= 72 bytes) verified message-style over the raw challenge.
    #[test]
    fn ec_keypair_authorization_verifies_like_backup_service() {
        let raw_challenge = [7u8; 32];
        let challenge_base64 = STANDARD.encode(raw_challenge);
        let signer = P256Signer::verify(Arc::new(TestSigner::new())).unwrap();

        let Authorization::EcKeypair {
            public_key,
            signature,
        } = ec_keypair_authorization(&signer, &challenge_base64).unwrap();

        let public_key = STANDARD.decode(&public_key).unwrap();
        assert_eq!(public_key.len(), 65, "service requires uncompressed SEC1");
        let verifying_key = VerifyingKey::from_sec1_bytes(&public_key).unwrap();

        let signature = STANDARD.decode(&signature).unwrap();
        assert!(
            signature.len() <= 72,
            "DER P-256 signature is at most 72 bytes"
        );
        let signature = Signature::from_der(&signature).unwrap();

        verifying_key
            .verify(&raw_challenge, &signature)
            .expect("signature must verify over the raw challenge");
    }

    #[test]
    fn ec_keypair_authorization_rejects_malformed_challenge() {
        let signer = P256Signer::verify(Arc::new(TestSigner::new())).unwrap();
        let error =
            ec_keypair_authorization(&signer, "not valid base64!!!").unwrap_err();
        assert!(matches!(error, BackupOperationError::BackupService { .. }));
    }

    /// `fetch_challenge` opts into bounded retry, but only a `Network { retryable }`
    /// classification actually retries. 429 and 408 reaching the caller as terminal
    /// business errors is the bug both PR reviewers caught.
    #[test]
    fn transient_statuses_are_retryable_with_or_without_a_body() {
        let body = br#"{"error":{"code":"rate_limited","message":"slow down"}}"#;
        for status in [
            StatusCode::TOO_MANY_REQUESTS,
            StatusCode::REQUEST_TIMEOUT,
            StatusCode::INTERNAL_SERVER_ERROR,
            StatusCode::SERVICE_UNAVAILABLE,
        ] {
            assert!(
                matches!(
                    status_error(status, body),
                    BackupOperationError::Network { retryable: true }
                ),
                "{status} with a body should be retryable"
            );
            assert!(
                matches!(
                    status_error(status, b"not json"),
                    BackupOperationError::Network { retryable: true }
                ),
                "{status} without a body should be retryable"
            );
        }
    }

    /// An ordinary rejection must stay terminal: retrying it burns the single-use
    /// challenge token for nothing.
    #[test]
    fn business_rejections_stay_terminal() {
        let body = br#"{"error":{"code":"factor_not_found","message":"nope"}}"#;
        assert!(matches!(
            status_error(StatusCode::BAD_REQUEST, body),
            BackupOperationError::BackupService { .. }
        ));
        assert!(matches!(
            status_error(StatusCode::NOT_FOUND, b"not json"),
            BackupOperationError::BackupService { .. }
        ));
    }

    #[tokio::test]
    async fn delete_backup_accepts_an_empty_204_body() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path(DELETE_BACKUP_CHALLENGE_PATH))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "challenge": STANDARD.encode([7u8; 32]),
                "token": "challenge-token",
            })))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path(DELETE_BACKUP_PATH))
            .respond_with(ResponseTemplate::new(204))
            .mount(&server)
            .await;

        let client = BackupServiceClient::with_base_url_for_test(server.uri()).unwrap();
        let signer = P256Signer::verify(Arc::new(TestSigner::new())).unwrap();

        client.delete_backup(&signer).await.unwrap();
    }

    #[tokio::test]
    async fn delete_backup_is_not_replayed() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path(DELETE_BACKUP_CHALLENGE_PATH))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "challenge": STANDARD.encode([7u8; 32]),
                "token": "challenge-token",
            })))
            .mount(&server)
            .await;
        // A status the challenge fetch *would* retry, to prove the delete does not.
        Mock::given(method("POST"))
            .and(path(DELETE_BACKUP_PATH))
            .respond_with(ResponseTemplate::new(503))
            .mount(&server)
            .await;

        let client = BackupServiceClient::with_base_url_for_test(server.uri()).unwrap();
        let signer = P256Signer::verify(Arc::new(TestSigner::new())).unwrap();
        let error = client.delete_backup(&signer).await.unwrap_err();

        assert!(matches!(
            error,
            BackupOperationError::Network { retryable: true }
        ));
        let deletes = server
            .received_requests()
            .await
            .unwrap()
            .iter()
            .filter(|request| request.url.path() == DELETE_BACKUP_PATH)
            .count();
        assert_eq!(deletes, 1, "the delete must be attempted exactly once");
    }

    /// The challenge token is single-use and the delete is not idempotent. Only the
    /// `retry: false` argument prevents a replay, and nothing else pins it.
    #[tokio::test]
    async fn delete_factor_is_never_replayed() {
        use crate::primitives::attestation::AttestationTokenProvider;
        use crate::primitives::set_attestation_token_provider;
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        struct FakeAttestation;
        #[async_trait::async_trait]
        impl AttestationTokenProvider for FakeAttestation {
            async fn attestation_token(
                &self,
                _request_hash: String,
            ) -> Result<String, HttpError> {
                Ok("fake".to_string())
            }
        }
        set_attestation_token_provider(Arc::new(FakeAttestation));

        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path(DELETE_FACTOR_CHALLENGE_PATH))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "challenge": STANDARD.encode([7u8; 32]),
                "token": "challenge-token",
            })))
            .mount(&server)
            .await;
        // A status the challenge fetch *would* retry, to prove the delete does not.
        Mock::given(method("POST"))
            .and(path(DELETE_FACTOR_PATH))
            .respond_with(ResponseTemplate::new(503))
            .mount(&server)
            .await;

        let client = BackupServiceClient::with_base_url_for_test(server.uri()).unwrap();
        let signer = P256Signer::verify(Arc::new(TestSigner::new())).unwrap();
        let error = client
            .delete_factor(&signer, "f-1", None)
            .await
            .unwrap_err();

        assert!(matches!(
            error,
            BackupOperationError::Network { retryable: true }
        ));
        let deletes = server
            .received_requests()
            .await
            .unwrap()
            .iter()
            .filter(|request| request.url.path() == DELETE_FACTOR_PATH)
            .count();
        assert_eq!(deletes, 1, "the delete must be attempted exactly once");
    }
}
