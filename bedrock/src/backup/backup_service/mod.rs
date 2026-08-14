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
    Authorization, ChallengeResponse, DeleteFactorRequest, FactorScope,
    RetrieveMetadataRequest, ServiceErrorBody,
};

use crate::backup::{BackupOperationError, NeedsReauthReason};
use crate::primitives::attestation::get_attestation_gateway;
use crate::primitives::config::BedrockEnvironment;
use crate::primitives::retry::{retry_with_backoff, RetryPolicy};
use crate::primitives::{KeypairSignerError, P256Signer};
use crate::HttpError;

/// Header carrying the body-bound attestation-gateway token.
const ATTESTATION_HEADER: &str = "attestation-token";

const DELETE_FACTOR_CHALLENGE_PATH: &str = "/v1/delete-factor/challenge/keypair";
const DELETE_FACTOR_PATH: &str = "/v1/delete-factor";
const RETRIEVE_METADATA_CHALLENGE_PATH: &str =
    "/v1/retrieve-metadata/challenge/keypair";
const RETRIEVE_METADATA_PATH: &str = "/v1/retrieve-metadata";

/// Per-request timeout. A degraded backup service must not hang the operation.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(15);

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

    /// Retrieves the current backup metadata, authenticated by the sync factor.
    ///
    /// # Errors
    /// Returns [`BackupOperationError`] on signing, transport, or backup-service
    /// failure. An `unauthorized_factor` rejection surfaces as
    /// [`BackupOperationError::NeedsReauth`].
    pub async fn retrieve_metadata(
        &self,
        sync_factor: &P256Signer,
    ) -> Result<BackupMetadata, BackupOperationError> {
        let challenge = self
            .fetch_challenge(RETRIEVE_METADATA_CHALLENGE_PATH, &json!({}))
            .await?;
        let authorization =
            ec_keypair_authorization(sync_factor, &challenge.challenge)?;
        let request = RetrieveMetadataRequest {
            authorization,
            challenge_token: challenge.token,
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
    /// Returns [`BackupOperationError`] on signing, attestation, transport, or
    /// backup-service failure.
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

        let token = provider
            .assert_json_request("POST", DELETE_FACTOR_PATH, &body)
            .await
            .map_err(|error| attestation_error(&error))?;

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

    /// Fetches a keypair challenge from `path`. Idempotent, so retried.
    async fn fetch_challenge(
        &self,
        path: &str,
        body: &Value,
    ) -> Result<ChallengeResponse, BackupOperationError> {
        let bytes =
            serde_json::to_vec(body).map_err(|error| serialize_error(&error))?;
        let raw = self.post_bytes("challenge", path, bytes, &[], true).await?;
        serde_json::from_slice(&raw).map_err(|error| deserialize_error(&error))
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
    let retryable = error.is_timeout() || error.is_connect();
    crate::warn!(
        "backup_service.transport retryable={retryable} err={}",
        error.without_url()
    );
    BackupOperationError::Network { retryable }
}

/// Classifies a non-2xx backup-service response.
///
/// `unauthorized_factor` means the sync factor is no longer authorized and the
/// caller must re-authenticate. 5xx without a recognizable body is treated as a
/// retryable network failure.
fn status_error(status: StatusCode, body: &[u8]) -> BackupOperationError {
    if let Ok(parsed) = serde_json::from_slice::<ServiceErrorBody>(body) {
        let code = parsed.error.code;
        if code == "unauthorized_factor" {
            crate::warn!("backup_service.unauthorized_factor");
            return BackupOperationError::NeedsReauth {
                reason: NeedsReauthReason::SyncFactorInvalid,
            };
        }
        if status.is_server_error() {
            // The generic retry log carries neither, and they are what distinguishes
            // a 500 from a 503 during an incident.
            crate::warn!(
                "backup_service.server_error code={code} status={}",
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
    if status.is_server_error() {
        crate::warn!("backup_service.server_error status={}", status.as_u16());
        BackupOperationError::Network { retryable: true }
    } else {
        crate::warn!("backup_service.client_error status={}", status.as_u16());
        BackupOperationError::BackupService {
            code: format!("http_{}", status.as_u16()),
        }
    }
}

/// Maps an attestation-provider failure.
///
/// Risk blocks surface here rather than in [`status_error`]: the gateway refuses to
/// mint a token, so the request never reaches the backup service.
///
/// Attestation is native's to establish before invoking Bedrock: a failure here is
/// reported as an ordinary network error, and native decides what the user sees.
fn attestation_error(error: &HttpError) -> BackupOperationError {
    // Nothing is committed at this point, so a transient gateway failure reported as
    // permanent strands an operation a retry would have completed. Exhaustive: a new
    // `HttpError` variant must be classified, not silently treated as permanent.
    let retryable = match error {
        HttpError::Timeout
        | HttpError::NoConnectivity
        | HttpError::DnsResolutionFailed { .. }
        | HttpError::ConnectionRefused { .. } => true,
        // 429 is backpressure that clears on its own.
        HttpError::BadStatusCode { code, .. } => {
            *code == 429 || (500..600).contains(code)
        }
        HttpError::SslError { .. }
        | HttpError::Cancelled
        | HttpError::Generic { .. }
        | HttpError::FileSystem(_) => false,
    };
    crate::warn!("backup_service.attestation.failed retryable={retryable} err={error}");
    BackupOperationError::Network { retryable }
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

    /// Must agree with `transport_error`, which treats the same classes as retryable.
    #[test]
    fn transient_attestation_failures_are_retryable() {
        for error in [
            HttpError::Timeout,
            HttpError::NoConnectivity,
            HttpError::DnsResolutionFailed {
                error_message: "no such host".to_string(),
            },
            HttpError::ConnectionRefused {
                error_message: "refused".to_string(),
            },
            HttpError::BadStatusCode {
                code: 503,
                response_body: b"gateway unavailable".to_vec(),
            },
            HttpError::BadStatusCode {
                code: 429,
                response_body: b"slow down".to_vec(),
            },
        ] {
            assert!(
                matches!(
                    attestation_error(&error),
                    BackupOperationError::Network { retryable: true }
                ),
                "{error} should be retryable"
            );
        }
    }

    #[test]
    fn permanent_attestation_failures_are_not_retryable() {
        for error in [
            HttpError::Cancelled,
            HttpError::SslError {
                reason: "pinning failed".to_string(),
            },
            HttpError::BadStatusCode {
                code: 400,
                response_body: b"bad request".to_vec(),
            },
        ] {
            assert!(
                matches!(
                    attestation_error(&error),
                    BackupOperationError::Network { retryable: false }
                ),
                "{error} should not be retryable"
            );
        }
    }
}
