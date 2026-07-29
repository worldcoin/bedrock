//! Turnkey API access built on the official Turnkey Rust SDK (`turnkey_client`).
//!
//! Bedrock never handles the persistent private key: a [`KeypairSigner`] (native
//! secure enclave) is adapted into the SDK's [`Stamp`] trait, so the SDK client
//! stamps requests without the key crossing FFI. The SDK retries only the polling
//! of `PENDING` activities to completion; it does not retry transport failures, so
//! we wrap each call in our own bounded exponential-backoff-with-jitter policy
//! covering 429/5xx/timeouts/connectivity (org rule). Query results are cached
//! in-memory for the lifetime of a single client so that multiple migrations
//! reading the same data do not issue duplicate calls.
//!
//! The sub-organization id is treated as sensitive and is never logged.

use std::collections::HashMap;
use std::future::Future;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde::Serialize;
use sha2::{Digest, Sha256};
use turnkey_api_key_stamper::{
    Stamp, StampHeader, StamperError, API_KEY_STAMP_HEADER_NAME, SIGNATURE_SCHEME_P256,
};
use turnkey_client::generated::external::data::v1::User;
use turnkey_client::generated::immutable::activity::v1::{
    CreateOauthProvidersIntentV2, OauthProviderParamsV2,
};
use turnkey_client::generated::services::coordinator::public::v1::{
    GetUsersRequest, GetWhoamiRequest,
};
use turnkey_client::{RetryConfig, TurnkeyClient};

use crate::primitives::ntp::now_with_ntp;
use crate::primitives::KeypairSigner;
use crate::warn;

use super::error::TurnkeyApiError;

/// Adapts a [`KeypairSigner`] into the Turnkey SDK's [`Stamp`] trait, so the SDK
/// client can stamp requests with a key held in native secure storage.
///
/// Produces byte-for-byte the same `X-Stamp` as the SDK's own `TurnkeyP256ApiKey`.
pub struct KeypairSignerStamper {
    signer: Arc<dyn KeypairSigner>,
}

impl KeypairSignerStamper {
    /// Wraps a signer for use as a Turnkey stamper.
    #[must_use]
    pub fn new(signer: Arc<dyn KeypairSigner>) -> Self {
        Self { signer }
    }
}

impl Stamp for KeypairSignerStamper {
    fn stamp(&self, body: &[u8]) -> Result<StampHeader, StamperError> {
        let digest = Sha256::digest(body);
        let public_key = self
            .signer
            .public_key()
            .map_err(|e| StamperError::InvalidPublicKeyBytes(e.to_string()))?;
        let signature = self
            .signer
            .sign_digest(digest.to_vec())
            .map_err(|e| StamperError::InvalidPrivateKeyBytes(e.to_string()))?;
        let stamp = ApiStamp {
            public_key: hex::encode(public_key),
            signature: hex::encode(signature),
            scheme: SIGNATURE_SCHEME_P256.to_string(),
        };
        let json = serde_json::to_string(&stamp).map_err(|e| {
            StamperError::InvalidPrivateKeyBytes(format!(
                "stamp serialization failed: {e}"
            ))
        })?;
        Ok(StampHeader {
            name: API_KEY_STAMP_HEADER_NAME.to_string(),
            value: URL_SAFE_NO_PAD.encode(json.as_bytes()),
        })
    }
}

/// Turnkey API stamp payload (mirrors the SDK's internal stamp shape).
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ApiStamp {
    public_key: String,
    signature: String,
    scheme: String,
}

/// Bounded retry policy: exponential backoff with full jitter.
#[derive(Debug, Clone, Copy)]
struct RetryPolicy {
    max_attempts: u32,
    base_delay: Duration,
    max_delay: Duration,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            max_attempts: 3,
            base_delay: Duration::from_millis(250),
            max_delay: Duration::from_secs(2),
        }
    }
}

/// Returns whether an error is worth retrying (transient classes only).
const fn is_retryable(error: &TurnkeyApiError) -> bool {
    match error {
        TurnkeyApiError::Timeout
        | TurnkeyApiError::RateLimited
        | TurnkeyApiError::ServerError { .. }
        | TurnkeyApiError::Transport { .. } => true,
        TurnkeyApiError::Unauthorized
        | TurnkeyApiError::NotFound
        | TurnkeyApiError::Activity { .. }
        | TurnkeyApiError::Signer(_)
        | TurnkeyApiError::Client(_)
        | TurnkeyApiError::MainUserNotFound => false,
    }
}

/// Computes the backoff delay for `attempt` (1-indexed) with full jitter,
/// capped at [`RetryPolicy::max_delay`].
fn backoff_delay(attempt: u32, policy: &RetryPolicy) -> Duration {
    let factor = 2u32.saturating_pow(attempt.saturating_sub(1));
    let exp = policy.base_delay.saturating_mul(factor);
    let capped = exp.min(policy.max_delay);
    let ceil_ms = u64::try_from(capped.as_millis()).unwrap_or(u64::MAX);
    if ceil_ms == 0 {
        return Duration::ZERO;
    }
    // Full jitter: uniform in [0, ceil_ms]. Randomness need not be secure here.
    Duration::from_millis(rand::random::<u64>() % (ceil_ms + 1))
}

/// Turnkey API client using the Turnkey SDK plus Bedrock's retry and caching.
///
/// `get_users` responses are cached for the lifetime of the client (a single
/// `check_migrations` run), keyed by sub-organization id.
pub struct TurnkeyApiClient {
    retry: RetryPolicy,
    users_cache: Mutex<HashMap<String, Vec<User>>>,
}

impl TurnkeyApiClient {
    /// Creates a client with the default retry policy and an empty cache.
    #[must_use]
    pub fn new() -> Self {
        Self {
            retry: RetryPolicy::default(),
            users_cache: Mutex::new(HashMap::new()),
        }
    }

    /// Builds an SDK client that stamps with `signer`.
    ///
    /// Uses the SDK's default retry config so it polls `PENDING` activities to
    /// completion; transport-level retries are handled by [`Self::with_retry`].
    fn sdk_client(
        signer: Arc<dyn KeypairSigner>,
    ) -> Result<TurnkeyClient<KeypairSignerStamper>, TurnkeyApiError> {
        TurnkeyClient::<KeypairSignerStamper>::builder()
            .api_key(KeypairSignerStamper::new(signer))
            .retry_config(RetryConfig::default())
            .build()
            .map_err(TurnkeyApiError::from)
    }

    /// Runs `op`, retrying transient failures with bounded backoff and full jitter.
    async fn with_retry<T, Fut>(
        &self,
        operation: &str,
        mut op: impl FnMut() -> Fut + Send,
    ) -> Result<T, TurnkeyApiError>
    where
        Fut: Future<Output = Result<T, TurnkeyApiError>> + Send,
    {
        let mut attempt: u32 = 0;
        loop {
            match op().await {
                Ok(value) => return Ok(value),
                Err(error) => {
                    attempt += 1;
                    if attempt >= self.retry.max_attempts || !is_retryable(&error) {
                        warn!("turnkey.request.failed op={operation} attempts={attempt} err={error}");
                        return Err(error);
                    }
                    let delay = backoff_delay(attempt, &self.retry);
                    warn!(
                        "turnkey.request.retry op={operation} attempt={attempt} delay_ms={} err={error}",
                        delay.as_millis()
                    );
                    tokio::time::sleep(delay).await;
                }
            }
        }
    }

    fn cached_users(&self, suborganization_id: &str) -> Option<Vec<User>> {
        self.users_cache
            .lock()
            .ok()
            .and_then(|cache| cache.get(suborganization_id).cloned())
    }

    fn cache_users(&self, suborganization_id: &str, users: &[User]) {
        if let Ok(mut cache) = self.users_cache.lock() {
            cache.insert(suborganization_id.to_string(), users.to_vec());
        }
    }
}

impl TurnkeyApiClient {
    /// Resolves the sub-organization id for `stamper`'s credential via `whoami`.
    ///
    /// `parent_organization_id` is the org to query against; Turnkey returns the
    /// sub-organization that the stamping credential belongs to. Unlike the
    /// auth-proxy public-key lookup, this works for a credential that has never
    /// been used before, because the sub-org is derived from the request stamp.
    ///
    /// # Errors
    /// Returns [`TurnkeyApiError`] on transport, stamping, or parsing failures.
    pub async fn resolve_suborganization_id(
        &self,
        parent_organization_id: &str,
        stamper: Arc<dyn KeypairSigner>,
    ) -> Result<String, TurnkeyApiError> {
        let client = Self::sdk_client(stamper)?;
        let request = GetWhoamiRequest {
            organization_id: parent_organization_id.to_string(),
        };
        self.with_retry("whoami", || async {
            client
                .get_whoami(request.clone())
                .await
                .map(|response| response.organization_id)
                .map_err(TurnkeyApiError::from)
        })
        .await
    }

    /// Lists the users of a sub-organization (stamped by the read/query signer).
    ///
    /// Results are cached for the lifetime of this client.
    ///
    /// # Errors
    /// Returns [`TurnkeyApiError`] on transport, stamping, or parsing failures.
    pub async fn get_users(
        &self,
        suborganization_id: &str,
        stamper: Arc<dyn KeypairSigner>,
    ) -> Result<Vec<User>, TurnkeyApiError> {
        if let Some(cached) = self.cached_users(suborganization_id) {
            return Ok(cached);
        }
        let client = Self::sdk_client(stamper)?;
        let request = GetUsersRequest {
            organization_id: suborganization_id.to_string(),
        };

        let users = self
            .with_retry("get_users", || async {
                client
                    .get_users(request.clone())
                    .await
                    .map(|response| response.users)
                    .map_err(TurnkeyApiError::from)
            })
            .await?;

        self.cache_users(suborganization_id, &users);
        Ok(users)
    }

    /// Creates OAuth providers on a user (stamped by the write/submit signer).
    ///
    /// # Errors
    /// Returns [`TurnkeyApiError`] on transport, stamping, activity, or parsing failures.
    pub async fn create_oauth_providers(
        &self,
        suborganization_id: &str,
        user_id: &str,
        providers: Vec<OauthProviderParamsV2>,
        stamper: Arc<dyn KeypairSigner>,
    ) -> Result<(), TurnkeyApiError> {
        let client = Self::sdk_client(stamper)?;
        let intent = CreateOauthProvidersIntentV2 {
            user_id: user_id.to_string(),
            oauth_providers: providers,
        };
        // Fixed timestamp across retries so Turnkey de-duplicates identical
        // submissions (a retry after a timeout must not create duplicates).
        let timestamp_ms = ntp_timestamp_ms();

        self.with_retry("create_oauth_providers", || async {
            client
                .create_oauth_providers(
                    suborganization_id.to_string(),
                    timestamp_ms,
                    intent.clone(),
                )
                .await
                .map(|_| ())
                .map_err(TurnkeyApiError::from)
        })
        .await
    }
}

/// Current NTP time in milliseconds, for Turnkey activity timestamps.
fn ntp_timestamp_ms() -> u128 {
    u128::try_from(now_with_ntp().timestamp_millis()).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backup::turnkey::test::TestSigner;

    /// Randomly generated P-256 key reused across stamp tests.
    const TEST_KEY: &str =
        "8b380767b1947c1c67da42dbc6929a9137202bab770bca2ddcdeaa1dbdd505b8";

    #[test]
    fn stamp_matches_sdk_and_legacy() {
        use base64::prelude::BASE64_URL_SAFE_NO_PAD;

        // All three are RFC6979-deterministic ECDSA over SHA-256(body), so they
        // agree on the signature and public key.
        let body = serde_json::json!({ "example": 123 }).to_string();

        let adapter =
            KeypairSignerStamper::new(Arc::new(TestSigner::from_hex(TEST_KEY)));
        let produced = adapter.stamp(body.as_bytes()).unwrap().value;

        // Byte-identical to the SDK's own P-256 stamper (the format we emit).
        let sdk =
            turnkey_api_key_stamper::TurnkeyP256ApiKey::from_strings(TEST_KEY, None)
                .unwrap()
                .stamp(body.as_bytes())
                .unwrap()
                .value;
        assert_eq!(produced, sdk);

        // Semantically identical to the legacy Turnkey::stamp. It orders the
        // stamp JSON keys differently (sorted), so compare decoded objects.
        let legacy = super::super::Turnkey::new().stamp(&body, TEST_KEY).unwrap();
        let decode = |value: &str| -> serde_json::Value {
            serde_json::from_slice(&BASE64_URL_SAFE_NO_PAD.decode(value).unwrap())
                .unwrap()
        };
        assert_eq!(decode(&produced), decode(&legacy));
    }

    #[test]
    fn stamp_verifies_against_body() {
        use base64::prelude::BASE64_URL_SAFE_NO_PAD;
        use p256::ecdsa::signature::Verifier;

        let body = serde_json::json!({ "activity": "create" }).to_string();
        let adapter =
            KeypairSignerStamper::new(Arc::new(TestSigner::from_hex(TEST_KEY)));
        let stamp = adapter.stamp(body.as_bytes()).unwrap().value;

        let decoded = BASE64_URL_SAFE_NO_PAD.decode(&stamp).unwrap();
        let stamp_json: serde_json::Value = serde_json::from_slice(&decoded).unwrap();
        assert_eq!(stamp_json["scheme"], SIGNATURE_SCHEME_P256);

        let signature = p256::ecdsa::Signature::from_der(
            &hex::decode(stamp_json["signature"].as_str().unwrap()).unwrap(),
        )
        .unwrap();
        let public_key = p256::PublicKey::from_sec1_bytes(
            &hex::decode(stamp_json["publicKey"].as_str().unwrap()).unwrap(),
        )
        .unwrap();
        let verifying_key = p256::ecdsa::VerifyingKey::from(public_key);
        assert!(verifying_key.verify(body.as_bytes(), &signature).is_ok());
    }

    #[test]
    fn retryable_classes_only() {
        assert!(is_retryable(&TurnkeyApiError::Timeout));
        assert!(is_retryable(&TurnkeyApiError::RateLimited));
        assert!(is_retryable(&TurnkeyApiError::ServerError { status: 503 }));
        assert!(is_retryable(&TurnkeyApiError::Transport {
            message: "reset".to_string()
        }));

        assert!(!is_retryable(&TurnkeyApiError::Unauthorized));
        assert!(!is_retryable(&TurnkeyApiError::NotFound));
        assert!(!is_retryable(&TurnkeyApiError::Activity {
            message: "failed".to_string()
        }));
    }

    #[test]
    fn backoff_is_bounded_by_max_delay() {
        let policy = RetryPolicy::default();
        for attempt in 1..=8 {
            assert!(backoff_delay(attempt, &policy) <= policy.max_delay);
        }
    }

    #[test]
    fn sdk_error_status_classification() {
        use turnkey_client::TurnkeyClientError;
        assert!(matches!(
            TurnkeyApiError::from(TurnkeyClientError::UnexpectedHttpStatus(
                429,
                String::new()
            )),
            TurnkeyApiError::RateLimited
        ));
        assert!(matches!(
            TurnkeyApiError::from(TurnkeyClientError::UnexpectedHttpStatus(
                500,
                String::new()
            )),
            TurnkeyApiError::ServerError { status: 500 }
        ));
        assert!(matches!(
            TurnkeyApiError::from(TurnkeyClientError::MissingResult),
            TurnkeyApiError::Activity { .. }
        ));
    }
}
