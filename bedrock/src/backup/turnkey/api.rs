//! Turnkey API access built on the official Turnkey Rust SDK (`turnkey_client`).
//!
//! Bedrock never handles the persistent private key: a [`KeypairSigner`] (native
//! secure enclave) is adapted into the SDK's [`Stamp`] trait, so the SDK client
//! stamps requests without the key crossing FFI. The SDK's own retry is disabled
//! in favour of our bounded exponential-backoff-with-jitter policy (org rule:
//! retries must be bounded with jitter and cover 429/5xx/timeout/connectivity).
//! Query results are cached in-memory for the lifetime of a single client so that
//! multiple migrations reading the same data do not issue duplicate calls.
//!
//! The sub-organization id is treated as sensitive and is never logged.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use once_cell::sync::OnceCell;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use turnkey_api_key_stamper::{
    Stamp, StampHeader, StamperError, API_KEY_STAMP_HEADER_NAME, SIGNATURE_SCHEME_P256,
};
use turnkey_client::generated::external::data::v1::User;
use turnkey_client::generated::immutable::activity::v1::{
    CreateOauthProvidersIntentV2, OauthProviderParamsV2,
};
use turnkey_client::generated::services::coordinator::public::v1::GetUsersRequest;
use turnkey_client::{RetryConfig, TurnkeyClient};

use crate::primitives::ntp::now_with_ntp;
use crate::primitives::KeypairSigner;
use crate::warn;

use super::error::TurnkeyApiError;

/// URL of the Turnkey auth proxy account endpoint (public sub-org lookups).
const AUTH_PROXY_ACCOUNT_URL: &str = "https://authproxy.turnkey.com/v1/account";
/// Header carrying the public auth-proxy configuration id.
const AUTH_PROXY_CONFIG_ID_HEADER: &str = "X-Auth-Proxy-Config-Id";
/// Auth-proxy filter that resolves a sub-org by the credential's public key.
const AUTH_PROXY_FILTER_PUBLIC_KEY: &str = "PUBLIC_KEY";
/// Per-attempt request timeout for the auth-proxy call.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(15);
/// Maximum characters of a non-2xx body surfaced in a transport error.
const MAX_ERROR_BODY_CHARS: usize = 256;

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

/// Request body for the auth-proxy `/v1/account` lookup.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AuthProxyAccountBody<'a> {
    filter_type: &'a str,
    filter_value: &'a str,
}

/// Response body for the auth-proxy `/v1/account` lookup.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct AuthProxyAccountResponse {
    #[serde(default)]
    organization_id: Option<String>,
}

/// The set of Turnkey operations used by account management.
///
/// Abstracting these behind a trait lets migrations and sub-org resolution be
/// unit-tested against static payloads without any network access.
#[async_trait::async_trait]
pub trait TurnkeyApi: Send + Sync {
    /// Resolves the sub-organization id owning `public_key_hex` via the public
    /// auth proxy. Returns `None` when no account matches.
    ///
    /// # Errors
    /// Returns [`TurnkeyApiError`] on transport or parsing failures.
    async fn resolve_suborganization_id(
        &self,
        auth_proxy_config_id: &str,
        public_key_hex: &str,
    ) -> Result<Option<String>, TurnkeyApiError>;

    /// Lists the users of a sub-organization (stamped by the read/query signer).
    ///
    /// # Errors
    /// Returns [`TurnkeyApiError`] on transport, stamping, or parsing failures.
    async fn get_users(
        &self,
        suborganization_id: &str,
        stamper: Arc<dyn KeypairSigner>,
    ) -> Result<Vec<User>, TurnkeyApiError>;

    /// Creates OAuth providers on a user (stamped by the write/submit signer).
    ///
    /// # Errors
    /// Returns [`TurnkeyApiError`] on transport, stamping, activity, or parsing failures.
    async fn create_oauth_providers(
        &self,
        suborganization_id: &str,
        user_id: &str,
        providers: Vec<OauthProviderParamsV2>,
        stamper: Arc<dyn KeypairSigner>,
    ) -> Result<(), TurnkeyApiError>;
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
        | TurnkeyApiError::SubOrgNotFound
        | TurnkeyApiError::MainUserNotFound
        | TurnkeyApiError::Generic { .. }
        | TurnkeyApiError::FileSystem(_) => false,
    }
}

/// Short, stable label for the failure class, for structured logs.
pub const fn failure_class(error: &TurnkeyApiError) -> &'static str {
    match error {
        TurnkeyApiError::Timeout => "timeout",
        TurnkeyApiError::RateLimited => "rate_limited",
        TurnkeyApiError::ServerError { .. } => "server_error",
        TurnkeyApiError::Transport { .. } => "transport",
        TurnkeyApiError::Unauthorized => "unauthorized",
        TurnkeyApiError::NotFound => "not_found",
        TurnkeyApiError::Activity { .. } => "activity",
        TurnkeyApiError::Signer(_) => "signer",
        TurnkeyApiError::Client(_) => "client",
        TurnkeyApiError::SubOrgNotFound => "suborg_not_found",
        TurnkeyApiError::MainUserNotFound => "main_user_not_found",
        TurnkeyApiError::Generic { .. } => "generic",
        TurnkeyApiError::FileSystem(_) => "filesystem",
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

    /// Builds an SDK client that stamps with `signer`, with SDK retries disabled.
    fn sdk_client(
        signer: Arc<dyn KeypairSigner>,
    ) -> Result<TurnkeyClient<KeypairSignerStamper>, TurnkeyApiError> {
        TurnkeyClient::<KeypairSignerStamper>::builder()
            .api_key(KeypairSignerStamper::new(signer))
            .retry_config(RetryConfig::none())
            .build()
            .map_err(TurnkeyApiError::from)
    }

    /// Decides whether to retry after a failed attempt; logs the outcome.
    /// Returns the delay to wait before retrying, or `None` to give up.
    fn next_delay(
        &self,
        attempt: u32,
        error: &TurnkeyApiError,
        operation: &str,
    ) -> Option<Duration> {
        if attempt >= self.retry.max_attempts || !is_retryable(error) {
            warn!(
                "turnkey.request.failed op={operation} attempts={attempt} class={}",
                failure_class(error)
            );
            None
        } else {
            let delay = backoff_delay(attempt, &self.retry);
            warn!(
                "turnkey.request.retry op={operation} attempt={attempt} class={} delay_ms={}",
                failure_class(error),
                delay.as_millis()
            );
            Some(delay)
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

#[async_trait::async_trait]
impl TurnkeyApi for TurnkeyApiClient {
    async fn resolve_suborganization_id(
        &self,
        auth_proxy_config_id: &str,
        public_key_hex: &str,
    ) -> Result<Option<String>, TurnkeyApiError> {
        let body = serde_json::to_vec(&AuthProxyAccountBody {
            filter_type: AUTH_PROXY_FILTER_PUBLIC_KEY,
            filter_value: public_key_hex,
        })
        .map_err(|e| {
            TurnkeyApiError::Client(format!("serialize auth-proxy body: {e}"))
        })?;

        let mut attempt: u32 = 0;
        let bytes = loop {
            match auth_proxy_post(auth_proxy_config_id, &body).await {
                Ok(bytes) => break bytes,
                Err(error) => {
                    attempt += 1;
                    let Some(delay) =
                        self.next_delay(attempt, &error, "resolve_suborg")
                    else {
                        return Err(error);
                    };
                    tokio::time::sleep(delay).await;
                }
            }
        };

        let response: AuthProxyAccountResponse = serde_json::from_slice(&bytes)
            .map_err(|e| {
                TurnkeyApiError::Client(format!("decode auth-proxy response: {e}"))
            })?;
        Ok(response.organization_id.filter(|id| !id.is_empty()))
    }

    async fn get_users(
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

        let mut attempt: u32 = 0;
        let users = loop {
            match client.get_users(request.clone()).await {
                Ok(response) => break response.users,
                Err(error) => {
                    let error = TurnkeyApiError::from(error);
                    attempt += 1;
                    let Some(delay) = self.next_delay(attempt, &error, "get_users")
                    else {
                        return Err(error);
                    };
                    tokio::time::sleep(delay).await;
                }
            }
        };

        self.cache_users(suborganization_id, &users);
        Ok(users)
    }

    async fn create_oauth_providers(
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

        let mut attempt: u32 = 0;
        loop {
            match client
                .create_oauth_providers(
                    suborganization_id.to_string(),
                    timestamp_ms,
                    intent.clone(),
                )
                .await
            {
                Ok(_) => return Ok(()),
                Err(error) => {
                    let error = TurnkeyApiError::from(error);
                    attempt += 1;
                    let Some(delay) =
                        self.next_delay(attempt, &error, "create_oauth_providers")
                    else {
                        return Err(error);
                    };
                    tokio::time::sleep(delay).await;
                }
            }
        }
    }
}

/// Shared `reqwest` client for the auth-proxy call.
static REQWEST_CLIENT: OnceCell<reqwest::Client> = OnceCell::new();

/// Returns the process-wide `reqwest` client, building it on first use.
fn reqwest_client() -> Result<&'static reqwest::Client, TurnkeyApiError> {
    REQWEST_CLIENT.get_or_try_init(|| {
        reqwest::Client::builder()
            .timeout(REQUEST_TIMEOUT)
            .redirect(reqwest::redirect::Policy::none())
            .gzip(true)
            .build()
            .map_err(|e| TurnkeyApiError::Transport {
                message: format!("failed to build HTTP client: {}", e.without_url()),
            })
    })
}

/// POSTs an auth-proxy account lookup and returns the raw response bytes.
async fn auth_proxy_post(
    config_id: &str,
    body: &[u8],
) -> Result<Vec<u8>, TurnkeyApiError> {
    let client = reqwest_client()?;
    let response = client
        .post(AUTH_PROXY_ACCOUNT_URL)
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .header(AUTH_PROXY_CONFIG_ID_HEADER, config_id)
        .body(body.to_vec())
        .send()
        .await
        .map_err(map_reqwest_error)?;

    let status = response.status();
    let bytes = response.bytes().await.map_err(map_reqwest_error)?;
    if status.is_success() {
        Ok(bytes.to_vec())
    } else {
        Err(map_status(status.as_u16(), &bytes))
    }
}

/// Maps a `reqwest` error to a typed transport error, stripping any URL.
fn map_reqwest_error(error: reqwest::Error) -> TurnkeyApiError {
    if error.is_timeout() {
        TurnkeyApiError::Timeout
    } else {
        TurnkeyApiError::Transport {
            message: error.without_url().to_string(),
        }
    }
}

/// Maps a non-2xx HTTP status to a typed error.
fn map_status(status: u16, body: &[u8]) -> TurnkeyApiError {
    match status {
        429 => TurnkeyApiError::RateLimited,
        401 | 403 => TurnkeyApiError::Unauthorized,
        404 => TurnkeyApiError::NotFound,
        500..=599 => TurnkeyApiError::ServerError { status },
        _ => {
            let snippet: String = String::from_utf8_lossy(body)
                .chars()
                .take(MAX_ERROR_BODY_CHARS)
                .collect();
            TurnkeyApiError::Transport {
                message: format!("HTTP {status}: {snippet}"),
            }
        }
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
        assert!(!is_retryable(&TurnkeyApiError::SubOrgNotFound));
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
    fn http_status_mapping() {
        assert!(matches!(map_status(429, b""), TurnkeyApiError::RateLimited));
        assert!(matches!(
            map_status(401, b""),
            TurnkeyApiError::Unauthorized
        ));
        assert!(matches!(
            map_status(403, b""),
            TurnkeyApiError::Unauthorized
        ));
        assert!(matches!(map_status(404, b""), TurnkeyApiError::NotFound));
        assert!(matches!(
            map_status(503, b""),
            TurnkeyApiError::ServerError { status: 503 }
        ));
        assert!(matches!(
            map_status(400, b"bad"),
            TurnkeyApiError::Transport { .. }
        ));
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

    #[test]
    fn auth_proxy_body_serializes_camel_case() {
        let body = serde_json::to_value(AuthProxyAccountBody {
            filter_type: AUTH_PROXY_FILTER_PUBLIC_KEY,
            filter_value: "abcd",
        })
        .unwrap();
        assert_eq!(body["filterType"], "PUBLIC_KEY");
        assert_eq!(body["filterValue"], "abcd");
    }
}
