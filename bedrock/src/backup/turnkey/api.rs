//! Turnkey API access built on the official Turnkey Rust SDK (`turnkey_client`).
//!
//! The SDK retries only the polling of `PENDING` activities to completion; it does not retry
//! transport failures, so we wrap each call in our own bounded exponential-backoff-with-jitter policy
//! covering 429/5xx/timeouts/connectivity. Query results are cached
//! in-memory for the lifetime of a single client so that multiple migrations
//! reading the same data do not issue duplicate calls.

use std::future::Future;
use std::sync::{Arc, Mutex};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde::Serialize;
use sha2::{Digest, Sha256};
use turnkey_api_key_stamper::{
    Stamp, StampHeader, StamperError, API_KEY_STAMP_HEADER_NAME, SIGNATURE_SCHEME_P256,
};
use turnkey_client::generated::external::data::v1::{Policy, User};
use turnkey_client::generated::immutable::activity::v1::{
    CreateOauthProvidersIntentV2, CreatePolicyIntentV3, DeleteAuthenticatorsIntent,
    DeleteOauthProvidersIntent, DeletePolicyIntent, DeleteSubOrganizationIntent,
    OauthProviderParamsV2, UpdatePolicyIntentV2,
};
use turnkey_client::generated::services::coordinator::public::v1::{
    GetPoliciesRequest, GetUsersRequest, GetWhoamiRequest,
};
use turnkey_client::{RetryConfig, TurnkeyClient};

use crate::backup::{MainFactor, SyncFactor};
use crate::primitives::ntp::now_with_ntp;
use crate::primitives::retry::{retry_with_backoff, RetryPolicy};
use crate::primitives::P256Signer;

use super::error::TurnkeyApiError;

/// Adapts a [`P256Signer`] into the Turnkey SDK's [`Stamp`] trait, so the SDK
/// client can stamp requests with a key held in native secure storage.
///
/// The public key is validated once when the [`P256Signer`] is built, so
/// stamping only signs and reuses the cached key.
///
/// Produces byte-for-byte the same `X-Stamp` as the SDK's own `TurnkeyP256ApiKey`.
pub struct KeypairSignerStamper {
    signer: P256Signer,
}

impl KeypairSignerStamper {
    /// Wraps a verified signer for use as a Turnkey stamper.
    #[must_use]
    pub fn new(signer: &P256Signer) -> Self {
        Self {
            signer: signer.clone(),
        }
    }
}

impl Stamp for KeypairSignerStamper {
    fn stamp(&self, body: &[u8]) -> Result<StampHeader, StamperError> {
        let digest = Sha256::digest(body);
        let signature = self
            .signer
            .sign_digest(digest.to_vec())
            .map_err(|e| StamperError::InvalidPrivateKeyBytes(e.to_string()))?;
        let stamp = ApiStamp {
            public_key: self.signer.public_key_hex().to_string(),
            signature: hex::encode(signature.to_der()),
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

/// A cache of one query result for a **single** sub-organization.
///
/// A [`TurnkeyApiClient`] serves exactly one sub-organization for its lifetime (a
/// user has exactly one), so the cache holds at most one entry. Reading it for a
/// different sub-org is a consistency violation.
struct OrgCache<T> {
    /// The cached `(suborganization_id, value)`, or `None` when empty. The value is
    /// held behind an [`Arc`] so reads share one allocation rather than deep-copying.
    entry: Mutex<Option<(String, Arc<T>)>>,
    /// Names this cache in the poison-recovery log.
    label: &'static str,
}

impl<T> OrgCache<T> {
    const fn new(label: &'static str) -> Self {
        Self {
            entry: Mutex::new(None),
            label,
        }
    }

    /// Locks the entry, recovering from poisoning by discarding its (always
    /// reconstructible) contents.
    fn lock(&self) -> std::sync::MutexGuard<'_, Option<(String, Arc<T>)>> {
        match self.entry.lock() {
            Ok(guard) => guard,
            Err(poisoned) => {
                crate::warn!(
                    "turnkey.cache.poisoned: discarding in-memory {} cache and recovering",
                    self.label
                );
                self.entry.clear_poison();
                let mut guard = poisoned.into_inner();
                *guard = None;
                guard
            }
        }
    }

    /// Returns a shared handle to the cached value for `suborganization_id`, if any.
    ///
    /// # Errors
    /// [`TurnkeyApiError::Consistency`] if a *different* sub-organization is
    /// cached. A client only ever serves one sub-org, so this must never happen;
    /// it signals a critical consistency problem.
    fn get(&self, suborganization_id: &str) -> Result<Option<Arc<T>>, TurnkeyApiError> {
        match &*self.lock() {
            Some((cached, value)) if cached == suborganization_id => {
                Ok(Some(Arc::clone(value)))
            }
            Some(_) => Err(TurnkeyApiError::Consistency),
            None => Ok(None),
        }
    }

    /// Caches `value` for `suborganization_id` (replacing any previous entry) and
    /// returns the shared handle, so the caller reuses the same allocation.
    fn store(&self, suborganization_id: &str, value: T) -> Arc<T> {
        let value = Arc::new(value);
        *self.lock() = Some((suborganization_id.to_string(), Arc::clone(&value)));
        value
    }

    /// Drops the cached entry (e.g. after a write changes the underlying data).
    fn clear(&self) {
        *self.lock() = None;
    }
}

/// Turnkey API client using the Turnkey SDK plus Bedrock's retry and caching.
///
/// Unless otherwise noted, all read operations are cached in-memory for the
/// lifetime of this client.
pub struct TurnkeyApiClient {
    retry: RetryPolicy,
    users_cache: OrgCache<Vec<User>>,
    policies_cache: OrgCache<Vec<Policy>>,
    /// Overrides the SDK's default Turnkey base URL. `None` in production; set
    /// only in tests to point the real client at a mock HTTP server.
    base_url: Option<String>,
}

impl TurnkeyApiClient {
    /// Creates a client with the default retry policy and an empty cache.
    #[must_use]
    pub fn new() -> Self {
        Self {
            retry: RetryPolicy::default(),
            users_cache: OrgCache::new("user"),
            policies_cache: OrgCache::new("policy"),
            base_url: None,
        }
    }

    /// Creates a client that targets `base_url` instead of Turnkey's default,
    /// for driving the real client against a mock HTTP server in tests.
    #[cfg(test)]
    pub fn with_base_url(base_url: String) -> Self {
        Self {
            base_url: Some(base_url),
            ..Self::new()
        }
    }

    /// Builds an SDK client that stamps with `signer`.
    ///
    /// Uses the SDK's default retry config so it polls `PENDING` activities to
    /// completion; transport-level retries are handled by [`Self::with_retry`].
    fn sdk_client(
        &self,
        signer: &P256Signer,
    ) -> Result<TurnkeyClient<KeypairSignerStamper>, TurnkeyApiError> {
        let mut builder = TurnkeyClient::<KeypairSignerStamper>::builder()
            .api_key(KeypairSignerStamper::new(signer))
            .retry_config(RetryConfig::default());
        if let Some(base_url) = &self.base_url {
            builder = builder.base_url(base_url.clone());
        }
        builder.build().map_err(TurnkeyApiError::from)
    }

    /// Runs `op`, retrying transient failures with bounded backoff and jitter.
    async fn with_retry<T, Fut>(
        &self,
        operation: &str,
        op: impl FnMut() -> Fut + Send,
    ) -> Result<T, TurnkeyApiError>
    where
        Fut: Future<Output = Result<T, TurnkeyApiError>> + Send,
    {
        retry_with_backoff(&self.retry, operation, TurnkeyApiError::is_retryable, op)
            .await
    }
}

/// # Warning
/// For any activities (i.e. requests that change the state) it is imperative that
/// the `timestamp_ms` is computed once outside any retry loops. Turnkey submissions
/// are idempotent on a fingerprint, maintaining the same `timestamp_ms` ensures a
/// request is not executed twice.
///
/// Reference: <https://docs.turnkey.com/api-reference/activities/overview>.
///
impl TurnkeyApiClient {
    /// Resolves the sub-organization id for the user based on the public
    /// key provided. Internally uses `whoami`.
    ///
    /// # Errors
    /// Returns [`TurnkeyApiError`] on transport, stamping, or parsing failures.
    pub async fn resolve_suborganization_id(
        &self,
        parent_organization_id: &str,
        signer: SyncFactor<'_>,
    ) -> Result<String, TurnkeyApiError> {
        let client = self.sdk_client(signer.0)?;
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

    /// Returns the Turnkey user id that `signer` authenticates as in
    /// `suborganization_id`.
    ///
    /// Not cached: the whole point is to exercise this specific signer.
    ///
    /// # Errors
    /// Returns [`TurnkeyApiError`] on transport, stamping, or parsing failures. An
    /// unregistered key surfaces as [`TurnkeyApiError::is_public_key_not_found`].
    pub async fn whoami_user_id(
        &self,
        suborganization_id: &str,
        signer: MainFactor<'_>,
    ) -> Result<String, TurnkeyApiError> {
        let client = self.sdk_client(signer.0)?;
        let request = GetWhoamiRequest {
            organization_id: suborganization_id.to_string(),
        };
        self.with_retry("whoami_user_id", || async {
            client
                .get_whoami(request.clone())
                .await
                .map(|response| response.user_id)
                .map_err(TurnkeyApiError::from)
        })
        .await
    }

    /// Lists the users of a sub-organization.
    ///
    /// Results are cached for the lifetime of this client.
    ///
    /// # Errors
    /// Returns [`TurnkeyApiError`] on transport, stamping, or parsing failures.
    /// Re-reads the users, discarding any cached copy first.
    ///
    /// For callers that must act on the current state rather than a snapshot taken
    /// earlier in the same flow.
    ///
    /// # Errors
    /// Returns [`TurnkeyApiError`] on transport, stamping, or parsing failures.
    pub async fn get_users_fresh(
        &self,
        suborganization_id: &str,
        signer: SyncFactor<'_>,
    ) -> Result<Arc<Vec<User>>, TurnkeyApiError> {
        self.users_cache.clear();
        self.get_users(suborganization_id, signer).await
    }

    pub async fn get_users(
        &self,
        suborganization_id: &str,
        signer: SyncFactor<'_>,
    ) -> Result<Arc<Vec<User>>, TurnkeyApiError> {
        if let Some(cached) = self.users_cache.get(suborganization_id)? {
            return Ok(cached);
        }
        let client = self.sdk_client(signer.0)?;
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

        Ok(self.users_cache.store(suborganization_id, users))
    }

    /// Creates OAuth providers on a user (needs a [`MainFactor`] signer).
    ///
    /// All `providers` are submitted in a **single** `CreateOauthProviders`
    /// activity, so they are added atomically.
    ///
    /// Please note this activity only adds new providers, it does not replace or upsert. If
    /// the same (aud,sub,iss) combination for an existing login method is used for a new one,
    /// it will be rejected by the API.
    ///
    /// Reference: <https://docs.turnkey.com/features/authentication/social-logins>
    ///
    /// # Errors
    /// Returns [`TurnkeyApiError`] on transport, stamping, activity, or parsing failures.
    pub async fn create_oauth_providers(
        &self,
        suborganization_id: &str,
        user_id: &str,
        providers: Vec<OauthProviderParamsV2>,
        signer: MainFactor<'_>,
    ) -> Result<(), TurnkeyApiError> {
        let client = self.sdk_client(signer.0)?;
        let requested = providers.len();
        let intent = CreateOauthProvidersIntentV2 {
            user_id: user_id.to_string(),
            oauth_providers: providers,
        };

        let timestamp_ms = ntp_timestamp_ms()?;
        let created = self
            .with_retry("create_oauth_providers", || async {
                client
                    .create_oauth_providers(
                        suborganization_id.to_string(),
                        timestamp_ms,
                        intent.clone(),
                    )
                    .await
                    .map(|activity| activity.result.provider_ids.len())
                    .map_err(TurnkeyApiError::from)
            })
            .await?;

        if created != requested {
            // If Turnkey's activity succeeded but the created count is mismatched, this is surfacing
            // a major consistency problem with Turnkey. Requires immediate attention.
            crate::critical!(
                "turnkey.create_oauth_providers.count_mismatch requested={requested} created={created}"
            );
        }

        // User has changed, remove the cache
        self.users_cache.clear();
        Ok(())
    }

    /// Deletes OAuth providers from a Turnkey user.
    ///
    /// A [`MainFactor`] is required because OAuth providers live on the root user
    /// ([`super::policies::AUTH_USER_MAIN_USERNAME`]) and Turnkey doesn't allow non-root
    /// users to update root users even if a policy allows it.
    ///
    /// # Errors
    /// Returns [`TurnkeyApiError`] on transport, stamping, activity, or parsing failures.
    pub async fn delete_oauth_providers(
        &self,
        suborganization_id: &str,
        user_id: &str,
        provider_ids: Vec<String>,
        signer: MainFactor<'_>,
    ) -> Result<(), TurnkeyApiError> {
        let client = self.sdk_client(signer.0)?;
        let intent = DeleteOauthProvidersIntent {
            user_id: user_id.to_string(),
            provider_ids,
        };

        let requested = intent.provider_ids.len();
        let timestamp_ms = ntp_timestamp_ms()?;
        let deleted = self
            .with_retry("delete_oauth_providers", || async {
                client
                    .delete_oauth_providers(
                        suborganization_id.to_string(),
                        timestamp_ms,
                        intent.clone(),
                    )
                    .await
                    .map(|activity| activity.result.provider_ids.len())
                    .map_err(TurnkeyApiError::from)
            })
            .await?;

        // A completed activity that deleted nothing would otherwise be reported as
        // success, leaving the provider the caller asked to revoke still usable.
        // Mirrors the same check in `create_oauth_providers`.
        if deleted != requested {
            crate::critical!(
                "turnkey.delete_oauth_providers.count_mismatch requested={requested} deleted={deleted}"
            );
        }

        // User has changed, remove the cache.
        self.users_cache.clear();
        Ok(())
    }

    /// Deletes `WebAuthn` authenticators (passkeys) from a Turnkey user.
    ///
    /// A [`MainFactor`] is required for the same reason as
    /// [`Self::delete_oauth_providers`]: authenticators live on the root user.
    ///
    /// # Errors
    /// Returns [`TurnkeyApiError`] on transport, stamping, activity, or parsing failures.
    pub async fn delete_authenticators(
        &self,
        suborganization_id: &str,
        user_id: &str,
        authenticator_ids: Vec<String>,
        signer: MainFactor<'_>,
    ) -> Result<(), TurnkeyApiError> {
        let client = self.sdk_client(signer.0)?;
        let intent = DeleteAuthenticatorsIntent {
            user_id: user_id.to_string(),
            authenticator_ids,
        };

        let requested = intent.authenticator_ids.len();
        let timestamp_ms = ntp_timestamp_ms()?;
        let deleted = self
            .with_retry("delete_authenticators", || async {
                client
                    .delete_authenticators(
                        suborganization_id.to_string(),
                        timestamp_ms,
                        intent.clone(),
                    )
                    .await
                    .map(|activity| activity.result.authenticator_ids.len())
                    .map_err(TurnkeyApiError::from)
            })
            .await?;

        if deleted != requested {
            crate::critical!(
                "turnkey.delete_authenticators.count_mismatch requested={requested} deleted={deleted}"
            );
        }

        // User has changed, remove the cache.
        self.users_cache.clear();
        Ok(())
    }

    /// Deletes the entire Turnkey Account (sub-organization). One of the few
    /// state-mutating operations that the [`SyncFactor`] can execute.
    ///
    /// # Errors
    /// Returns [`TurnkeyApiError`] on transport, stamping, activity, or parsing failures.
    pub async fn delete_sub_organization(
        &self,
        suborganization_id: &str,
        signer: SyncFactor<'_>,
    ) -> Result<(), TurnkeyApiError> {
        let client = self.sdk_client(signer.0)?;
        let intent = DeleteSubOrganizationIntent {
            delete_without_export: Some(true),
        };

        let timestamp_ms = ntp_timestamp_ms()?;
        self.with_retry("delete_sub_organization", || async {
            client
                .delete_sub_organization(
                    suborganization_id.to_string(),
                    timestamp_ms,
                    intent,
                )
                .await
                .map(|_activity| ())
                .map_err(TurnkeyApiError::from)
        })
        .await?;

        self.users_cache.clear();
        self.policies_cache.clear();
        Ok(())
    }

    /// Lists the policies of a sub-organization.
    ///
    /// Results are cached for the lifetime of this client; the policy writes
    /// ([`Self::create_policy`], [`Self::update_policy`]) invalidate the cache.
    ///
    /// # Errors
    /// Returns [`TurnkeyApiError`] on transport, stamping, or parsing failures.
    pub async fn get_policies(
        &self,
        suborganization_id: &str,
        signer: SyncFactor<'_>,
    ) -> Result<Arc<Vec<Policy>>, TurnkeyApiError> {
        if let Some(cached) = self.policies_cache.get(suborganization_id)? {
            return Ok(cached);
        }
        let client = self.sdk_client(signer.0)?;
        let request = GetPoliciesRequest {
            organization_id: suborganization_id.to_string(),
        };

        let policies = self
            .with_retry("get_policies", || async {
                client
                    .get_policies(request.clone())
                    .await
                    .map(|response| response.policies)
                    .map_err(TurnkeyApiError::from)
            })
            .await?;

        Ok(self.policies_cache.store(suborganization_id, policies))
    }

    /// Creates a policy on the sub-organization (needs a [`MainFactor`] signer).
    ///
    /// # Errors
    /// Returns [`TurnkeyApiError`] on transport, stamping, activity, or parsing failures.
    pub async fn create_policy(
        &self,
        suborganization_id: &str,
        policy: CreatePolicyIntentV3,
        signer: MainFactor<'_>,
    ) -> Result<(), TurnkeyApiError> {
        let client = self.sdk_client(signer.0)?;
        let timestamp_ms = ntp_timestamp_ms()?;
        self.with_retry("create_policy", || async {
            client
                .create_policy(
                    suborganization_id.to_string(),
                    timestamp_ms,
                    policy.clone(),
                )
                .await
                .map(|_activity| ())
                .map_err(TurnkeyApiError::from)
        })
        .await?;

        // Policies have changed; drop the stale cache entry.
        self.policies_cache.clear();
        Ok(())
    }

    /// Updates an existing policy (needs a [`MainFactor`] signer).
    ///
    /// Only the fields set on `params` are changed; a `None` field is left as-is.
    ///
    /// # Errors
    /// Returns [`TurnkeyApiError`] on transport, stamping, activity, or parsing failures.
    pub async fn update_policy(
        &self,
        suborganization_id: &str,
        params: UpdatePolicyIntentV2,
        signer: MainFactor<'_>,
    ) -> Result<(), TurnkeyApiError> {
        let client = self.sdk_client(signer.0)?;
        let timestamp_ms = ntp_timestamp_ms()?;
        self.with_retry("update_policy", || async {
            client
                .update_policy(
                    suborganization_id.to_string(),
                    timestamp_ms,
                    params.clone(),
                )
                .await
                .map(|_activity| ())
                .map_err(TurnkeyApiError::from)
        })
        .await?;

        // Policies have changed; drop the stale cache entry.
        self.policies_cache.clear();
        Ok(())
    }

    /// Deletes a policy from the sub-organization (needs a [`MainFactor`] signer).
    ///
    /// # Errors
    /// Returns [`TurnkeyApiError`] on transport, stamping, activity, or parsing failures.
    pub async fn delete_policy(
        &self,
        suborganization_id: &str,
        policy_id: &str,
        signer: MainFactor<'_>,
    ) -> Result<(), TurnkeyApiError> {
        let client = self.sdk_client(signer.0)?;
        let intent = DeletePolicyIntent {
            policy_id: policy_id.to_string(),
        };
        let timestamp_ms = ntp_timestamp_ms()?;
        self.with_retry("delete_policy", || async {
            client
                .delete_policy(
                    suborganization_id.to_string(),
                    timestamp_ms,
                    intent.clone(),
                )
                .await
                .map(|_activity| ())
                .map_err(TurnkeyApiError::from)
        })
        .await?;

        // Policies have changed; drop the stale cache entry.
        self.policies_cache.clear();
        Ok(())
    }
}

/// Current NTP time in milliseconds, for Turnkey activity timestamps.
///
/// # Errors
/// Returns [`TurnkeyApiError`] if the time source yields a non-positive
/// timestamp (a broken clock). A zero/negative timestamp is useless to Turnkey,
/// so we fail fast rather than submit an activity that cannot succeed.
fn ntp_timestamp_ms() -> Result<u128, TurnkeyApiError> {
    let millis = now_with_ntp().timestamp_millis();
    let millis = u128::try_from(millis).map_err(|_| {
        TurnkeyApiError::Client(format!(
            "time source returned a pre-epoch timestamp ({millis} ms)"
        ))
    })?;
    if millis == 0 {
        return Err(TurnkeyApiError::Client(
            "time source returned a zero timestamp".to_string(),
        ));
    }
    Ok(millis)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backup::turnkey::test::TestSigner;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::Arc;

    #[test]
    fn stamp_verifies_against_body() {
        use base64::prelude::BASE64_URL_SAFE_NO_PAD;
        use p256::ecdsa::signature::Verifier;

        let body = serde_json::json!({ "activity": "create" }).to_string();
        let verified = P256Signer::verify(Arc::new(TestSigner::new())).unwrap();
        let adapter = KeypairSignerStamper::new(&verified);
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
        let body = || String::new();
        assert!(TurnkeyApiError::Timeout.is_retryable());
        assert!(TurnkeyApiError::RateLimited { body: body() }.is_retryable());
        assert!(TurnkeyApiError::ServerError {
            status: 503,
            body: body()
        }
        .is_retryable());
        assert!(TurnkeyApiError::Transport {
            error_message: "reset".to_string()
        }
        .is_retryable());

        // Already-submitted activity: a retry would restart polling, not observe
        // it. Non-retryable by design.
        assert!(!TurnkeyApiError::ActivityPollingExceeded {
            error_message: "still pending".to_string()
        }
        .is_retryable());
        assert!(!TurnkeyApiError::Unauthorized { body: body() }.is_retryable());
        assert!(!TurnkeyApiError::NotFound { body: body() }.is_retryable());
        assert!(!TurnkeyApiError::ClientError {
            status: 400,
            body: body()
        }
        .is_retryable());
        assert!(!TurnkeyApiError::Activity {
            error_message: "failed".to_string()
        }
        .is_retryable());
    }

    #[test]
    fn sdk_error_status_classification() {
        use turnkey_client::TurnkeyClientError;
        assert!(matches!(
            TurnkeyApiError::from(TurnkeyClientError::UnexpectedHttpStatus(
                429,
                String::new()
            )),
            TurnkeyApiError::RateLimited { .. }
        ));
        assert!(matches!(
            TurnkeyApiError::from(TurnkeyClientError::UnexpectedHttpStatus(
                500,
                String::new()
            )),
            TurnkeyApiError::ServerError { status: 500, .. }
        ));
        assert!(matches!(
            TurnkeyApiError::from(TurnkeyClientError::UnexpectedHttpStatus(
                409,
                String::new()
            )),
            TurnkeyApiError::ClientError { status: 409, .. }
        ));
        assert!(matches!(
            TurnkeyApiError::from(TurnkeyClientError::MissingResult),
            TurnkeyApiError::Activity { .. }
        ));
        assert!(matches!(
            TurnkeyApiError::from(TurnkeyClientError::ExceededRetries(3)),
            TurnkeyApiError::ActivityPollingExceeded { .. }
        ));
        // Response-header parse failures are transport-class (retryable), not the
        // permanent `Client` catch-all.
        let header_err =
            TurnkeyApiError::from(TurnkeyClientError::MissingContentTypeHeader);
        assert!(matches!(header_err, TurnkeyApiError::Transport { .. }));
        assert!(header_err.is_retryable());
    }

    #[test]
    fn http_error_preserves_response_body() {
        use turnkey_client::TurnkeyClientError;
        let error = TurnkeyApiError::from(TurnkeyClientError::UnexpectedHttpStatus(
            400,
            "invalid audience".to_string(),
        ));
        let TurnkeyApiError::ClientError { status, body } = &error else {
            panic!("expected ClientError, got {error:?}");
        };
        assert_eq!(*status, 400);
        assert_eq!(body, "invalid audience");
        // The body must reach the failure log, which formats via Display.
        assert!(error.to_string().contains("invalid audience"));
    }

    #[test]
    fn oversized_body_is_truncated_in_error() {
        use turnkey_client::TurnkeyClientError;
        let big = "a".repeat(4096);
        let error = TurnkeyApiError::from(TurnkeyClientError::UnexpectedHttpStatus(
            500,
            big.clone(),
        ));
        let TurnkeyApiError::ServerError { body, .. } = &error else {
            panic!("expected ServerError, got {error:?}");
        };
        assert!(body.len() < big.len());
        assert!(body.contains("truncated"));
    }

    /// Ensures there can be a recovery through retries after transient failures.
    ///
    /// Using `start_paused` so backoff sleeps are skipped.
    #[tokio::test(start_paused = true)]
    async fn with_retry_recovers_after_transient_failures() {
        let client = TurnkeyApiClient::new();
        let calls = AtomicU32::new(0);
        let result: Result<u32, TurnkeyApiError> = client
            .with_retry("op", || {
                let attempt = calls.fetch_add(1, Ordering::SeqCst);
                async move {
                    if attempt < 2 {
                        Err(TurnkeyApiError::Timeout)
                    } else {
                        Ok(42)
                    }
                }
            })
            .await;

        assert_eq!(result.unwrap(), 42);
        assert_eq!(calls.load(Ordering::SeqCst), 3);
    }

    #[tokio::test(start_paused = true)]
    async fn with_retry_gives_up_after_max_attempts() {
        let client = TurnkeyApiClient::new();
        let calls = AtomicU32::new(0);
        let result: Result<(), TurnkeyApiError> = client
            .with_retry("op", || {
                calls.fetch_add(1, Ordering::SeqCst);
                async {
                    Err(TurnkeyApiError::ServerError {
                        status: 503,
                        body: String::new(),
                    })
                }
            })
            .await;

        assert!(matches!(result, Err(TurnkeyApiError::ServerError { .. })));
        assert_eq!(
            calls.load(Ordering::SeqCst),
            RetryPolicy::default().max_attempts
        );
    }

    #[tokio::test(start_paused = true)]
    async fn with_retry_does_not_retry_non_retryable() {
        let client = TurnkeyApiClient::new();
        let calls = AtomicU32::new(0);
        let result: Result<(), TurnkeyApiError> = client
            .with_retry("op", || {
                calls.fetch_add(1, Ordering::SeqCst);
                async { Err(TurnkeyApiError::MainUserNotFound) }
            })
            .await;

        assert!(matches!(result, Err(TurnkeyApiError::MainUserNotFound)));
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }
}
