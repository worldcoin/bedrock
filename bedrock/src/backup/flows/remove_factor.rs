//! BF-7 (remove a main factor: an OIDC account or a passkey), escalating to BF-8
//! (delete the whole backup) when the removed factor is the last main factor.

use async_trait::async_trait;

use super::{BackupFlow, FlowContext};
use crate::backup::backup_service::{
    BackupEncryptionKey, BackupFactorKind, BackupMetadata, DeleteFactorResponse,
};
use crate::backup::turnkey::{TurnkeyApiClient, TurnkeyApiError};
use crate::backup::{BackupOperationError, MainFactor, NeedsReauthReason, SyncFactor};
use crate::primitives::P256Signer;

/// Outcome of a successful factor removal.
#[derive(Debug, uniffi::Enum)]
pub enum RemoveFactorOutcome {
    /// The factor was removed and the backup survives; carries the refreshed
    /// metadata.
    FactorRemoved {
        /// Backup metadata after the removal (helps update the UI)
        metadata: BackupMetadata,
    },
    /// The removed factor was the last [`MainFactor`], so the entire backup was
    /// deleted (the user had confirmed).
    BackupDeleted,
}

/// Removes the [`MainFactor`] `factor_id`, driving the backup service and, for OIDC
/// factors, Turnkey.
pub struct RemoveFactor {
    /// The id of the factor to remove.
    pub factor_id: String,
    /// Set only after the user confirmed that removing the last [`MainFactor`] deletes
    /// the entire backup.
    pub user_confirmed_backup_removal: bool,
}

#[async_trait]
impl BackupFlow for RemoveFactor {
    type Output = RemoveFactorOutcome;

    async fn run(
        &self,
        ctx: &FlowContext<'_>,
    ) -> Result<RemoveFactorOutcome, BackupOperationError> {
        let metadata = ctx.service.retrieve_metadata(ctx.sync_factor).await?;
        let factor = metadata.factor(&self.factor_id).ok_or_else(|| {
            crate::warn!("remove_factor.factor_not_found");
            BackupOperationError::BackupService {
                code: "factor_not_found".to_string(),
            }
        })?;

        if metadata.main_factor_count() == 1 && !self.user_confirmed_backup_removal {
            crate::debug!("remove_factor.would_delete_backup");
            return Err(BackupOperationError::WouldDeleteBackup);
        }

        match &factor.kind {
            BackupFactorKind::OidcAccount { .. } => {
                self.remove_oidc(ctx, &metadata).await
            }
            BackupFactorKind::Passkey { .. } => {
                self.remove_passkey(ctx, &metadata).await
            }
            BackupFactorKind::EcKeypair { .. } => {
                crate::error!("remove_factor.keychain_removal_unsupported");
                Err(BackupOperationError::Unsupported {
                    detail: "iCloud Keychain factor removal is not yet supported"
                        .to_string(),
                })
            }
        }
    }
}

impl RemoveFactor {
    /// Removes an OIDC factor. Deleting one of several providers needs a
    /// [`MainFactor`]; removing the last OIDC factor tears down the whole sub-org
    /// (sync-signed) and drops the Turnkey encryption key.
    async fn remove_oidc(
        &self,
        ctx: &FlowContext<'_>,
        metadata: &BackupMetadata,
    ) -> Result<RemoveFactorOutcome, BackupOperationError> {
        let plan = plan_oidc_removal(metadata, &self.factor_id)?;

        // The provider path needs a main factor and the full set of providers backing
        // the identity; resolve both before the irreversible delete-factor commit so a
        // re-auth or a transient Turnkey read fails while a retry is still safe.
        let provider_ids = if plan.is_last_oidc_factor {
            None
        } else if ctx.main_factor.is_some() {
            Some(provider_ids_for_identity(ctx, &plan).await?)
        } else {
            // Deleting an OAuth provider requires a [`MainFactor`]
            crate::debug!("remove_factor.needs_main_factor");
            return Err(BackupOperationError::NeedsReauth {
                reason: NeedsReauthReason::MainFactorRequired,
            });
        };

        // backup-service is authoritative, drop first
        let encryption_key = plan.is_last_oidc_factor.then(|| plan.turnkey_key.clone());
        let response = ctx
            .service
            .delete_factor(ctx.sync_factor, &self.factor_id, encryption_key)
            .await?;

        // Turnkey teardown is best-effort: the factor is already removed, and a
        // failure here leaves an orphaned Turnkey resource for a later migration, not
        // a blocked user (BF-8).
        if plan.is_last_oidc_factor {
            best_effort_delete_sub_org(ctx.turnkey, &plan.suborg_id, ctx.sync_factor)
                .await;
        } else if let (Some(main_factor), Some(provider_ids)) =
            (ctx.main_factor, provider_ids)
        {
            best_effort_delete_providers(ctx, &plan, &provider_ids, main_factor).await;
        }

        finalize(response)
    }

    /// Removes a passkey factor by dropping its PRF encryption key at the backup
    /// service. No Turnkey and no main factor are involved.
    ///
    /// The exported metadata does not link a passkey to its PRF key, so with more
    /// than one passkey Bedrock cannot tell which key to drop and refuses rather than
    /// orphan the wrong one.
    async fn remove_passkey(
        &self,
        ctx: &FlowContext<'_>,
        metadata: &BackupMetadata,
    ) -> Result<RemoveFactorOutcome, BackupOperationError> {
        if metadata.passkey_factor_count() > 1 {
            crate::error!("remove_factor.multiple_passkeys_unsupported");
            return Err(BackupOperationError::Unsupported {
                detail:
                    "removing a passkey is unsupported while several passkeys exist"
                        .to_string(),
            });
        }

        let prf_key = metadata.single_prf_key().cloned().ok_or_else(|| {
            crate::error!("remove_factor.missing_prf_key");
            BackupOperationError::Unsupported {
                detail: "the passkey has no PRF encryption key to drop".to_string(),
            }
        })?;

        let response = ctx
            .service
            .delete_factor(ctx.sync_factor, &self.factor_id, Some(prf_key))
            .await?;

        finalize(response)
    }
}

/// Maps a successful delete-factor response to the flow outcome.
fn finalize(
    response: DeleteFactorResponse,
) -> Result<RemoveFactorOutcome, BackupOperationError> {
    if response.backup_deleted {
        crate::info!("remove_factor.backup_deleted");
        return Ok(RemoveFactorOutcome::BackupDeleted);
    }
    let metadata = response.backup_metadata.ok_or_else(|| {
        crate::error!("remove_factor.missing_response_metadata");
        BackupOperationError::Generic {
            error_message: "backup service returned no metadata".to_string(),
        }
    })?;
    crate::info!("remove_factor.factor_removed");
    Ok(RemoveFactorOutcome::FactorRemoved { metadata })
}

/// The Turnkey references and last-OIDC flag derived from the backup metadata.
struct OidcRemovalPlan {
    provider_id: String,
    suborg_id: String,
    user_id: String,
    turnkey_key: BackupEncryptionKey,
    is_last_oidc_factor: bool,
}

/// Derives the Turnkey references and the last-OIDC flag for the OIDC `factor_id`.
fn plan_oidc_removal(
    metadata: &BackupMetadata,
    factor_id: &str,
) -> Result<OidcRemovalPlan, BackupOperationError> {
    let provider_id = metadata
        .factor(factor_id)
        .and_then(|factor| factor.turnkey_provider_id())
        .ok_or_else(|| {
            crate::error!("remove_factor.factor_not_oidc");
            BackupOperationError::BackupService {
                code: "factor_not_oidc".to_string(),
            }
        })?
        .to_string();

    let turnkey_key = metadata.turnkey_key().cloned().ok_or_else(|| {
        crate::error!("remove_factor.missing_turnkey_key");
        BackupOperationError::BackupService {
            code: "missing_turnkey_key".to_string(),
        }
    })?;
    let BackupEncryptionKey::Turnkey {
        turnkey_account_id,
        turnkey_user_id,
        ..
    } = &turnkey_key
    else {
        crate::error!("remove_factor.turnkey_key_wrong_kind");
        return Err(BackupOperationError::BackupService {
            code: "missing_turnkey_key".to_string(),
        });
    };

    Ok(OidcRemovalPlan {
        provider_id,
        suborg_id: turnkey_account_id.clone(),
        user_id: turnkey_user_id.clone(),
        is_last_oidc_factor: metadata.oidc_factor_count() == 1,
        turnkey_key,
    })
}

/// Maps a Turnkey read failure. An invalid signer becomes a re-auth signal;
/// transient failures are retryable; anything else is a coarse Turnkey error.
fn map_turnkey_error(error: &TurnkeyApiError) -> BackupOperationError {
    if error.indicates_invalid_signer() {
        crate::warn!("remove_factor.sync_factor_invalid");
        BackupOperationError::NeedsReauth {
            reason: NeedsReauthReason::SyncFactorInvalid,
        }
    } else if error.is_retryable() {
        BackupOperationError::Network { retryable: true }
    } else {
        BackupOperationError::Turnkey {
            code: error.code().to_string(),
        }
    }
}

/// Tears down the Turnkey sub-organization; failures are logged (no hard failure)
async fn best_effort_delete_sub_org(
    turnkey: &TurnkeyApiClient,
    suborg_id: &str,
    sync_factor: &P256Signer,
) {
    if let Err(error) = turnkey
        .delete_sub_organization(suborg_id, SyncFactor(sync_factor))
        .await
    {
        crate::error!(
            "remove_factor.turnkey_suborg_cleanup_failed (best effort) code={} err={error}",
            error.code()
        );
    }
}

/// Deletes every Turnkey provider backing the removed OIDC identity, **one at a
/// time** so an already-absent audience doesn't block the rest.
///
/// A single OIDC identity can back several providers: Apple registers one per
/// audience (per client app), all sharing one `sub`. Best-effort: each failure is
/// logged, never fatal (the backup-service removal is already authoritative).
async fn best_effort_delete_providers(
    ctx: &FlowContext<'_>,
    plan: &OidcRemovalPlan,
    provider_ids: &[String],
    main_factor: &P256Signer,
) {
    for provider_id in provider_ids {
        match ctx
            .turnkey
            .delete_oauth_providers(
                &plan.suborg_id,
                &plan.user_id,
                vec![provider_id.clone()],
                MainFactor(main_factor),
            )
            .await
        {
            Ok(()) => {}
            Err(error) if error.is_no_matching_provider() => {
                crate::debug!(
                    "remove_factor.turnkey_provider_already_absent provider={provider_id}"
                );
            }
            Err(error) => {
                crate::error!(
                    "remove_factor.turnkey_provider_cleanup_failed (best effort) provider={provider_id} code={} err={error}",
                    error.code()
                );
            }
        }
    }
}

/// Resolves every Turnkey provider id sharing the target provider's OIDC identity
/// (`issuer` + `subject`): all of an Apple `sub`'s per-audience providers, for example.
///
/// Fails on a read error rather than falling back to the single provider, so a
/// transient error can't leave the sibling providers orphaned. Returns an empty set
/// if the identity is already absent from Turnkey (nothing to delete).
async fn provider_ids_for_identity(
    ctx: &FlowContext<'_>,
    plan: &OidcRemovalPlan,
) -> Result<Vec<String>, BackupOperationError> {
    let users = ctx
        .turnkey
        .get_users(&plan.suborg_id, SyncFactor(ctx.sync_factor))
        .await
        .map_err(|error| map_turnkey_error(&error))?;

    let ids = users
        .iter()
        .find(|user| user.user_id == plan.user_id)
        .and_then(|user| {
            let target = user
                .oauth_providers
                .iter()
                .find(|provider| provider.provider_id == plan.provider_id)?;
            Some(
                user.oauth_providers
                    .iter()
                    .filter(|provider| {
                        provider.issuer == target.issuer
                            && provider.subject == target.subject
                    })
                    .map(|provider| provider.provider_id.clone())
                    .collect::<Vec<_>>(),
            )
        })
        .unwrap_or_default();

    Ok(ids)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backup::backup_service::BackupServiceClient;
    use crate::backup::turnkey::test::TestSigner;
    use crate::primitives::set_attestation_token_provider;
    use crate::primitives::AttestationTokenProvider;
    use crate::HttpError;
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;
    use serde_json::{json, Value};
    use std::sync::Arc;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    const RETRIEVE_META_CHALLENGE: &str = "/v1/retrieve-metadata/challenge/keypair";
    const RETRIEVE_META: &str = "/v1/retrieve-metadata";
    const DELETE_FACTOR_CHALLENGE: &str = "/v1/delete-factor/challenge/keypair";
    const DELETE_FACTOR: &str = "/v1/delete-factor";
    const LIST_USERS: &str = "/public/v1/query/list_users";
    const DELETE_SUB_ORG: &str = "/public/v1/submit/delete_sub_organization";
    const DELETE_OAUTH: &str = "/public/v1/submit/delete_oauth_providers";

    struct FakeAttestation;

    #[async_trait]
    impl AttestationTokenProvider for FakeAttestation {
        async fn attestation_token(
            &self,
            _request_hash: String,
        ) -> Result<String, HttpError> {
            Ok("fake-attestation-token".to_string())
        }
    }

    /// Installs the fake attestation provider. The global is idempotent and the fake
    /// is stateless, so concurrent tests share it safely.
    fn install_attestation() {
        set_attestation_token_provider(Arc::new(FakeAttestation));
    }

    fn signer() -> P256Signer {
        P256Signer::verify(Arc::new(TestSigner::new())).expect("valid test signer")
    }

    fn challenge_response() -> Value {
        json!({ "challenge": STANDARD.encode([7u8; 32]), "token": "challenge-token" })
    }

    fn turnkey_key() -> Value {
        json!({
            "kind": "TURNKEY",
            "encryptedKey": "ek",
            "turnkeyAccountId": "suborg-1",
            "turnkeyUserId": "user-1",
            "turnkeyPrivateKeyId": "pk-1",
        })
    }

    fn prf_key(encrypted_key: &str) -> Value {
        json!({ "kind": "PRF", "encryptedKey": encrypted_key })
    }

    fn oidc_factor(id: &str, provider_id: &str) -> Value {
        json!({
            "id": id,
            "createdAt": 1,
            "kind": {
                "kind": "OIDC_ACCOUNT",
                "account": { "kind": "GOOGLE", "maskedEmail": "j***@g.com" },
                "turnkeyProviderId": provider_id,
            },
        })
    }

    fn passkey_factor(id: &str) -> Value {
        json!({
            "id": id,
            "createdAt": 1,
            "kind": { "kind": "PASSKEY", "credentialId": format!("cred-{id}"), "label": "L" },
        })
    }

    fn eckeypair_factor(id: &str) -> Value {
        json!({
            "id": id,
            "createdAt": 1,
            "kind": { "kind": "EC_KEYPAIR", "publicKey": "pub" },
        })
    }

    fn metadata_keyed(keys: Vec<Value>, factors: Vec<Value>) -> Value {
        let mut meta = json!({
            "id": "backup-1",
            "manifestHash": "abcd",
            "syncFactors": [],
        });
        meta["keys"] = Value::Array(keys);
        meta["factors"] = Value::Array(factors);
        meta
    }

    fn metadata(factors: Vec<Value>) -> Value {
        metadata_keyed(vec![turnkey_key()], factors)
    }

    fn completed_activity(
        activity_type: &str,
        result_key: &str,
        result: Value,
    ) -> Value {
        let mut activity = json!({
            "activity": {
                "id": "act-1",
                "organizationId": "suborg-1",
                "status": "ACTIVITY_STATUS_COMPLETED",
                "type": activity_type,
                "fingerprint": "fp-1",
                "result": {},
            }
        });
        activity["activity"]["result"][result_key] = result;
        activity
    }

    /// A Turnkey OAuth provider entry as returned by `list_users`.
    fn oauth_provider(provider_id: &str, issuer: &str, subject: &str) -> Value {
        json!({
            "providerId": provider_id,
            "providerName": "n",
            "issuer": issuer,
            "audience": format!("aud-{provider_id}"),
            "subject": subject,
        })
    }

    /// `auth_user_main` (id `user-1`, matching `turnkey_key`) carrying `providers`.
    fn main_user(providers: Vec<Value>) -> Value {
        let mut user = json!({ "userId": "user-1", "userName": "auth_user_main" });
        user["oauthProviders"] = Value::Array(providers);
        user
    }

    /// All `providerIds` across every captured `delete_oauth_providers` request.
    async fn deleted_provider_ids(server: &MockServer) -> Vec<String> {
        server
            .received_requests()
            .await
            .unwrap()
            .iter()
            .filter(|request| request.url.path() == DELETE_OAUTH)
            .flat_map(|request| {
                let value: Value = serde_json::from_slice(&request.body).unwrap();
                value["parameters"]["providerIds"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|id| id.as_str().unwrap().to_string())
                    .collect::<Vec<_>>()
            })
            .collect()
    }

    async fn mount(server: &MockServer, endpoint: &str, body: Value) {
        Mock::given(method("POST"))
            .and(path(endpoint))
            .respond_with(ResponseTemplate::new(200).set_body_json(body))
            .mount(server)
            .await;
    }

    async fn mount_metadata(server: &MockServer, meta: Value) {
        mount(server, RETRIEVE_META_CHALLENGE, challenge_response()).await;
        mount(server, RETRIEVE_META, meta).await;
    }

    async fn mount_delete_factor(server: &MockServer, response: Value) {
        mount(server, DELETE_FACTOR_CHALLENGE, challenge_response()).await;
        mount(server, DELETE_FACTOR, response).await;
    }

    async fn mount_users(server: &MockServer, providers: Vec<Value>) {
        mount(
            server,
            LIST_USERS,
            json!({ "users": [main_user(providers)] }),
        )
        .await;
    }

    async fn mount_delete_oauth(server: &MockServer) {
        mount(
            server,
            DELETE_OAUTH,
            completed_activity(
                "ACTIVITY_TYPE_DELETE_OAUTH_PROVIDERS",
                "deleteOauthProvidersResult",
                json!({ "providerIds": [] }),
            ),
        )
        .await;
    }

    async fn mount_delete_sub_org(server: &MockServer) {
        mount(
            server,
            DELETE_SUB_ORG,
            completed_activity(
                "ACTIVITY_TYPE_DELETE_SUB_ORGANIZATION",
                "deleteSubOrganizationResult",
                json!({ "subOrganizationUuid": "suborg-1" }),
            ),
        )
        .await;
    }

    async fn called_paths(server: &MockServer) -> Vec<String> {
        server
            .received_requests()
            .await
            .unwrap()
            .iter()
            .map(|request| request.url.path().to_string())
            .collect()
    }

    fn clients(server: &MockServer) -> (BackupServiceClient, TurnkeyApiClient) {
        (
            BackupServiceClient::with_base_url_for_test(server.uri()).unwrap(),
            TurnkeyApiClient::with_base_url(server.uri()),
        )
    }

    /// Runs `RemoveFactor` against mock clients.
    async fn run_remove(
        server: &MockServer,
        factor_id: &str,
        main_factor: Option<&P256Signer>,
        confirmed: bool,
    ) -> Result<RemoveFactorOutcome, BackupOperationError> {
        let (service, turnkey) = clients(server);
        let sync = signer();
        let ctx = FlowContext {
            service: &service,
            turnkey: &turnkey,
            sync_factor: &sync,
            main_factor,
        };
        RemoveFactor {
            factor_id: factor_id.to_string(),
            user_confirmed_backup_removal: confirmed,
        }
        .run(&ctx)
        .await
    }

    /// The body of the single captured delete-factor request.
    async fn delete_factor_body(server: &MockServer) -> String {
        let requests = server.received_requests().await.unwrap();
        let request = requests
            .iter()
            .find(|request| request.url.path() == DELETE_FACTOR)
            .expect("delete-factor was called");
        String::from_utf8_lossy(&request.body).into_owned()
    }

    /// Provider path with no main factor: re-auth is required before any mutation.
    #[tokio::test]
    async fn provider_removal_needs_main_factor() {
        install_attestation();
        let server = MockServer::start().await;
        mount_metadata(
            &server,
            metadata(vec![oidc_factor("f-1", "p-1"), oidc_factor("f-2", "p-2")]),
        )
        .await;

        let error = run_remove(&server, "f-1", None, false).await.unwrap_err();

        assert!(matches!(
            error,
            BackupOperationError::NeedsReauth {
                reason: NeedsReauthReason::MainFactorRequired
            }
        ));
        assert!(!called_paths(&server)
            .await
            .contains(&DELETE_FACTOR.to_string()));
    }

    /// Provider path with a main factor: deletes only that identity's provider, no
    /// sub-org teardown and no encryption-key removal.
    #[tokio::test]
    async fn provider_removal_deletes_only_the_provider() {
        install_attestation();
        let server = MockServer::start().await;
        mount_metadata(
            &server,
            metadata(vec![oidc_factor("f-1", "p-1"), oidc_factor("f-2", "p-2")]),
        )
        .await;
        mount_users(
            &server,
            vec![oauth_provider(
                "p-1",
                "https://accounts.google.com",
                "sub-1",
            )],
        )
        .await;
        mount_delete_factor(
            &server,
            json!({ "backupDeleted": false, "backupMetadata": metadata(vec![oidc_factor("f-2", "p-2")]) }),
        )
        .await;
        mount_delete_oauth(&server).await;
        let main = signer();

        let outcome = run_remove(&server, "f-1", Some(&main), false)
            .await
            .unwrap();

        assert!(matches!(outcome, RemoveFactorOutcome::FactorRemoved { .. }));
        assert!(
            !delete_factor_body(&server).await.contains("encryptionKey"),
            "provider path must not drop the key"
        );
        assert_eq!(deleted_provider_ids(&server).await, vec!["p-1".to_string()]);
        assert!(!called_paths(&server)
            .await
            .contains(&DELETE_SUB_ORG.to_string()));
    }

    /// A single OIDC identity backed by several Turnkey providers (Apple's
    /// per-audience providers, one `sub`) must have *every* audience deleted, and
    /// only that identity's providers.
    #[tokio::test]
    async fn provider_removal_deletes_all_audiences_of_the_identity() {
        install_attestation();
        let server = MockServer::start().await;
        mount_metadata(
            &server,
            metadata(vec![
                oidc_factor("f-apple", "p-apple-ios"),
                oidc_factor("f-google", "p-google"),
            ]),
        )
        .await;
        let apple = "https://appleid.apple.com";
        mount_users(
            &server,
            vec![
                oauth_provider("p-apple-ios", apple, "sub-apple"),
                oauth_provider("p-apple-wid", apple, "sub-apple"),
                oauth_provider("p-apple-web", apple, "sub-apple"),
                oauth_provider("p-google", "https://accounts.google.com", "sub-google"),
            ],
        )
        .await;
        mount_delete_factor(
            &server,
            json!({ "backupDeleted": false, "backupMetadata": metadata(vec![oidc_factor("f-google", "p-google")]) }),
        )
        .await;
        mount_delete_oauth(&server).await;
        let main = signer();

        let outcome = run_remove(&server, "f-apple", Some(&main), false)
            .await
            .unwrap();

        assert!(matches!(outcome, RemoveFactorOutcome::FactorRemoved { .. }));
        let mut ids = deleted_provider_ids(&server).await;
        ids.sort();
        assert_eq!(
            ids,
            vec![
                "p-apple-ios".to_string(),
                "p-apple-web".to_string(),
                "p-apple-wid".to_string(),
            ]
        );
    }

    /// Last OIDC factor: tears down the sub-organization and drops the encryption key.
    #[tokio::test]
    async fn last_oidc_removal_tears_down_sub_org() {
        install_attestation();
        let server = MockServer::start().await;
        mount_metadata(
            &server,
            metadata(vec![oidc_factor("f-1", "p-1"), passkey_factor("pk-1")]),
        )
        .await;
        mount_delete_factor(
            &server,
            json!({ "backupDeleted": false, "backupMetadata": metadata(vec![passkey_factor("pk-1")]) }),
        )
        .await;
        mount_delete_sub_org(&server).await;

        let outcome = run_remove(&server, "f-1", None, false).await.unwrap();

        assert!(matches!(outcome, RemoveFactorOutcome::FactorRemoved { .. }));
        assert!(delete_factor_body(&server)
            .await
            .contains("turnkeyAccountId"));
        let paths = called_paths(&server).await;
        assert!(paths.contains(&DELETE_SUB_ORG.to_string()));
        assert!(!paths.contains(&DELETE_OAUTH.to_string()));
    }

    /// Provider path: a transient Turnkey read failure aborts before the commit, so
    /// the sibling providers can't be orphaned by deleting only the id we were handed.
    #[tokio::test]
    async fn provider_removal_aborts_when_identity_lookup_fails() {
        install_attestation();
        let server = MockServer::start().await;
        mount_metadata(
            &server,
            metadata(vec![oidc_factor("f-1", "p-1"), oidc_factor("f-2", "p-2")]),
        )
        .await;
        Mock::given(method("POST"))
            .and(path(LIST_USERS))
            .respond_with(ResponseTemplate::new(503))
            .mount(&server)
            .await;
        let main = signer();

        let error = run_remove(&server, "f-1", Some(&main), false)
            .await
            .unwrap_err();

        assert!(matches!(
            error,
            BackupOperationError::Network { retryable: true }
        ));
        assert!(!called_paths(&server)
            .await
            .contains(&DELETE_FACTOR.to_string()));
    }

    /// Passkey removal (not the last main factor): drops the passkey's PRF key and
    /// touches no Turnkey endpoint.
    #[tokio::test]
    async fn passkey_removal_drops_prf_key() {
        install_attestation();
        let server = MockServer::start().await;
        mount_metadata(
            &server,
            metadata_keyed(
                vec![prf_key("prf-ek"), turnkey_key()],
                vec![passkey_factor("pk-1"), oidc_factor("f-2", "p-2")],
            ),
        )
        .await;
        mount_delete_factor(
            &server,
            json!({ "backupDeleted": false, "backupMetadata": metadata(vec![oidc_factor("f-2", "p-2")]) }),
        )
        .await;

        let outcome = run_remove(&server, "pk-1", None, false).await.unwrap();

        assert!(matches!(outcome, RemoveFactorOutcome::FactorRemoved { .. }));
        let body = delete_factor_body(&server).await;
        assert!(body.contains("\"PRF\"") && body.contains("prf-ek"));
        let paths = called_paths(&server).await;
        assert!(!paths.contains(&LIST_USERS.to_string()));
        assert!(!paths.contains(&DELETE_OAUTH.to_string()));
        assert!(!paths.contains(&DELETE_SUB_ORG.to_string()));
    }

    /// Last passkey, confirmed: the service deletes the whole backup, no Turnkey.
    #[tokio::test]
    async fn last_passkey_confirmed_deletes_backup() {
        install_attestation();
        let server = MockServer::start().await;
        mount_metadata(
            &server,
            metadata_keyed(vec![prf_key("prf-ek")], vec![passkey_factor("pk-1")]),
        )
        .await;
        mount_delete_factor(
            &server,
            json!({ "backupDeleted": true, "backupMetadata": null }),
        )
        .await;

        let outcome = run_remove(&server, "pk-1", None, true).await.unwrap();

        assert!(matches!(outcome, RemoveFactorOutcome::BackupDeleted));
        assert!(delete_factor_body(&server).await.contains("prf-ek"));
        let paths = called_paths(&server).await;
        assert!(!paths.contains(&LIST_USERS.to_string()));
        assert!(!paths.contains(&DELETE_OAUTH.to_string()));
        assert!(!paths.contains(&DELETE_SUB_ORG.to_string()));
    }

    /// More than one passkey: Bedrock can't tell which PRF key backs the target, so
    /// it aborts before any mutation.
    #[tokio::test]
    async fn multiple_passkeys_removal_unsupported() {
        install_attestation();
        let server = MockServer::start().await;
        mount_metadata(
            &server,
            metadata_keyed(
                vec![prf_key("prf-a"), prf_key("prf-b")],
                vec![passkey_factor("pk-1"), passkey_factor("pk-2")],
            ),
        )
        .await;

        let error = run_remove(&server, "pk-1", None, false).await.unwrap_err();

        assert!(matches!(error, BackupOperationError::Unsupported { .. }));
        assert!(!called_paths(&server)
            .await
            .contains(&DELETE_FACTOR.to_string()));
    }

    /// iCloud Keychain factors (EC keypair main factors) aren't supported yet: abort
    /// before any mutation.
    #[tokio::test]
    async fn keychain_factor_removal_unsupported() {
        install_attestation();
        let server = MockServer::start().await;
        mount_metadata(
            &server,
            metadata(vec![eckeypair_factor("ec-1"), oidc_factor("f-2", "p-2")]),
        )
        .await;

        let error = run_remove(&server, "ec-1", None, false).await.unwrap_err();

        assert!(matches!(error, BackupOperationError::Unsupported { .. }));
        assert!(!called_paths(&server)
            .await
            .contains(&DELETE_FACTOR.to_string()));
    }

    /// Last main factor, unconfirmed: gated before any mutation.
    #[tokio::test]
    async fn last_main_factor_requires_confirmation() {
        install_attestation();
        let server = MockServer::start().await;
        mount_metadata(&server, metadata(vec![oidc_factor("f-1", "p-1")])).await;

        let error = run_remove(&server, "f-1", None, false).await.unwrap_err();

        assert!(matches!(error, BackupOperationError::WouldDeleteBackup));
        assert!(!called_paths(&server)
            .await
            .contains(&DELETE_FACTOR.to_string()));
    }

    /// Last main factor, confirmed: the service deletes the backup and the sub-org is
    /// torn down.
    #[tokio::test]
    async fn last_main_factor_confirmed_deletes_backup() {
        install_attestation();
        let server = MockServer::start().await;
        mount_metadata(&server, metadata(vec![oidc_factor("f-1", "p-1")])).await;
        mount_delete_factor(
            &server,
            json!({ "backupDeleted": true, "backupMetadata": null }),
        )
        .await;
        mount_delete_sub_org(&server).await;

        let outcome = run_remove(&server, "f-1", None, true).await.unwrap();

        assert!(matches!(outcome, RemoveFactorOutcome::BackupDeleted));
        assert!(called_paths(&server)
            .await
            .contains(&DELETE_SUB_ORG.to_string()));
    }

    /// A Turnkey provider already gone is an idempotent success: the factor is still
    /// reported removed.
    #[tokio::test]
    async fn provider_cleanup_tolerates_already_absent() {
        install_attestation();
        let server = MockServer::start().await;
        mount_metadata(
            &server,
            metadata(vec![oidc_factor("f-1", "p-1"), oidc_factor("f-2", "p-2")]),
        )
        .await;
        mount_users(
            &server,
            vec![oauth_provider(
                "p-1",
                "https://accounts.google.com",
                "sub-1",
            )],
        )
        .await;
        mount_delete_factor(
            &server,
            json!({ "backupDeleted": false, "backupMetadata": metadata(vec![oidc_factor("f-2", "p-2")]) }),
        )
        .await;
        Mock::given(method("POST"))
            .and(path(DELETE_OAUTH))
            .respond_with(
                ResponseTemplate::new(400).set_body_string(
                    "provider (No matching providers found) not found",
                ),
            )
            .mount(&server)
            .await;
        let main = signer();

        let outcome = run_remove(&server, "f-1", Some(&main), false)
            .await
            .unwrap();

        assert!(matches!(outcome, RemoveFactorOutcome::FactorRemoved { .. }));
    }

    /// An unknown factor id is rejected before any mutation.
    #[tokio::test]
    async fn unknown_factor_is_rejected() {
        install_attestation();
        let server = MockServer::start().await;
        mount_metadata(
            &server,
            metadata(vec![oidc_factor("f-1", "p-1"), oidc_factor("f-2", "p-2")]),
        )
        .await;

        let error = run_remove(&server, "missing", None, false)
            .await
            .unwrap_err();

        assert!(matches!(
            error,
            BackupOperationError::BackupService { code } if code == "factor_not_found"
        ));
    }
}
