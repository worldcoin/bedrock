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
    ///
    /// # Native responsibilities
    /// Bedrock clears the state it owns (the local manifest and the backup event
    /// report). The sync factor lives in native secure storage and the backup it
    /// authenticated is gone, so on receiving this the caller MUST:
    /// 1. Delete its stored sync-factor keypair (iOS `keyManagementService`, Android
    ///    `LocalSyncFactorStore`). Keeping it strands a credential every subsequent
    ///    backup call would fail against.
    /// 2. Update whatever "backup enabled" state it shows the user.
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

        // Before the confirmation gate: never ask a user to approve destroying their
        // backup for a removal that was never supported.
        if let Some(detail) = unsupported_reason(&metadata, &factor.kind) {
            return Err(BackupOperationError::Unsupported { detail });
        }

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
            // Rejected by `unsupported_reason` before the confirmation gate.
            BackupFactorKind::EcKeypair { .. } => {
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

        // Probe Turnkey first: teardown failures knowable in advance are worth an
        // error here rather than an orphaned resource after the commit. A transient
        // failure is fatal only on the provider path, which needs the read's data
        // (deleting just the id we were handed would orphan sibling audiences); the
        // last-OIDC path needs only its verdict.
        let provider_ids = if plan.is_last_oidc_factor {
            verify_sync_factor(ctx, &plan).await?;
            None
        } else if let Some(main_factor) = ctx.main_factor {
            verify_main_factor(ctx, &plan, main_factor).await?;
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

        // Best-effort: the factor is already gone from the authoritative store, so
        // failing here would block a user whose removal succeeded. Orphans are logged
        // `critical!` because nothing reclaims them yet (TODO in `turnkey::migrations`).
        if plan.is_last_oidc_factor {
            best_effort_delete_sub_org(ctx.turnkey, &plan.suborg_id, ctx.sync_factor)
                .await;
        } else if let (Some(main_factor), Some(provider_ids)) =
            (ctx.main_factor, provider_ids)
        {
            best_effort_delete_providers(ctx, &plan, &provider_ids, main_factor).await;
        }

        finalize(response, self.user_confirmed_backup_removal)
    }

    /// Removes a passkey factor by dropping its PRF encryption key at the backup
    /// service. No Turnkey and no main factor are involved.
    ///
    /// Preconditions are enforced by [`unsupported_reason`] before the confirmation
    /// gate; the `ok_or_else` below is defensive, not the user-facing check.
    async fn remove_passkey(
        &self,
        ctx: &FlowContext<'_>,
        metadata: &BackupMetadata,
    ) -> Result<RemoveFactorOutcome, BackupOperationError> {
        let prf_key = metadata.single_prf_key().cloned().ok_or_else(|| {
            crate::warn!("remove_factor.missing_prf_key");
            BackupOperationError::Unsupported {
                detail: "the passkey has no PRF encryption key to drop".to_string(),
            }
        })?;

        let response = ctx
            .service
            .delete_factor(ctx.sync_factor, &self.factor_id, Some(prf_key))
            .await?;

        finalize(response, self.user_confirmed_backup_removal)
    }
}

/// Why this factor cannot be removed at all, if it cannot.
///
/// Evaluated before the destructive-confirmation gate so an unsupported removal is
/// refused without first asking the user to approve deleting their whole backup.
fn unsupported_reason(
    metadata: &BackupMetadata,
    kind: &BackupFactorKind,
) -> Option<String> {
    match kind {
        BackupFactorKind::EcKeypair { .. } => {
            crate::warn!("remove_factor.keychain_removal_unsupported");
            Some("iCloud Keychain factor removal is not yet supported".to_string())
        }
        // The exported metadata does not link a passkey to its PRF key, so with
        // several passkeys Bedrock cannot tell which key to drop.
        BackupFactorKind::Passkey { .. } if metadata.passkey_factor_count() > 1 => {
            crate::warn!("remove_factor.multiple_passkeys_unsupported");
            Some(
                "removing a passkey is unsupported while several passkeys exist"
                    .to_string(),
            )
        }
        BackupFactorKind::Passkey { .. } if metadata.single_prf_key().is_none() => {
            crate::warn!("remove_factor.missing_prf_key");
            Some("the passkey has no PRF encryption key to drop".to_string())
        }
        BackupFactorKind::Passkey { .. } | BackupFactorKind::OidcAccount { .. } => None,
    }
}

/// Maps a successful delete-factor response to the flow outcome.
///
/// `user_confirmed` only feeds the detection below; it cannot change the outcome,
/// since the service has already acted by this point.
fn finalize(
    response: DeleteFactorResponse,
    user_confirmed: bool,
) -> Result<RemoveFactorOutcome, BackupOperationError> {
    if response.backup_deleted {
        // The request carries no confirmation flag, so a concurrent removal on another
        // device can cascade into a deletion this user never approved. Undoable by
        // nobody; detectable at least.
        if user_confirmed {
            crate::info!("remove_factor.backup_deleted");
        } else {
            crate::critical!(
                "remove_factor.backup_deleted_without_confirmation (the service cascaded on a factor the caller did not flag as last)"
            );
        }
        return Ok(RemoveFactorOutcome::BackupDeleted);
    }
    let metadata = response.backup_metadata.ok_or_else(|| {
        // The removal committed; only our ability to report the new state failed. The
        // caller is told it failed and its retry will hit `factor_not_found`.
        crate::critical!(
            "remove_factor.missing_response_metadata (factor IS removed; reporting failure)"
        );
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

/// Confirms Turnkey still accepts the sync factor, before anything irreversible.
///
/// `get_users` is the read the provider path already needs, so it shares the client's
/// cache. Note this proves the signer is *registered and accepted for a read*, not
/// that policy authorizes the delete activity that follows: a sub-organization whose
/// `sync_factor_policy` migration never ran can pass here and still reject the
/// teardown. It converts the common failure (a sync factor Turnkey has never seen)
/// into an actionable error before the commit; it does not make the teardown
/// guaranteed.
///
/// Only a stale signer blocks the flow. A Turnkey outage does not: the teardown this
/// gates is best-effort, and failing here would take BF-8 down with it.
///
/// # Errors
/// [`NeedsReauthReason::SyncFactorInvalid`] if Turnkey no longer knows the signer.
async fn verify_sync_factor(
    ctx: &FlowContext<'_>,
    plan: &OidcRemovalPlan,
) -> Result<(), BackupOperationError> {
    match ctx
        .turnkey
        .get_users(&plan.suborg_id, SyncFactor(ctx.sync_factor))
        .await
    {
        Ok(_) => Ok(()),
        Err(error) if error.indicates_invalid_signer() => {
            crate::warn!("remove_factor.sync_factor_invalid (pre-flight)");
            Err(BackupOperationError::NeedsReauth {
                reason: NeedsReauthReason::SyncFactorInvalid,
            })
        }
        Err(error) => {
            crate::warn!(
                "remove_factor.preflight_inconclusive code={} err={error} (proceeding; teardown is best-effort)",
                error.code()
            );
            Ok(())
        }
    }
}

/// Confirms the main factor authenticates as the root user that owns the providers,
/// before anything irreversible.
///
/// The sync-factor probe cannot cover this: the provider deletion is stamped by the
/// *main* factor, and that teardown is best-effort. A main factor from the wrong
/// passkey would therefore drop the backup factor, fail the teardown, and report
/// success while the account the user asked to disconnect stayed authorized.
///
/// # Errors
/// [`NeedsReauthReason::MainFactorRequired`] if the signer is unknown to Turnkey or
/// authenticates as a different user — in both cases the caller needs a new ceremony.
async fn verify_main_factor(
    ctx: &FlowContext<'_>,
    plan: &OidcRemovalPlan,
    main_factor: &P256Signer,
) -> Result<(), BackupOperationError> {
    let user_id = match ctx
        .turnkey
        .whoami_user_id(&plan.suborg_id, MainFactor(main_factor))
        .await
    {
        Ok(user_id) => user_id,
        Err(error) if error.indicates_invalid_signer() => {
            crate::warn!("remove_factor.main_factor_invalid (pre-flight)");
            return Err(BackupOperationError::NeedsReauth {
                reason: NeedsReauthReason::MainFactorRequired,
            });
        }
        // Transient: the teardown is best-effort, so don't block on an outage.
        Err(error) => {
            crate::warn!(
                "remove_factor.main_factor_preflight_inconclusive code={} err={error}",
                error.code()
            );
            return Ok(());
        }
    };

    if user_id != plan.user_id {
        // A valid Turnkey key, but not the root user that owns the OAuth providers --
        // the user completed the ceremony with the wrong passkey.
        crate::warn!(
            "remove_factor.main_factor_wrong_user expected={} got={user_id}",
            plan.user_id
        );
        return Err(BackupOperationError::NeedsReauth {
            reason: NeedsReauthReason::MainFactorRequired,
        });
    }
    Ok(())
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
        // Still `PENDING` when we stopped polling: may yet complete, so not an orphan.
        if matches!(error, TurnkeyApiError::ActivityPollingExceeded { .. }) {
            crate::warn!(
                "remove_factor.turnkey_suborg_teardown_pending suborg_id={suborg_id} err={error}"
            );
            return;
        }
        // `suborg_id` is only in this record now: delete-factor just dropped the
        // Turnkey key from the metadata that held it.
        crate::critical!(
            "remove_factor.turnkey_suborg_orphaned suborg_id={suborg_id} code={} err={error}",
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
            // May yet complete upstream, so not an orphan.
            Err(error @ TurnkeyApiError::ActivityPollingExceeded { .. }) => {
                crate::warn!(
                    "remove_factor.turnkey_provider_teardown_pending suborg_id={} provider={provider_id} err={error}",
                    plan.suborg_id
                );
            }
            Err(error) => {
                // The account the user asked to disconnect can still authorize.
                crate::critical!(
                    "remove_factor.turnkey_provider_orphaned suborg_id={} provider={provider_id} code={} err={error}",
                    plan.suborg_id,
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

    let Some(user) = users.iter().find(|user| user.user_id == plan.user_id) else {
        // No provider deletion can succeed without the user. Unlike the failures the
        // teardown tolerates, this is knowable pre-commit, so abort while retry is safe
        // rather than report success over a still-authorized account.
        crate::critical!(
            "remove_factor.turnkey_user_missing suborg_id={} user_id={} (aborting before commit)",
            plan.suborg_id,
            plan.user_id
        );
        return Err(BackupOperationError::Turnkey {
            code: "turnkey_user_not_found".to_string(),
        });
    };

    let Some(target) = user
        .oauth_providers
        .iter()
        .find(|provider| provider.provider_id == plan.provider_id)
    else {
        // An earlier attempt got this far. Idempotent, not an error.
        crate::debug!(
            "remove_factor.turnkey_provider_already_absent provider={}",
            plan.provider_id
        );
        return Ok(Vec::new());
    };

    Ok(user
        .oauth_providers
        .iter()
        .filter(|provider| {
            provider.issuer == target.issuer && provider.subject == target.subject
        })
        .map(|provider| provider.provider_id.clone())
        .collect())
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
    const WHOAMI: &str = "/public/v1/query/whoami";
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

    /// `whoami` for the main factor, resolving to `user_id`.
    async fn mount_whoami(server: &MockServer, user_id: &str) {
        mount(
            server,
            WHOAMI,
            json!({
                "organizationId": "suborg-1",
                "organizationName": "org",
                "userId": user_id,
                "username": "auth_user_main",
            }),
        )
        .await;
    }

    async fn mount_users(server: &MockServer, providers: Vec<Value>) {
        mount(
            server,
            LIST_USERS,
            json!({ "users": [main_user(providers)] }),
        )
        .await;
    }

    /// Turnkey echoes back the ids it deleted; the flow submits one per activity.
    async fn mount_delete_oauth(server: &MockServer) {
        mount(
            server,
            DELETE_OAUTH,
            completed_activity(
                "ACTIVITY_TYPE_DELETE_OAUTH_PROVIDERS",
                "deleteOauthProvidersResult",
                json!({ "providerIds": ["deleted"] }),
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
        mount_whoami(&server, "user-1").await;
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
        let paths = called_paths(&server).await;
        assert!(!paths.contains(&DELETE_SUB_ORG.to_string()));
        assert_ordered(&paths, DELETE_FACTOR, DELETE_OAUTH);
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
        mount_whoami(&server, "user-1").await;
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
        mount_users(&server, vec![]).await;
        mount_delete_sub_org(&server).await;

        let outcome = run_remove(&server, "f-1", None, false).await.unwrap();

        assert!(matches!(outcome, RemoveFactorOutcome::FactorRemoved { .. }));
        assert!(delete_factor_body(&server)
            .await
            .contains("turnkeyAccountId"));
        let paths = called_paths(&server).await;
        assert!(paths.contains(&DELETE_SUB_ORG.to_string()));
        assert!(!paths.contains(&DELETE_OAUTH.to_string()));
        assert_ordered(&paths, DELETE_FACTOR, DELETE_SUB_ORG);
    }

    /// Reversing this order would tear down Turnkey for a removal the service may
    /// still reject.
    fn assert_ordered(paths: &[String], first: &str, then: &str) {
        let first_at = paths.iter().position(|path| path == first);
        let then_at = paths.iter().position(|path| path == then);
        assert!(
            matches!((first_at, then_at), (Some(a), Some(b)) if a < b),
            "expected {first} before {then}, got {paths:?}"
        );
    }

    /// Once the service has committed, a Turnkey failure must not read as a failed
    /// removal.
    #[tokio::test]
    async fn last_oidc_removal_survives_a_failing_sub_org_teardown() {
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
        mount_users(&server, vec![]).await;
        Mock::given(method("POST"))
            .and(path(DELETE_SUB_ORG))
            .respond_with(ResponseTemplate::new(500))
            .mount(&server)
            .await;

        let outcome = run_remove(&server, "f-1", None, false).await.unwrap();

        assert!(
            matches!(outcome, RemoveFactorOutcome::FactorRemoved { .. }),
            "the factor is gone from the authoritative store; the user must be told so"
        );
    }

    /// The pre-flight makes this rare, not fatal.
    #[tokio::test]
    async fn last_oidc_removal_survives_an_unauthorized_teardown() {
        install_attestation();
        let server = MockServer::start().await;
        mount_metadata(&server, metadata(vec![oidc_factor("f-1", "p-1")])).await;
        mount_delete_factor(&server, json!({ "backupDeleted": true })).await;
        mount_users(&server, vec![]).await;
        Mock::given(method("POST"))
            .and(path(DELETE_SUB_ORG))
            .respond_with(ResponseTemplate::new(401).set_body_json(json!({
                "error": { "message": "PUBLIC_KEY_NOT_FOUND" }
            })))
            .mount(&server)
            .await;

        let outcome = run_remove(&server, "f-1", None, true).await.unwrap();

        assert!(matches!(outcome, RemoveFactorOutcome::BackupDeleted));
    }

    /// Without the pre-flight, the delete succeeds, the teardown fails on the same
    /// stale key, and the user is told it worked while the sub-org leaks.
    #[tokio::test]
    async fn last_oidc_removal_aborts_when_sync_factor_is_stale() {
        install_attestation();
        let server = MockServer::start().await;
        mount_metadata(
            &server,
            metadata(vec![oidc_factor("f-1", "p-1"), passkey_factor("pk-1")]),
        )
        .await;
        Mock::given(method("POST"))
            .and(path(LIST_USERS))
            .respond_with(ResponseTemplate::new(401).set_body_json(json!({
                "error": { "message": "PUBLIC_KEY_NOT_FOUND" }
            })))
            .mount(&server)
            .await;
        mount_delete_factor(&server, json!({ "backupDeleted": true })).await;
        mount_delete_sub_org(&server).await;

        let error = run_remove(&server, "f-1", None, false).await.unwrap_err();

        assert!(
            matches!(
                error,
                BackupOperationError::NeedsReauth {
                    reason: NeedsReauthReason::SyncFactorInvalid
                }
            ),
            "expected SyncFactorInvalid, got {error:?}"
        );
        let paths = called_paths(&server).await;
        assert!(
            !paths.contains(&DELETE_FACTOR.to_string()),
            "the backup must be intact so the caller can re-auth and retry"
        );
        assert!(!paths.contains(&DELETE_SUB_ORG.to_string()));
    }

    /// A Turnkey outage must not block removals: the teardown it gates is best-effort,
    /// and BF-8 would go down with it while the backup service is healthy.
    #[tokio::test]
    async fn last_oidc_removal_proceeds_when_the_preflight_is_inconclusive() {
        install_attestation();
        let server = MockServer::start().await;
        mount_metadata(
            &server,
            metadata(vec![oidc_factor("f-1", "p-1"), passkey_factor("pk-1")]),
        )
        .await;
        Mock::given(method("POST"))
            .and(path(LIST_USERS))
            .respond_with(ResponseTemplate::new(503))
            .mount(&server)
            .await;
        mount_delete_factor(
            &server,
            json!({ "backupDeleted": false, "backupMetadata": metadata(vec![passkey_factor("pk-1")]) }),
        )
        .await;
        mount_delete_sub_org(&server).await;

        let outcome = run_remove(&server, "f-1", None, false).await.unwrap();

        assert!(
            matches!(outcome, RemoveFactorOutcome::FactorRemoved { .. }),
            "a Turnkey outage must not block a removal the backup service can complete"
        );
        let paths = called_paths(&server).await;
        assert!(paths.contains(&DELETE_FACTOR.to_string()));
        assert!(
            paths.contains(&DELETE_SUB_ORG.to_string()),
            "the teardown must still be attempted after an inconclusive probe"
        );
    }

    /// Unlike the last-OIDC path, this one needs the read's data: without it the only
    /// option is deleting the single id we were handed, orphaning sibling audiences.
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

    /// The factor is both unsupported and the last main factor, so whichever check
    /// runs first decides the error -- and the user must not be asked to approve
    /// deleting their backup for a removal that was never supported.
    #[tokio::test]
    async fn unsupported_removal_is_refused_before_asking_to_delete_the_backup() {
        install_attestation();
        let server = MockServer::start().await;
        // Sole main factor, and an unsupported kind.
        mount_metadata(&server, metadata(vec![eckeypair_factor("ec-1")])).await;

        let error = run_remove(&server, "ec-1", None, false).await.unwrap_err();

        assert!(
            matches!(error, BackupOperationError::Unsupported { .. }),
            "expected Unsupported ahead of WouldDeleteBackup, got {error:?}"
        );
    }

    /// Same ordering, for the passkey preconditions.
    #[tokio::test]
    async fn multiple_passkeys_refused_before_asking_to_delete_the_backup() {
        install_attestation();
        let server = MockServer::start().await;
        mount_metadata(
            &server,
            metadata_keyed(
                vec![prf_key("ek")],
                vec![passkey_factor("pk-1"), passkey_factor("pk-2")],
            ),
        )
        .await;

        let error = run_remove(&server, "pk-1", None, false).await.unwrap_err();

        assert!(
            matches!(error, BackupOperationError::Unsupported { .. }),
            "expected Unsupported ahead of WouldDeleteBackup, got {error:?}"
        );
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
        mount_users(&server, vec![]).await;
        mount_delete_sub_org(&server).await;

        let outcome = run_remove(&server, "f-1", None, true).await.unwrap();

        assert!(matches!(outcome, RemoveFactorOutcome::BackupDeleted));
        assert!(called_paths(&server)
            .await
            .contains(&DELETE_SUB_ORG.to_string()));
    }

    /// The user completed the passkey ceremony with the wrong passkey: the signer is
    /// valid at Turnkey but authenticates as a different user, so it cannot delete the
    /// root user's providers. The teardown is best-effort, so without this check the
    /// factor would be dropped and the disconnected account left authorized.
    #[tokio::test]
    async fn provider_removal_aborts_when_the_main_factor_is_the_wrong_user() {
        install_attestation();
        let server = MockServer::start().await;
        mount_metadata(
            &server,
            metadata(vec![oidc_factor("f-1", "p-1"), oidc_factor("f-2", "p-2")]),
        )
        .await;
        mount_whoami(&server, "some-other-user").await;
        mount_users(&server, vec![oauth_provider("p-1", "iss", "sub")]).await;
        mount_delete_factor(&server, json!({ "backupDeleted": false })).await;
        mount_delete_oauth(&server).await;
        let main = signer();

        let error = run_remove(&server, "f-1", Some(&main), false)
            .await
            .unwrap_err();

        assert!(
            matches!(
                error,
                BackupOperationError::NeedsReauth {
                    reason: NeedsReauthReason::MainFactorRequired
                }
            ),
            "expected MainFactorRequired, got {error:?}"
        );
        let paths = called_paths(&server).await;
        assert!(
            !paths.contains(&DELETE_FACTOR.to_string()),
            "nothing may be committed for a main factor that cannot do the teardown"
        );
        assert!(!paths.contains(&DELETE_OAUTH.to_string()));
    }

    /// A main factor Turnkey does not know at all: same abort, same reason.
    #[tokio::test]
    async fn provider_removal_aborts_when_the_main_factor_is_unregistered() {
        install_attestation();
        let server = MockServer::start().await;
        mount_metadata(
            &server,
            metadata(vec![oidc_factor("f-1", "p-1"), oidc_factor("f-2", "p-2")]),
        )
        .await;
        Mock::given(method("POST"))
            .and(path(WHOAMI))
            .respond_with(ResponseTemplate::new(401).set_body_json(json!({
                "error": { "message": "PUBLIC_KEY_NOT_FOUND" }
            })))
            .mount(&server)
            .await;
        mount_delete_factor(&server, json!({ "backupDeleted": false })).await;
        let main = signer();

        let error = run_remove(&server, "f-1", Some(&main), false)
            .await
            .unwrap_err();

        assert!(
            matches!(
                error,
                BackupOperationError::NeedsReauth {
                    reason: NeedsReauthReason::MainFactorRequired
                }
            ),
            "expected MainFactorRequired, got {error:?}"
        );
        assert!(!called_paths(&server)
            .await
            .contains(&DELETE_FACTOR.to_string()));
    }

    /// No provider deletion can succeed if the user is absent, and that is knowable
    /// before the commit -- so abort rather than leave the account still authorized.
    #[tokio::test]
    async fn provider_removal_aborts_when_the_turnkey_user_is_missing() {
        install_attestation();
        let server = MockServer::start().await;
        mount_metadata(
            &server,
            metadata(vec![oidc_factor("f-1", "p-1"), oidc_factor("f-2", "p-2")]),
        )
        .await;
        // `main_user` is id `user-1`; the sub-org only knows a different one.
        mount(
            &server,
            LIST_USERS,
            json!({ "users": [{
                "userId": "user-recreated",
                "userName": "auth_user_main",
                "oauthProviders": [oauth_provider("p-1", "iss", "sub")],
            }] }),
        )
        .await;
        mount_delete_factor(&server, json!({ "backupDeleted": false })).await;
        mount_whoami(&server, "user-1").await;
        mount_delete_oauth(&server).await;
        let main = signer();

        let error = run_remove(&server, "f-1", Some(&main), false)
            .await
            .unwrap_err();

        // The code is the only thing native can match on, and `map_turnkey_error`
        // yields the same variant for any non-retryable Turnkey failure, so pin it.
        let BackupOperationError::Turnkey { code } = &error else {
            panic!("expected a Turnkey error, got {error:?}");
        };
        assert_eq!(code, "turnkey_user_not_found");
        let paths = called_paths(&server).await;
        assert!(
            !paths.contains(&DELETE_FACTOR.to_string()),
            "nothing may be committed when the teardown provably cannot run"
        );
        assert!(!paths.contains(&DELETE_OAUTH.to_string()));
    }

    /// An earlier attempt already deleted it; proceed and remove the factor.
    #[tokio::test]
    async fn provider_removal_proceeds_when_the_provider_is_already_absent() {
        install_attestation();
        let server = MockServer::start().await;
        mount_metadata(
            &server,
            metadata(vec![oidc_factor("f-1", "p-1"), oidc_factor("f-2", "p-2")]),
        )
        .await;
        // The user exists but carries only an unrelated provider.
        mount_users(&server, vec![oauth_provider("p-9", "iss", "other")]).await;
        mount_delete_factor(
            &server,
            json!({ "backupDeleted": false, "backupMetadata": metadata(vec![oidc_factor("f-2", "p-2")]) }),
        )
        .await;
        mount_whoami(&server, "user-1").await;
        mount_delete_oauth(&server).await;
        let main = signer();

        let outcome = run_remove(&server, "f-1", Some(&main), false)
            .await
            .unwrap();

        assert!(matches!(outcome, RemoveFactorOutcome::FactorRemoved { .. }));
        assert!(
            deleted_provider_ids(&server).await.is_empty(),
            "nothing to delete; must not guess at a provider id"
        );
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
