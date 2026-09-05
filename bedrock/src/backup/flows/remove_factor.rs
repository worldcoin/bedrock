//! BF-7 [`MainFactor`] deletion. When removing the last one,
//! the entire backup is deleted (it can't be used).

use async_trait::async_trait;

use super::{BackupFlow, FlowContext};
use crate::backup::backup_service::{
    BackupEncryptionKey, BackupFactorKind, BackupMetadata,
};
use crate::backup::flows::{delete_backup, DeleteBackup};
use crate::backup::turnkey::TurnkeyApiError;
use crate::backup::{
    BackupOperationError, MainFactor, NeedsReauthReason, SyncFactor, TurnkeyMeta,
};
use crate::primitives::P256Signer;

/// Outcome of a successful factor removal.
#[derive(Debug, uniffi::Enum)]
pub enum RemoveFactorOutcome {
    /// The factor was removed, returns the updated backup metadata.
    FactorRemoved {
        /// Updated backup metadata (helps update the UI)
        metadata: BackupMetadata,
    },
    /// The removed factor was the last [`MainFactor`], so the entire backup was
    /// deleted.
    ///
    /// # Native responsibilities
    /// 1. Delete its stored [`SyncFactor`] keypair.
    /// 2. Update whatever "backup enabled" state it shows the user.
    BackupDeleted,
}

/// Removes the [`MainFactor`] with `factor_id`
pub struct RemoveFactor {
    /// The id of the factor to remove.
    pub factor_id: String,
    /// Set if the user approved full backup deletion
    pub user_confirmed_backup_removal: bool,
}

#[async_trait]
impl BackupFlow for RemoveFactor {
    type Output = RemoveFactorOutcome;

    async fn run(
        &self,
        ctx: &FlowContext<'_>,
    ) -> Result<RemoveFactorOutcome, BackupOperationError> {
        let plan = self.plan(ctx).await?;
        self.commit(ctx, plan).await
    }
}

/// The execution plan for this operation
enum Plan {
    /// Removing an OIDC factor.
    Oidc {
        turnkey_account: TurnkeyMeta,
        /// The encrypted backup key to remove.
        backup_encryption_key: BackupEncryptionKey,
        /// OIDC Provider IDs that must be removed (Turnkey IDs).
        provider_ids: Vec<String>,
        /// When removing the last OIDC factor, the Turnkey account is deleted (as it's no longer used).
        is_last_oidc_factor: bool,
    },
    /// Removing a passkey.
    Passkey {
        backup_encryption_key: BackupEncryptionKey,
        /// All metadata to remove the passkey from Turnkey. `None` if the user has no Turnkey account.
        turnkey: Option<TurnkeyPasskeyMeta>,
    },
    /// Delete the entire backup everywhere.
    FullDeletion {},
}

/// The metadata required to delete the passkey (i.e. authenticator) from Turnkey.
#[derive(Clone)]
struct TurnkeyPasskeyMeta {
    turnkey_account: TurnkeyMeta,
    /// The Turnkey ID of the passkey that needs to be removed.
    authenticator_id: String,
}

impl RemoveFactor {
    /// Reads state and validates pre-conditions, cancel-safe.
    async fn plan(&self, ctx: &FlowContext<'_>) -> Result<Plan, BackupOperationError> {
        let metadata = ctx
            .service
            .retrieve_metadata(ctx.sync_factor, ctx.backup_id)
            .await?;
        let factor = metadata
            .factor(&self.factor_id)
            .ok_or(BackupOperationError::InvalidFactorId)?;

        if let Some(detail) = is_removal_supported(&metadata, &factor.kind) {
            return Err(BackupOperationError::Unsupported { detail });
        }

        if metadata.main_factor_count() == 1 {
            if !self.user_confirmed_backup_removal {
                crate::debug!("remove_factor.would_delete_backup");
                return Err(BackupOperationError::WouldDeleteBackup);
            }

            return Ok(Plan::FullDeletion {});
        }

        match &factor.kind {
            BackupFactorKind::OidcAccount {
                turnkey_provider_id,
                ..
            } => {
                self.plan_oidc(ctx, &metadata, turnkey_provider_id.as_str())
                    .await
            }
            BackupFactorKind::Passkey { credential_id, .. } => {
                let backup_encryption_key =
                    metadata.single_prf_key().cloned().ok_or_else(|| {
                        crate::warn!(
                            "remove_factor.missing_backup_encryption_key for passkey"
                        );
                        BackupOperationError::Unsupported {
                            detail: "passkey has no PRF encryption key to drop"
                                .to_string(),
                        }
                    })?;
                let turnkey = self
                    .plan_passkey_on_turnkey(ctx, &metadata, credential_id)
                    .await?;
                Ok(Plan::Passkey {
                    backup_encryption_key,
                    turnkey,
                })
            }
            BackupFactorKind::EcKeypair { .. } => {
                unreachable!("eckeypair deletion not supported") // verified in `is_removal_supported`
            }
        }
    }

    /// Plan for an OIDC factor removal.
    async fn plan_oidc(
        &self,
        ctx: &FlowContext<'_>,
        metadata: &BackupMetadata,
        turnkey_provider_id: &str,
    ) -> Result<Plan, BackupOperationError> {
        let (turnkey_account, backup_encryption_key) =
            metadata.turnkey_account().ok_or_else(|| {
                // Critical consistency. A backup with multiple Turnkey accounts.
                crate::critical!("remove_factor.missing_unique_turnkey_key");
                BackupOperationError::BackupService {
                    code: "missing_turnkey_key".to_string(),
                }
            })?;

        let is_last_oidc_factor = metadata.oidc_factor_count() == 1;

        let provider_ids = if is_last_oidc_factor {
            ctx.turnkey
                .verify_sync_factor(&turnkey_account.id, SyncFactor(ctx.sync_factor))
                .await?;
            vec![turnkey_provider_id.to_string()]
        } else if let Some(main_factor) = ctx.main_factor {
            ctx.turnkey
                .verify_main_factor(
                    &turnkey_account.id,
                    &turnkey_account.auth_user_main_id,
                    MainFactor(main_factor),
                )
                .await?;
            resolve_all_turnkey_provider_ids(ctx, &turnkey_account, turnkey_provider_id)
                .await?
        } else {
            // Deleting an OAuth provider from Turnkey requires a [`MainFactor`]
            crate::debug!("remove_factor.needs_main_factor");
            return Err(BackupOperationError::NeedsReauth {
                reason: NeedsReauthReason::MainFactorRequired,
            });
        };

        Ok(Plan::Oidc {
            turnkey_account,
            backup_encryption_key: backup_encryption_key.clone(),
            provider_ids,
            is_last_oidc_factor,
        })
    }

    /// Plans a passkey removal from Turnkey. Returns `None` if the user does not have
    /// a Turnkey account (a Turnkey account only exists if the user has an OIDC factor).
    ///
    /// # Errors
    /// See [`BackupOperationError`]. [`BackupOperationError::NeedsReauth`] is possible
    /// if a [`MainFactor`] is not provided.
    async fn plan_passkey_on_turnkey(
        &self,
        ctx: &FlowContext<'_>,
        metadata: &BackupMetadata,
        credential_id: &str,
    ) -> Result<Option<TurnkeyPasskeyMeta>, BackupOperationError> {
        let Some((turnkey_account, _)) = metadata.turnkey_account() else {
            return Ok(None);
        };

        let users = match ctx
            .turnkey
            .get_users(&turnkey_account.id, SyncFactor(ctx.sync_factor))
            .await
        {
            Ok(users) => users,
            // Actionable: [`SyncFactor`] can be refreshed with a [`MainFactor`]
            Err(error) if error.indicates_invalid_signer() => {
                crate::warn!("remove_factor.authenticator_lookup_sync_factor_invalid");
                return Err(BackupOperationError::NeedsReauth {
                    reason: NeedsReauthReason::SyncFactorInvalid,
                });
            }
            Err(error) => return Err(error.into()),
        };

        let Some(authenticator_id) = users
            .iter()
            .find(|user| user.user_id == *turnkey_account.auth_user_main_id)
            .and_then(|user| {
                user.authenticators
                    .iter()
                    .find(|authenticator| authenticator.credential_id == credential_id)
            })
            .map(|authenticator| authenticator.authenticator_id.clone())
        else {
            crate::debug!("remove_factor.authenticator_already_absent");
            return Ok(None);
        };

        let Some(main_factor) = ctx.main_factor else {
            crate::warn!("remove_factor.authenticator_needs_main_factor");
            return Err(BackupOperationError::NeedsReauth {
                reason: NeedsReauthReason::MainFactorRequired,
            });
        };
        ctx.turnkey
            .verify_main_factor(
                &turnkey_account.id,
                &turnkey_account.auth_user_main_id,
                MainFactor(main_factor),
            )
            .await?;

        let meta = TurnkeyPasskeyMeta {
            turnkey_account,
            authenticator_id,
        };

        Ok(Some(meta))
    }

    /// Applies the removal at the authoritative store, then cleans up Turnkey.
    ///
    /// Deliberately not wrapped in a cancelling deadline: past the delete the outcome
    /// is decided, and dropping this future would report a failure for it.
    async fn commit(
        &self,
        ctx: &FlowContext<'_>,
        plan: Plan,
    ) -> Result<RemoveFactorOutcome, BackupOperationError> {
        if matches!(plan, Plan::FullDeletion {}) {
            DeleteBackup.run(ctx).await?;
            return Ok(RemoveFactorOutcome::BackupDeleted);
        }

        let (backup_encryption_key, turnkey_account) = match &plan {
            Plan::Oidc {
                backup_encryption_key,
                turnkey_account,
                is_last_oidc_factor,
                ..
            } => (
                is_last_oidc_factor.then(|| backup_encryption_key.clone()),
                Some(turnkey_account.clone()),
            ),
            Plan::Passkey {
                backup_encryption_key,
                turnkey,
                ..
            } => (
                Some(backup_encryption_key.clone()),
                turnkey.as_ref().map(|v| v.turnkey_account.clone()),
            ),
            Plan::FullDeletion { .. } => {
                unreachable!("handled above")
            }
        };

        // Step 1: Commit backup-service (authorative)
        let response = ctx
            .service
            .delete_factor(ctx.sync_factor, &self.factor_id, backup_encryption_key)
            .await?;

        // Step 2: Commit Turnkey

        //  Step 2A: Delete the whole Turnkey account if the backup was deleted (remote race condition)
        if response.backup_deleted {
            if let Some(turnkey_account) = turnkey_account {
                delete_backup::delete_turnkey_account(
                    ctx.turnkey,
                    vec![turnkey_account.id],
                    ctx.sync_factor,
                )
                .await;
            }

            if !self.user_confirmed_backup_removal {
                crate::critical!(
                    "remove_factor.backup_deleted_without_confirmation (the service cascaded on a factor the caller did not flag as last)"
                );
            }
            return Ok(RemoveFactorOutcome::BackupDeleted);
        }

        // Step 2B: Delete the factor from Turnkey
        turnkey_commit(ctx, plan).await;

        // Step 3: Result
        let metadata = response.backup_metadata.ok_or_else(|| {
            crate::critical!(
                "remove_factor.missing_response_metadata (factor IS removed; backup-service returned incorrect response)"
            );
            BackupOperationError::Generic {
                error_message: "deletion suceeded but missing_response_metadata".to_string(),
            }
        })?;
        crate::debug!("remove_factor.factor_removed");
        Ok(RemoveFactorOutcome::FactorRemoved { metadata })
    }
}

/// Executes the factor removal from the Turnkey account.
async fn turnkey_commit(ctx: &FlowContext<'_>, plan: Plan) {
    match plan {
        Plan::Oidc {
            turnkey_account,
            provider_ids,
            is_last_oidc_factor,
            ..
        } => {
            // Removing the last OIDC factor -> delete the Turnkey account (there's no use for it anymore)
            if is_last_oidc_factor {
                delete_backup::delete_turnkey_account(
                    ctx.turnkey,
                    vec![turnkey_account.id],
                    ctx.sync_factor,
                )
                .await;
            } else if let Some(main_factor) = ctx.main_factor {
                delete_oauth_providers_from_turnkey(
                    ctx,
                    &turnkey_account,
                    provider_ids,
                    main_factor,
                )
                .await;
            }
        }
        Plan::Passkey {
            turnkey: Some(turnkey),
            ..
        } => {
            let Some(main_factor) = ctx.main_factor else {
                crate::critical!("internal unreachable inconsistency");
                return;
            };
            if let Err(error) = ctx
                .turnkey
                .delete_authenticators(
                    &turnkey.turnkey_account.id,
                    &turnkey.turnkey_account.auth_user_main_id,
                    vec![turnkey.authenticator_id],
                    MainFactor(main_factor),
                )
                .await
            {
                crate::error!(
                    "remove_factor.authenticator_orphaned code={} err={error}",
                    error.code()
                );
            }
        }
        Plan::Passkey { .. } => {}
        Plan::FullDeletion { .. } => {
            unreachable!("handled at the top of `commit`")
        }
    }
}

/// Deletes each OIDC provider in `provider_ids` from the Turnkey account.
async fn delete_oauth_providers_from_turnkey(
    ctx: &FlowContext<'_>,
    turnkey_account: &TurnkeyMeta,
    provider_ids: Vec<String>,
    main_factor: &P256Signer,
) {
    if provider_ids.is_empty() {
        crate::debug!("remove_factor.turnkey_providers_already_absent");
        return;
    }

    match ctx
        .turnkey
        .delete_oauth_providers(
            &turnkey_account.id,
            &turnkey_account.auth_user_main_id,
            provider_ids,
            MainFactor(main_factor),
        )
        .await
    {
        Ok(()) => {}
        Err(error @ TurnkeyApiError::ActivityPollingExceeded { .. }) => {
            crate::warn!("remove_factor.turnkey_provider_teardown_pending err={error}");
        }
        Err(error) => {
            // Inconsistency will be resolved with a migration
            crate::error!(
                "remove_factor.turnkey_provider_orphaned code={} err={error}",
                error.code()
            );
        }
    }
}

/// Can the requested factor be removed? If not, why.
fn is_removal_supported(
    metadata: &BackupMetadata,
    kind: &BackupFactorKind,
) -> Option<String> {
    match kind {
        BackupFactorKind::EcKeypair { .. } => {
            crate::warn!("remove_factor.keychain_removal_unsupported");
            Some("iCloud Keychain factor removal is not yet supported".to_string())
        }
        BackupFactorKind::Passkey { .. } if metadata.passkey_factor_count() > 1 => {
            // Theoretical invariant, multiple passkeys are not supported.
            crate::critical!("remove_factor.multiple_passkeys_unsupported");
            Some(
                "removing a passkey is unsupported while several passkeys exist"
                    .to_string(),
            )
        }
        BackupFactorKind::Passkey { .. } if metadata.single_prf_key().is_none() => {
            crate::critical!("remove_factor.missing_prf_key");
            Some("the passkey has no PRF encryption key to drop".to_string())
        }
        BackupFactorKind::Passkey { .. } | BackupFactorKind::OidcAccount { .. } => None,
    }
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

/// Obtains the list of all `provider_id`s to remove from Turnkey based on the factor being
/// removed. Explicitly for Apple, multiple providers are used to support all clients.
async fn resolve_all_turnkey_provider_ids(
    ctx: &FlowContext<'_>,
    turnkey_meta: &TurnkeyMeta,
    turnkey_provider_id: &str,
) -> Result<Vec<String>, BackupOperationError> {
    let users = ctx
        .turnkey
        .get_users(&turnkey_meta.id, SyncFactor(ctx.sync_factor))
        .await
        .map_err(|error| map_turnkey_error(&error))?;

    let Some(user) = users
        .iter()
        .find(|user| user.user_id == turnkey_meta.auth_user_main_id)
    else {
        // Logged as critical because it means that an ID registered with the backup-service is not in Turnkey.
        crate::critical!(
            "remove_factor.turnkey_user_missing suborg_id={} (aborting)",
            turnkey_meta.id,
        );
        return Err(BackupOperationError::Consistency);
    };

    let Some(target) = user
        .oauth_providers
        .iter()
        .find(|provider| provider.provider_id == *turnkey_provider_id)
    else {
        crate::error!(
            "remove_factor.turnkey_provider_already_absent suborg_id={} (siblings cannot be identified)",
            turnkey_meta.id,
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
    use crate::backup::turnkey::TurnkeyApiClient;
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
    const DELETE_AUTHENTICATORS: &str = "/public/v1/submit/delete_authenticators";
    const DELETE_BACKUP_CHALLENGE: &str = "/v1/delete-backup/challenge/keypair";
    const DELETE_BACKUP: &str = "/v1/delete-backup";
    const TEST_BACKUP_ID: &str = "backup-1";

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

    /// `list_users` where the root user carries `credential_ids` as authenticators.
    async fn mount_users_with_authenticators(
        server: &MockServer,
        credential_ids: &[&str],
    ) {
        let authenticators: Vec<Value> = credential_ids
            .iter()
            .map(|credential_id| {
                json!({
                    "transports": [],
                    "attestationType": "none",
                    "aaguid": "",
                    "credentialId": credential_id,
                    "model": "",
                    "authenticatorId": format!("auth-{credential_id}"),
                    "authenticatorName": "passkey",
                })
            })
            .collect();
        let mut user = main_user(vec![]);
        user["authenticators"] = Value::Array(authenticators);
        mount(server, LIST_USERS, json!({ "users": [user] })).await;
    }

    async fn mount_delete_authenticators(server: &MockServer, deleted: &str) {
        mount(
            server,
            DELETE_AUTHENTICATORS,
            completed_activity(
                "ACTIVITY_TYPE_DELETE_AUTHENTICATORS",
                "deleteAuthenticatorsResult",
                json!({ "authenticatorIds": [deleted] }),
            ),
        )
        .await;
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

    /// The endpoints the `FullDeletion` path uses: removing the last main factor now
    /// deletes the whole backup outright instead of leaning on the service's cascade.
    async fn mount_delete_backup(server: &MockServer) {
        mount(server, DELETE_BACKUP_CHALLENGE, challenge_response()).await;
        Mock::given(method("POST"))
            .and(path(DELETE_BACKUP))
            .respond_with(ResponseTemplate::new(204))
            .mount(server)
            .await;
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
            backup_id: TEST_BACKUP_ID,
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
        // One activity for the whole identity: a per-provider loop leaves the set
        // half-torn when a later call stalls or fails.
        let deletes = called_paths(&server)
            .await
            .iter()
            .filter(|path| *path == DELETE_OAUTH)
            .count();
        assert_eq!(deletes, 1, "the identity must be torn down atomically");
    }

    /// Corrupt metadata with two Turnkey keys cannot say which sub-organization a
    /// removal targets, so it must refuse rather than pick one.
    #[tokio::test]
    async fn oidc_removal_aborts_on_multiple_turnkey_keys() {
        install_attestation();
        let server = MockServer::start().await;
        mount_metadata(
            &server,
            metadata_keyed(
                vec![turnkey_key(), turnkey_key()],
                vec![oidc_factor("f-1", "p-1"), oidc_factor("f-2", "p-2")],
            ),
        )
        .await;
        mount_delete_factor(&server, json!({ "backupDeleted": false })).await;
        let main = signer();

        let error = run_remove(&server, "f-1", Some(&main), false)
            .await
            .unwrap_err();

        let BackupOperationError::BackupService { code } = &error else {
            panic!("expected a BackupService error, got {error:?}");
        };
        assert_eq!(code, "missing_turnkey_key");
        assert!(!called_paths(&server)
            .await
            .contains(&DELETE_FACTOR.to_string()));
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
        mount_delete_backup(&server).await;
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

    #[tokio::test]
    async fn a_failed_turnkey_cleanup_does_not_erase_the_committed_outcome() {
        install_attestation();
        let server = MockServer::start().await;
        mount_delete_backup(&server).await;
        mount_metadata(&server, metadata(vec![oidc_factor("f-1", "p-1")])).await;
        mount_users(&server, vec![]).await;
        mount_delete_factor(&server, json!({ "backupDeleted": true })).await;
        // The teardown is best-effort: the factor is already gone at the
        // authoritative store, so nothing here may change what the caller is told.
        Mock::given(method("POST"))
            .and(path(DELETE_SUB_ORG))
            .respond_with(ResponseTemplate::new(500))
            .mount(&server)
            .await;

        let outcome = run_remove(&server, "f-1", None, true).await.unwrap();

        assert!(
            matches!(outcome, RemoveFactorOutcome::BackupDeleted),
            "the committed outcome must survive a failed cleanup, got {outcome:?}"
        );
        let paths = called_paths(&server).await;
        assert!(
            paths.contains(&DELETE_BACKUP.to_string()),
            "the last main factor deletes the backup outright"
        );
        assert!(
            !paths.contains(&DELETE_FACTOR.to_string()),
            "delete-factor is not involved once the whole backup goes"
        );
    }

    /// A Turnkey outage must not block removals: the teardown it gates is best-effort,
    /// and BF-8 would go down with it while the backup service is healthy.
    #[tokio::test]
    async fn last_oidc_removal_aborts_when_the_preflight_is_inconclusive() {
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

        let error = run_remove(&server, "f-1", None, false).await.unwrap_err();

        assert!(matches!(
            error,
            BackupOperationError::Network { retryable: true }
        ));
        let paths = called_paths(&server).await;
        assert!(
            !paths.contains(&DELETE_FACTOR.to_string()),
            "nothing may be committed on a premise the plan could not verify"
        );
        assert!(!paths.contains(&DELETE_SUB_ORG.to_string()));
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

        // The passkey was never registered as a Turnkey authenticator.
        mount_users_with_authenticators(&server, &[]).await;

        let outcome = run_remove(&server, "pk-1", None, false).await.unwrap();

        assert!(matches!(outcome, RemoveFactorOutcome::FactorRemoved { .. }));
        let body = delete_factor_body(&server).await;
        assert!(body.contains("\"PRF\"") && body.contains("prf-ek"));
        let paths = called_paths(&server).await;
        assert!(!paths.contains(&DELETE_AUTHENTICATORS.to_string()));
        assert!(!paths.contains(&DELETE_OAUTH.to_string()));
        assert!(!paths.contains(&DELETE_SUB_ORG.to_string()));
    }

    /// Dropping the PRF key stops the passkey recovering the backup, but on its own
    /// leaves it able to authorize Turnkey activities. The disconnect is only complete
    /// once the authenticator goes too.
    #[tokio::test]
    async fn passkey_removal_deletes_the_turnkey_authenticator() {
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
        mount_users_with_authenticators(&server, &["cred-pk-1"]).await;
        mount_whoami(&server, "user-1").await;
        mount_delete_factor(
            &server,
            json!({ "backupDeleted": false, "backupMetadata": metadata(vec![oidc_factor("f-2", "p-2")]) }),
        )
        .await;
        mount_delete_authenticators(&server, "auth-cred-pk-1").await;
        let main = signer();

        let outcome = run_remove(&server, "pk-1", Some(&main), false)
            .await
            .unwrap();

        assert!(matches!(outcome, RemoveFactorOutcome::FactorRemoved { .. }));
        let paths = called_paths(&server).await;
        assert!(paths.contains(&DELETE_AUTHENTICATORS.to_string()));
        assert_ordered(&paths, DELETE_FACTOR, DELETE_AUTHENTICATORS);
    }

    #[tokio::test]
    async fn passkey_removal_aborts_when_the_main_factor_is_the_wrong_user() {
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
        mount_users_with_authenticators(&server, &["cred-pk-1"]).await;
        mount_whoami(&server, "some-other-user").await;
        mount_delete_factor(&server, json!({ "backupDeleted": false })).await;
        mount_delete_authenticators(&server, "auth-cred-pk-1").await;
        let main = signer();

        let error = run_remove(&server, "pk-1", Some(&main), false)
            .await
            .unwrap_err();

        assert!(
            matches!(
                error,
                BackupOperationError::NeedsReauth {
                    reason: NeedsReauthReason::MainFactorInvalid
                }
            ),
            "expected MainFactorInvalid, got {error:?}"
        );
        let paths = called_paths(&server).await;
        assert!(!paths.contains(&DELETE_FACTOR.to_string()));
        assert!(!paths.contains(&DELETE_AUTHENTICATORS.to_string()));
    }

    /// Authenticators live on the root user, so removing one needs the same signer an
    /// OAuth provider deletion does. Asked for before anything is committed.
    #[tokio::test]
    async fn passkey_removal_needs_a_main_factor_for_the_authenticator() {
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
        mount_users_with_authenticators(&server, &["cred-pk-1"]).await;
        mount_delete_factor(&server, json!({ "backupDeleted": false })).await;

        let error = run_remove(&server, "pk-1", None, false).await.unwrap_err();

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

    /// Last passkey, confirmed: the service deletes the whole backup, no Turnkey.
    #[tokio::test]
    async fn last_passkey_confirmed_deletes_backup() {
        install_attestation();
        let server = MockServer::start().await;
        mount_delete_backup(&server).await;
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
        let paths = called_paths(&server).await;
        assert!(
            paths.contains(&DELETE_BACKUP.to_string()),
            "the last main factor deletes the backup outright"
        );
        assert!(!paths.contains(&DELETE_FACTOR.to_string()));
        // A PRF-only backup has no Turnkey account, so nothing there to touch.
        assert!(!paths.contains(&LIST_USERS.to_string()));
        assert!(!paths.contains(&DELETE_OAUTH.to_string()));
        assert!(!paths.contains(&DELETE_SUB_ORG.to_string()));
    }

    /// More than one passkey: Bedrock can't tell which PRF key backs the target, so
    /// it aborts before any mutation. INVARIANT: we don't allow multiple passkeys on a backup.
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
        mount_delete_backup(&server).await;
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

    /// The user completed the passkey ceremony with the wrong passkey
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
                    reason: NeedsReauthReason::MainFactorInvalid
                }
            ),
            "expected MainFactorInvalid, got {error:?}"
        );
        let paths = called_paths(&server).await;
        assert!(
            !paths.contains(&DELETE_FACTOR.to_string()),
            "nothing may be committed for a main factor that cannot do the teardown"
        );
        assert!(!paths.contains(&DELETE_OAUTH.to_string()));
    }

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
                    reason: NeedsReauthReason::MainFactorInvalid
                }
            ),
            "expected MainFactorInvalid, got {error:?}"
        );
        assert!(!called_paths(&server)
            .await
            .contains(&DELETE_FACTOR.to_string()));
    }

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

        assert!(matches!(error, BackupOperationError::Consistency),);
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
        mount_whoami(&server, "user-1").await;
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

        assert!(matches!(error, BackupOperationError::InvalidFactorId));
    }

    #[tokio::test]
    async fn removing_a_passkey_as_last_main_factor_deletes_the_backup() {
        install_attestation();
        let server = MockServer::start().await;
        mount_delete_backup(&server).await;
        mount_metadata(
            &server,
            metadata_keyed(
                vec![turnkey_key(), prf_key("ek")],
                vec![passkey_factor("f-1")],
            ),
        )
        .await;
        mount_users_with_authenticators(&server, &["cred-f-1"]).await;
        mount_whoami(&server, "user-1").await;
        mount_delete_authenticators(&server, "auth-cred-f-1").await;
        mount_delete_factor(&server, json!({ "backupDeleted": true })).await;
        mount_delete_sub_org(&server).await;
        let main = signer();

        let outcome = run_remove(&server, "f-1", Some(&main), true).await.unwrap();

        assert!(matches!(outcome, RemoveFactorOutcome::BackupDeleted));
        assert!(called_paths(&server)
            .await
            .contains(&DELETE_SUB_ORG.to_string()),);
    }

    #[tokio::test]
    async fn ec_keypair_cannot_be_the_last_main_factor_removal() {
        install_attestation();
        let server = MockServer::start().await;
        mount_delete_backup(&server).await;
        mount_metadata(
            &server,
            metadata_keyed(vec![prf_key("ek")], vec![eckeypair_factor("ec-1")]),
        )
        .await;

        // Confirmed, which is what makes the ordering load-bearing.
        let error = run_remove(&server, "ec-1", None, true).await.unwrap_err();

        assert!(
            matches!(error, BackupOperationError::Unsupported { .. }),
            "got {error:?}"
        );
        let paths = called_paths(&server).await;
        assert!(!paths.contains(&DELETE_BACKUP.to_string()));
        assert!(!paths.contains(&DELETE_FACTOR.to_string()));
    }

    #[tokio::test]
    async fn authenticator_lookup_surfaces_an_invalid_sync_factor_as_reauth() {
        install_attestation();
        let server = MockServer::start().await;
        mount_metadata(
            &server,
            // One passkey plus an OIDC factor: a supported, non-last-factor removal.
            metadata_keyed(
                vec![turnkey_key(), prf_key("ek")],
                vec![passkey_factor("pk-1"), oidc_factor("f-1", "p-1")],
            ),
        )
        .await;
        Mock::given(method("POST"))
            .and(path(LIST_USERS))
            .respond_with(
                ResponseTemplate::new(403).set_body_string("PUBLIC_KEY_NOT_FOUND"),
            )
            .mount(&server)
            .await;

        let error = run_remove(&server, "pk-1", None, false).await.unwrap_err();

        assert!(matches!(
            error,
            BackupOperationError::NeedsReauth {
                reason: NeedsReauthReason::SyncFactorInvalid
            }
        ));
    }

    #[tokio::test]
    async fn a_degraded_authenticator_lookup_aborts_before_committing() {
        install_attestation();
        let server = MockServer::start().await;
        mount_metadata(
            &server,
            metadata_keyed(
                vec![turnkey_key(), prf_key("ek")],
                vec![passkey_factor("pk-1"), oidc_factor("f-1", "p-1")],
            ),
        )
        .await;
        Mock::given(method("POST"))
            .and(path(LIST_USERS))
            .respond_with(ResponseTemplate::new(503))
            .mount(&server)
            .await;
        mount_delete_factor(
            &server,
            json!({ "backupDeleted": false, "backupMetadata": metadata_keyed(vec![turnkey_key()], vec![oidc_factor("f-1", "p-1")]) }),
        )
        .await;

        let error = run_remove(&server, "pk-1", None, false).await.unwrap_err();

        assert!(matches!(
            error,
            BackupOperationError::Network { retryable: true }
        ));
        let paths = called_paths(&server).await;
        assert!(
            !paths.contains(&DELETE_FACTOR.to_string()),
            "nothing may be committed while the plan is incomplete"
        );
        assert!(!paths.contains(&DELETE_AUTHENTICATORS.to_string()));
    }
}
