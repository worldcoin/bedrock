//! BF-7 (remove a main factor: an OIDC account or a passkey), escalating to BF-8
//! (delete the whole backup) when the removed factor is the last main factor.

use std::time::Duration;

use async_trait::async_trait;

use super::{BackupFlow, FlowContext};
use crate::backup::backup_service::{
    BackupEncryptionKey, BackupFactorKind, BackupMetadata, DeleteFactorResponse,
};
use crate::backup::turnkey::{TurnkeyApiClient, TurnkeyApiError};
use crate::backup::{BackupOperationError, MainFactor, NeedsReauthReason, SyncFactor};
use crate::primitives::P256Signer;

/// Deadline for a single Turnkey pre-flight probe
const PROBE_TIMEOUT: Duration = Duration::from_secs(10);

/// Deadline for the post-commit Turnkey cleanup. Expiring here orphans a Turnkey
/// resource but cannot change the outcome, which the service has already applied.
#[cfg(not(test))]
const CLEANUP_TIMEOUT: Duration = Duration::from_secs(10);
/// Shortened under test so the expiry path is exercised without a real 10s wait.
#[cfg(test)]
const CLEANUP_TIMEOUT: Duration = Duration::from_millis(200);

/// How many times the provider teardown re-reads and resubmits when the identity's
/// provider set changes underneath it.
const PROVIDER_TEARDOWN_ATTEMPTS: u32 = 3;

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

    /// Runs in two phases, split at the irreversible backup-service delete.
    ///
    /// Everything before the commit is cancel-safe, so it carries the deadline.
    /// Everything from the commit on does not: a deadline there would discard an
    /// outcome the service has already applied, leaving the caller with a retryable
    /// error for work that succeeded. The commit bounds itself with per-request
    /// timeouts instead, and the cleanup after it carries its own.
    async fn run(
        &self,
        ctx: &FlowContext<'_>,
    ) -> Result<RemoveFactorOutcome, BackupOperationError> {
        let prepared = self.prepare(ctx).await?;
        self.commit(ctx, prepared).await
    }
}

/// What the cancel-safe phase resolved, ready for the commit.
enum Prepared {
    /// An OIDC removal, with the providers to tear down afterwards (`None` when the
    /// whole sub-organization goes instead).
    Oidc {
        plan: OidcRemovalPlan,
        provider_ids: Option<Vec<String>>,
    },
    /// A passkey removal: the PRF key to drop, plus the Turnkey authenticator
    /// backing it when the backup has a Turnkey account.
    Passkey {
        prf_key: BackupEncryptionKey,
        authenticator: Option<PasskeyAuthenticator>,
    },
}

impl RemoveFactor {
    /// Reads state and validates every precondition that is knowable in advance.
    ///
    /// Cancel-safe: performs no writes, so abandoning it costs only the reads.
    async fn prepare(
        &self,
        ctx: &FlowContext<'_>,
    ) -> Result<Prepared, BackupOperationError> {
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
                self.prepare_oidc(ctx, &metadata).await
            }
            BackupFactorKind::Passkey { credential_id, .. } => {
                let prf_key = metadata.single_prf_key().cloned().ok_or_else(|| {
                    crate::warn!("remove_factor.missing_prf_key");
                    BackupOperationError::Unsupported {
                        detail: "the passkey has no PRF encryption key to drop"
                            .to_string(),
                    }
                })?;
                let authenticator = self
                    .prepare_authenticator(ctx, &metadata, credential_id)
                    .await?;
                Ok(Prepared::Passkey {
                    prf_key,
                    authenticator,
                })
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

    /// Probes Turnkey so the teardown failures that are knowable in advance surface
    /// while retrying is still safe.
    ///
    /// A transient failure is fatal only on the provider path, which needs the read's
    /// data (deleting just the id we were handed would orphan sibling audiences); the
    /// last-OIDC path needs only its verdict.
    async fn prepare_oidc(
        &self,
        ctx: &FlowContext<'_>,
        metadata: &BackupMetadata,
    ) -> Result<Prepared, BackupOperationError> {
        let plan = plan_oidc_removal(metadata, &self.factor_id)?;

        let provider_ids = if plan.is_last_oidc_factor {
            verify_sync_factor(ctx, &plan).await?;
            None
        } else if let Some(main_factor) = ctx.main_factor {
            verify_main_factor(ctx, &plan.suborg_id, &plan.user_id, main_factor)
                .await?;
            Some(provider_ids_for_identity(ctx, &plan, false).await?)
        } else {
            // Deleting an OAuth provider requires a [`MainFactor`]
            crate::debug!("remove_factor.needs_main_factor");
            return Err(BackupOperationError::NeedsReauth {
                reason: NeedsReauthReason::MainFactorRequired,
            });
        };

        Ok(Prepared::Oidc { plan, provider_ids })
    }

    /// Resolves the Turnkey authenticator registered for `credential_id`, if any to
    /// remove also from Turnkey.
    ///
    /// # Errors
    /// [`NeedsReauthReason::MainFactorRequired`] when the authenticator exists but no
    /// main factor was supplied: authenticators live on the root user, so deleting one
    /// needs the same signer an OAuth provider deletion does.
    async fn prepare_authenticator(
        &self,
        ctx: &FlowContext<'_>,
        metadata: &BackupMetadata,
        credential_id: &str,
    ) -> Result<Option<PasskeyAuthenticator>, BackupOperationError> {
        // No Turnkey account: the passkey was never registered there.
        let Some(BackupEncryptionKey::Turnkey {
            turnkey_account_id,
            turnkey_user_id,
            ..
        }) = metadata.turnkey_key()
        else {
            return Ok(None);
        };

        let probe = ctx
            .turnkey
            .get_users(turnkey_account_id, SyncFactor(ctx.sync_factor));
        let Ok(result) = tokio::time::timeout(PROBE_TIMEOUT, probe).await else {
            crate::warn!(
                "remove_factor.authenticator_lookup_timed_out (Turnkey unresponsive; skipping)"
            );
            return Ok(None);
        };
        let users = match result {
            Ok(users) => users,
            // Best-effort, like the teardown it feeds: a degraded Turnkey must not
            // block dropping the factor at the authoritative store.
            Err(error) if error.is_retryable() => {
                crate::warn!(
                    "remove_factor.authenticator_lookup_inconclusive code={} err={error}",
                    error.code()
                );
                return Ok(None);
            }
            Err(error) => return Err(map_turnkey_error(&error)),
        };

        let Some(authenticator_id) = users
            .iter()
            .find(|user| user.user_id == *turnkey_user_id)
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
            crate::debug!("remove_factor.authenticator_needs_main_factor");
            return Err(BackupOperationError::NeedsReauth {
                reason: NeedsReauthReason::MainFactorRequired,
            });
        };
        verify_main_factor(ctx, turnkey_account_id, turnkey_user_id, main_factor)
            .await?;

        Ok(Some(PasskeyAuthenticator {
            suborg: turnkey_account_id.clone(),
            user: turnkey_user_id.clone(),
            id: authenticator_id,
        }))
    }

    /// Applies the removal at the authoritative store, then cleans up Turnkey.
    ///
    /// Deliberately not wrapped in a cancelling deadline: past the delete the outcome
    /// is decided, and dropping this future would report a failure for it.
    async fn commit(
        &self,
        ctx: &FlowContext<'_>,
        prepared: Prepared,
    ) -> Result<RemoveFactorOutcome, BackupOperationError> {
        let mut passkey_authenticator = None;
        let (encryption_key, oidc) = match prepared {
            Prepared::Oidc { plan, provider_ids } => (
                plan.is_last_oidc_factor.then(|| plan.turnkey_key.clone()),
                Some((plan, provider_ids)),
            ),
            Prepared::Passkey {
                prf_key,
                authenticator,
            } => {
                passkey_authenticator = authenticator;
                (Some(prf_key), None)
            }
        };

        // backup-service is authoritative, drop first
        let response = ctx
            .service
            .delete_factor(ctx.sync_factor, &self.factor_id, encryption_key)
            .await?;

        if let Some((plan, provider_ids)) = oidc {
            best_effort_turnkey_cleanup(ctx, &plan, provider_ids).await;
        } else if let (Some(authenticator), Some(main_factor)) =
            (passkey_authenticator, ctx.main_factor)
        {
            best_effort_delete_authenticator(ctx, &authenticator, main_factor).await;
        }

        finalize(response, self.user_confirmed_backup_removal)
    }
}

/// Tears down whatever Turnkey resources the removal orphaned, under its own deadline.
///
/// Best-effort on both counts: the factor is already gone from the authoritative
/// store, so neither a failure nor a timeout can change what the caller is told. It
/// carries a deadline anyway so a wedged Turnkey cannot hold a foreground call open,
/// and reports the orphan at `critical!` because nothing reclaims it yet (TODO in
/// `turnkey::migrations`).
async fn best_effort_turnkey_cleanup(
    ctx: &FlowContext<'_>,
    plan: &OidcRemovalPlan,
    provider_ids: Option<Vec<String>>,
) {
    let cleanup = async {
        if plan.is_last_oidc_factor {
            best_effort_delete_sub_org(ctx.turnkey, &plan.suborg_id, ctx.sync_factor)
                .await;
        } else if let (Some(main_factor), Some(_)) = (ctx.main_factor, provider_ids) {
            best_effort_delete_providers(ctx, plan, main_factor).await;
        }
    };

    if tokio::time::timeout(CLEANUP_TIMEOUT, cleanup)
        .await
        .is_err()
    {
        crate::critical!(
            "remove_factor.turnkey_cleanup_timed_out suborg_id={} after {}s (factor IS removed; Turnkey resources orphaned)",
            plan.suborg_id,
            CLEANUP_TIMEOUT.as_secs()
        );
    }
}

/// The Turnkey authenticator backing a passkey factor.
struct PasskeyAuthenticator {
    suborg: String,
    user: String,
    id: String,
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
        // An OIDC factor with no Turnkey key: the remote account is internally
        // inconsistent and no removal can proceed until someone looks at it.
        crate::critical!(
            "remove_factor.missing_turnkey_key (OIDC factor present with no Turnkey key)"
        );
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
        crate::critical!("remove_factor.turnkey_key_wrong_kind");
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
    let probe = ctx
        .turnkey
        .get_users(&plan.suborg_id, SyncFactor(ctx.sync_factor));
    let Ok(result) = tokio::time::timeout(PROBE_TIMEOUT, probe).await else {
        crate::warn!(
            "remove_factor.preflight_timed_out after {}s (Turnkey unresponsive; proceeding)",
            PROBE_TIMEOUT.as_secs()
        );
        return Ok(());
    };

    match result {
        Ok(_) => Ok(()),
        Err(error) if error.indicates_invalid_signer() => {
            crate::warn!("remove_factor.sync_factor_invalid (pre-flight)");
            Err(BackupOperationError::NeedsReauth {
                reason: NeedsReauthReason::SyncFactorInvalid,
            })
        }
        // Only a retryable service outage is tolerated. A signer that cannot stamp,
        // or any other permanent failure, will fail the teardown the same way every
        // time, so it aborts here while retrying is still free.
        Err(error) if error.is_retryable() => {
            crate::warn!(
                "remove_factor.preflight_inconclusive code={} err={error} (Turnkey degraded; proceeding)",
                error.code()
            );
            Ok(())
        }
        Err(error) => {
            crate::warn!(
                "remove_factor.preflight_failed code={} err={error}",
                error.code()
            );
            Err(map_turnkey_error(&error))
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
    suborg_id: &str,
    expected_user_id: &str,
    main_factor: &P256Signer,
) -> Result<(), BackupOperationError> {
    let probe = ctx
        .turnkey
        .whoami_user_id(suborg_id, MainFactor(main_factor));
    let Ok(result) = tokio::time::timeout(PROBE_TIMEOUT, probe).await else {
        crate::warn!(
            "remove_factor.main_factor_preflight_timed_out after {}s (proceeding)",
            PROBE_TIMEOUT.as_secs()
        );
        return Ok(());
    };

    let user_id = match result {
        Ok(user_id) => user_id,
        Err(error) if error.indicates_invalid_signer() => {
            crate::warn!("remove_factor.main_factor_invalid (pre-flight)");
            return Err(BackupOperationError::NeedsReauth {
                reason: NeedsReauthReason::MainFactorRequired,
            });
        }
        // Only a retryable service outage is tolerated; see `verify_sync_factor`.
        Err(error) if error.is_retryable() => {
            crate::warn!(
                "remove_factor.main_factor_preflight_inconclusive code={} err={error}",
                error.code()
            );
            return Ok(());
        }
        Err(error) => {
            crate::warn!(
                "remove_factor.main_factor_preflight_failed code={} err={error}",
                error.code()
            );
            return Err(map_turnkey_error(&error));
        }
    };

    if user_id != expected_user_id {
        // A valid Turnkey key, but not the root user that owns the OAuth providers --
        // the user completed the ceremony with the wrong passkey.
        crate::warn!(
            "remove_factor.main_factor_wrong_user expected={expected_user_id} got={user_id}"
        );
        return Err(BackupOperationError::NeedsReauth {
            reason: NeedsReauthReason::MainFactorRequired,
        });
    }
    Ok(())
}

/// Removes the passkey's Turnkey authenticator, under the cleanup deadline.
///
/// Best-effort for the same reason as the OIDC teardown: the factor is already gone
/// from the authoritative store, so nothing here can change what the caller is told.
async fn best_effort_delete_authenticator(
    ctx: &FlowContext<'_>,
    authenticator: &PasskeyAuthenticator,
    main_factor: &P256Signer,
) {
    let delete = ctx.turnkey.delete_authenticators(
        &authenticator.suborg,
        &authenticator.user,
        vec![authenticator.id.clone()],
        MainFactor(main_factor),
    );

    match tokio::time::timeout(CLEANUP_TIMEOUT, delete).await {
        Ok(Ok(())) => {}
        Ok(Err(error @ TurnkeyApiError::ActivityPollingExceeded { .. })) => {
            crate::warn!("remove_factor.authenticator_teardown_pending err={error}");
        }
        Ok(Err(error)) => {
            // The passkey can still authorize Turnkey activities.
            crate::critical!(
                "remove_factor.authenticator_orphaned suborg_id={} code={} err={error}",
                authenticator.suborg,
                error.code()
            );
        }
        Err(_elapsed) => {
            crate::critical!(
                "remove_factor.authenticator_teardown_timed_out suborg_id={}",
                authenticator.suborg
            );
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
    main_factor: &P256Signer,
) {
    for attempt in 1..=PROVIDER_TEARDOWN_ATTEMPTS {
        let provider_ids = match provider_ids_for_identity(ctx, plan, true).await {
            Ok(provider_ids) => provider_ids,
            Err(error) => {
                crate::critical!(
                    "remove_factor.turnkey_provider_orphaned suborg_id={} (could not re-read providers) err={error}",
                    plan.suborg_id
                );
                return;
            }
        };

        if provider_ids.is_empty() {
            crate::debug!("remove_factor.turnkey_providers_already_absent");
            return;
        }

        match ctx
            .turnkey
            .delete_oauth_providers(
                &plan.suborg_id,
                &plan.user_id,
                provider_ids,
                MainFactor(main_factor),
            )
            .await
        {
            Ok(()) => return,
            // The identity's provider set changed between the read and the delete.
            // Re-read and submit the whole set again rather than leave it half-torn.
            Err(error) if error.is_no_matching_provider() => {
                crate::debug!(
                    "remove_factor.turnkey_providers_changed attempt={attempt}"
                );
            }
            Err(error @ TurnkeyApiError::ActivityPollingExceeded { .. }) => {
                crate::warn!(
                    "remove_factor.turnkey_provider_teardown_pending suborg_id={} err={error}",
                    plan.suborg_id
                );
                return;
            }
            Err(error) => {
                // The account the user asked to disconnect can still authorize.
                crate::critical!(
                    "remove_factor.turnkey_provider_orphaned suborg_id={} code={} err={error}",
                    plan.suborg_id,
                    error.code()
                );
                return;
            }
        }
    }

    crate::critical!(
        "remove_factor.turnkey_provider_orphaned suborg_id={} (provider set kept changing across {PROVIDER_TEARDOWN_ATTEMPTS} attempts)",
        plan.suborg_id
    );
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
    fresh: bool,
) -> Result<Vec<String>, BackupOperationError> {
    let signer = SyncFactor(ctx.sync_factor);
    let read = async {
        if fresh {
            ctx.turnkey.get_users_fresh(&plan.suborg_id, signer).await
        } else {
            ctx.turnkey.get_users(&plan.suborg_id, signer).await
        }
    };
    let users = read.await.map_err(|error| map_turnkey_error(&error))?;

    let Some(user) = users.iter().find(|user| user.user_id == plan.user_id) else {
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
    const DELETE_AUTHENTICATORS: &str = "/public/v1/submit/delete_authenticators";

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
    async fn slow_turnkey_cleanup_does_not_erase_the_committed_outcome() {
        install_attestation();
        let server = MockServer::start().await;
        mount_metadata(&server, metadata(vec![oidc_factor("f-1", "p-1")])).await;
        mount_users(&server, vec![]).await;
        mount_delete_factor(&server, json!({ "backupDeleted": true })).await;
        // Teardown hangs well past CLEANUP_TIMEOUT.
        Mock::given(method("POST"))
            .and(path(DELETE_SUB_ORG))
            .respond_with(ResponseTemplate::new(200).set_delay(CLEANUP_TIMEOUT * 20))
            .mount(&server)
            .await;

        let outcome = run_remove(&server, "f-1", None, true).await.unwrap();

        assert!(
            matches!(outcome, RemoveFactorOutcome::BackupDeleted),
            "the committed outcome must survive a timed-out cleanup, got {outcome:?}"
        );
        assert!(called_paths(&server)
            .await
            .contains(&DELETE_FACTOR.to_string()));
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
                    reason: NeedsReauthReason::MainFactorRequired
                }
            ),
            "expected MainFactorRequired, got {error:?}"
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
