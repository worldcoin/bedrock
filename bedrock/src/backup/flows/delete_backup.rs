//! BF-8 (delete the entire backup).

use async_trait::async_trait;

use super::{best_effort_delete_sub_org, BackupFlow, FlowContext, CLEANUP_TIMEOUT};
use crate::backup::backup_service::{BackupEncryptionKey, BackupMetadata};
use crate::backup::BackupOperationError;

/// Deletes the entire backup state from all remotes (backup-service and Turnkey)
/// and the local Bedrock state. Permanent, can't be undone.
pub struct DeleteBackup;

#[async_trait]
impl BackupFlow for DeleteBackup {
    type Output = ();

    /// Reads the metadata, deletes the backup, then deletes the Turnkey account
    async fn run(&self, ctx: &FlowContext<'_>) -> Result<(), BackupOperationError> {
        let captured = match ctx.service.retrieve_metadata(ctx.sync_factor).await {
            Ok(metadata) => Captured {
                backup_id: metadata.id.clone(),
                suborg_id: turnkey_suborg_id(&metadata),
            },
            Err(error) if is_already_gone(&error) => {
                crate::warn!("delete_backup.nothing_to_delete (no backup reachable)");
                return Ok(());
            }
            // Aborting keeps the sub-organization reachable on a retry
            Err(error) => return Err(error),
        };

        // backup-service is authoritative, deleted first
        commit_on_backup_service(ctx, &captured).await?;

        if let Some(suborg_id) = captured.suborg_id {
            let cleanup = best_effort_delete_sub_org(
                "delete_backup",
                ctx.turnkey,
                &suborg_id,
                ctx.sync_factor,
            );
            if tokio::time::timeout(CLEANUP_TIMEOUT, cleanup)
                .await
                .is_err()
            {
                crate::critical!(
                    "delete_backup.turnkey_cleanup_timed_out suborg_id={suborg_id} after {}s (backup IS deleted; sub-organization orphaned)",
                    CLEANUP_TIMEOUT.as_secs()
                );
            }
        }

        Ok(())
    }
}

/// Deletes the backup at the backup service, resolving a lost response rather than
/// reporting a failure for a delete that landed.
async fn commit_on_backup_service(
    ctx: &FlowContext<'_>,
    captured: &Captured,
) -> Result<(), BackupOperationError> {
    match ctx.service.delete_backup(ctx.sync_factor).await {
        Ok(()) => {
            crate::info!("delete_backup.deleted");
            Ok(())
        }
        Err(error) if is_already_gone(&error) => {
            // Logged as error because this shouldn't happen under normal circumstances
            crate::error!("delete_backup.raced_with_concurrent_deletion");
            Ok(())
        }

        Err(error @ BackupOperationError::Network { retryable: true }) => {
            if settle_lost_response(ctx, captured).await {
                Ok(())
            } else {
                Err(error)
            }
        }
        Err(error) => Err(error),
    }
}

/// Asks the service whether the backup is gone, to settle a delete whose response
/// never arrived. Returns whether it in fact committed.
async fn settle_lost_response(ctx: &FlowContext<'_>, captured: &Captured) -> bool {
    match ctx
        .service
        .backup_exists(ctx.sync_factor, &captured.backup_id)
        .await
    {
        Ok(false) => {
            crate::warn!("delete_backup.commit_confirmed_after_lost_response");
            true
        }
        // Either the delete never landed, or this device was revoked and a live backup
        // sits under the same account. Cleaning up after either would be destructive.
        Ok(true) => {
            crate::warn!("delete_backup.commit_did_not_land (backup still exists)");
            false
        }
        Err(error) => {
            if let Some(suborg_id) = &captured.suborg_id {
                crate::critical!(
                    "delete_backup.outcome_unresolved suborg_id={suborg_id} (delete may have committed) err={error:?}"
                );
            } else {
                crate::warn!("delete_backup.outcome_unresolved err={error:?}");
            }
            false
        }
    }
}

/// The ids read before the delete, which destroys the metadata holding them.
struct Captured {
    /// Qualifies the reconciliation read so an absence is unambiguous.
    backup_id: String,
    /// The Turnkey sub-organization to reclaim, if the backup had one.
    suborg_id: Option<String>,
}

/// The sub-organization holding the backup's Turnkey encryption key, if it has one.
fn turnkey_suborg_id(metadata: &BackupMetadata) -> Option<String> {
    // `None` covers both no Turnkey key and several of them: nothing safe to tear down either way.
    match metadata.turnkey_key()? {
        BackupEncryptionKey::Turnkey {
            turnkey_account_id, ..
        } => Some(turnkey_account_id.clone()),
        BackupEncryptionKey::Prf { .. } | BackupEncryptionKey::Icloud { .. } => None,
    }
}

fn is_already_gone(error: &BackupOperationError) -> bool {
    // TODO: migrate to typed errors (from backup-service)
    matches!(error, BackupOperationError::BackupService { code }
        if matches!(
            code.as_str(),
                "backup_untraceable"
                | "backup_missing"
                | "backup_not_found"
                | "backup_does_not_exist"
        )
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backup::backup_service::BackupServiceClient;
    use crate::backup::turnkey::test::TestSigner;
    use crate::backup::turnkey::TurnkeyApiClient;
    use crate::backup::NeedsReauthReason;
    use crate::primitives::P256Signer;
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;
    use serde_json::{json, Value};
    use std::sync::Arc;
    use std::time::Duration;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    const RETRIEVE_META_CHALLENGE: &str = "/v1/retrieve-metadata/challenge/keypair";
    const RETRIEVE_META: &str = "/v1/retrieve-metadata";
    const DELETE_BACKUP_CHALLENGE: &str = "/v1/delete-backup/challenge/keypair";
    const DELETE_BACKUP: &str = "/v1/delete-backup";
    const DELETE_SUB_ORG: &str = "/public/v1/submit/delete_sub_organization";

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

    fn metadata(keys: Vec<Value>) -> Value {
        let mut meta = json!({
            "id": "backup-1",
            "manifestHash": "abcd",
            "factors": [],
            "syncFactors": [],
        });
        meta["keys"] = Value::Array(keys);
        meta
    }

    async fn mount(server: &MockServer, endpoint: &str, response: ResponseTemplate) {
        Mock::given(method("POST"))
            .and(path(endpoint))
            .respond_with(response)
            .mount(server)
            .await;
    }

    async fn mount_json(server: &MockServer, endpoint: &str, body: Value) {
        mount(
            server,
            endpoint,
            ResponseTemplate::new(200).set_body_json(body),
        )
        .await;
    }

    /// A `400` carrying the backup service's machine-readable `code`.
    async fn mount_rejection(server: &MockServer, endpoint: &str, code: &str) {
        mount(
            server,
            endpoint,
            ResponseTemplate::new(400)
                .set_body_json(json!({ "error": { "code": code, "message": "m" } })),
        )
        .await;
    }

    /// Metadata answers once, then rejects with `code` -- the initial read followed
    /// by the reconciliation read.
    async fn mount_metadata_then(server: &MockServer, keys: Vec<Value>, code: &str) {
        mount_json(server, RETRIEVE_META_CHALLENGE, challenge_response()).await;
        Mock::given(method("POST"))
            .and(path(RETRIEVE_META))
            .respond_with(ResponseTemplate::new(200).set_body_json(metadata(keys)))
            .up_to_n_times(1)
            .mount(server)
            .await;
        mount_rejection(server, RETRIEVE_META, code).await;
    }

    /// The parsed bodies of every metadata request, in order.
    async fn metadata_bodies(server: &MockServer) -> Vec<Value> {
        server
            .received_requests()
            .await
            .unwrap()
            .iter()
            .filter(|request| request.url.path() == RETRIEVE_META)
            .map(|request| serde_json::from_slice(&request.body).unwrap())
            .collect()
    }

    async fn mount_metadata(server: &MockServer, keys: Vec<Value>) {
        mount_json(server, RETRIEVE_META_CHALLENGE, challenge_response()).await;
        mount_json(server, RETRIEVE_META, metadata(keys)).await;
    }

    /// The delete endpoint answers `204 No Content`, with no body to parse.
    async fn mount_delete_backup(server: &MockServer) {
        mount_json(server, DELETE_BACKUP_CHALLENGE, challenge_response()).await;
        mount(server, DELETE_BACKUP, ResponseTemplate::new(204)).await;
    }

    async fn mount_delete_sub_org(server: &MockServer, response: ResponseTemplate) {
        mount(server, DELETE_SUB_ORG, response).await;
    }

    fn completed_sub_org_teardown() -> ResponseTemplate {
        ResponseTemplate::new(200).set_body_json(json!({
            "activity": {
                "id": "act-1",
                "organizationId": "suborg-1",
                "status": "ACTIVITY_STATUS_COMPLETED",
                "type": "ACTIVITY_TYPE_DELETE_SUB_ORGANIZATION",
                "fingerprint": "fp-1",
                "result": {
                    "deleteSubOrganizationResult": { "subOrganizationUuid": "suborg-1" }
                },
            }
        }))
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

    async fn run_delete(server: &MockServer) -> Result<(), BackupOperationError> {
        let service =
            BackupServiceClient::with_base_url_for_test(server.uri()).unwrap();
        let turnkey = TurnkeyApiClient::with_base_url(server.uri());
        let sync = signer();
        let ctx = FlowContext {
            service: &service,
            turnkey: &turnkey,
            sync_factor: &sync,
            main_factor: None,
        };
        DeleteBackup.run(&ctx).await
    }

    #[tokio::test]
    async fn test_happy_path_deletes_the_backup_then_tears_down_the_sub_organization() {
        let server = MockServer::start().await;
        mount_metadata(&server, vec![turnkey_key()]).await;
        mount_delete_backup(&server).await;
        mount_delete_sub_org(&server, completed_sub_org_teardown()).await;

        run_delete(&server).await.unwrap();

        let paths = called_paths(&server).await;
        let delete = paths.iter().position(|p| p == DELETE_BACKUP).unwrap();
        let teardown = paths.iter().position(|p| p == DELETE_SUB_ORG).unwrap();
        assert!(delete < teardown, "the backup must be deleted first");
    }

    /// A PRF-only backup has no Turnkey account, so no call to Turnkey
    #[tokio::test]
    async fn a_backup_without_a_turnkey_key_skips_the_teardown() {
        let server = MockServer::start().await;
        mount_metadata(
            &server,
            vec![json!({ "kind": "PRF", "encryptedKey": "ek" })],
        )
        .await;
        mount_delete_backup(&server).await;

        run_delete(&server).await.unwrap();

        assert!(!called_paths(&server)
            .await
            .contains(&DELETE_SUB_ORG.to_string()));
    }

    #[tokio::test]
    async fn an_already_deleted_backup_is_reported_as_success() {
        for code in [
            "backup_missing",
            "backup_not_found",
            "backup_does_not_exist",
        ] {
            let server = MockServer::start().await;
            mount_json(&server, RETRIEVE_META_CHALLENGE, challenge_response()).await;
            mount_rejection(&server, RETRIEVE_META, code).await;

            run_delete(&server).await.unwrap_or_else(|error| {
                panic!("{code} must be treated as already deleted, got {error:?}")
            });

            assert!(
                !called_paths(&server)
                    .await
                    .contains(&DELETE_BACKUP.to_string()),
                "{code} means there is nothing to delete"
            );
        }
    }

    /// The metadata read is the only source of the sub-organization id. Committing
    /// the delete without it would orphan the sub-organization permanently
    #[tokio::test]
    async fn a_failed_metadata_read_aborts_before_the_delete() {
        let server = MockServer::start().await;
        mount_json(&server, RETRIEVE_META_CHALLENGE, challenge_response()).await;
        mount(&server, RETRIEVE_META, ResponseTemplate::new(503)).await;

        let error = run_delete(&server).await.unwrap_err();

        assert!(matches!(
            error,
            BackupOperationError::Network { retryable: true }
        ));
        assert!(!called_paths(&server)
            .await
            .contains(&DELETE_BACKUP.to_string()));
    }

    #[tokio::test]
    async fn an_unauthorized_sync_factor_surfaces_as_needs_reauth() {
        let server = MockServer::start().await;
        mount_json(&server, RETRIEVE_META_CHALLENGE, challenge_response()).await;
        mount_rejection(&server, RETRIEVE_META, "unauthorized_factor").await;

        let error = run_delete(&server).await.unwrap_err();

        assert!(matches!(
            error,
            BackupOperationError::NeedsReauth {
                reason: NeedsReauthReason::SyncFactorInvalid
            }
        ));
        assert!(!called_paths(&server)
            .await
            .contains(&DELETE_BACKUP.to_string()));
    }

    #[tokio::test]
    async fn a_failed_turnkey_teardown_does_not_fail_the_deletion() {
        let server = MockServer::start().await;
        mount_metadata(&server, vec![turnkey_key()]).await;
        mount_delete_backup(&server).await;
        mount_delete_sub_org(&server, ResponseTemplate::new(500)).await;

        run_delete(&server).await.unwrap();

        assert!(called_paths(&server)
            .await
            .contains(&DELETE_SUB_ORG.to_string()));
    }

    #[tokio::test]
    async fn test_turnkey_timeout_does_not_hang_forever() {
        let server = MockServer::start().await;
        mount_metadata(&server, vec![turnkey_key()]).await;
        mount_delete_backup(&server).await;
        mount_delete_sub_org(
            &server,
            completed_sub_org_teardown().set_delay(Duration::from_secs(30)),
        )
        .await;

        let started = std::time::Instant::now();
        run_delete(&server).await.unwrap();

        assert!(
            started.elapsed() < Duration::from_secs(5),
            "the teardown must be abandoned at CLEANUP_TIMEOUT, took {:?}",
            started.elapsed()
        );
    }

    #[tokio::test]
    async fn a_raced_deletion_still_clears_turnkey() {
        let server = MockServer::start().await;
        mount_metadata(&server, vec![turnkey_key()]).await;
        mount_json(&server, DELETE_BACKUP_CHALLENGE, challenge_response()).await;
        mount_rejection(&server, DELETE_BACKUP, "backup_not_found").await;
        mount_delete_sub_org(&server, completed_sub_org_teardown()).await;

        run_delete(&server).await.unwrap();

        assert!(called_paths(&server)
            .await
            .contains(&DELETE_SUB_ORG.to_string()));
    }

    #[tokio::test]
    async fn a_lost_response_is_settled_as_committed() {
        let server = MockServer::start().await;
        mount_metadata_then(&server, vec![turnkey_key()], "backup_does_not_exist")
            .await;
        mount_json(&server, DELETE_BACKUP_CHALLENGE, challenge_response()).await;
        mount(&server, DELETE_BACKUP, ResponseTemplate::new(503)).await;
        mount_delete_sub_org(&server, completed_sub_org_teardown()).await;

        run_delete(&server)
            .await
            .expect("a committed delete is a success");

        assert!(
            called_paths(&server)
                .await
                .contains(&DELETE_SUB_ORG.to_string()),
            "the captured sub-organization must still be reclaimed"
        );
    }

    #[tokio::test]
    async fn a_delete_that_did_not_land_stays_retryable() {
        let server = MockServer::start().await;
        mount_metadata(&server, vec![turnkey_key()]).await;
        mount_json(&server, DELETE_BACKUP_CHALLENGE, challenge_response()).await;
        mount(&server, DELETE_BACKUP, ResponseTemplate::new(503)).await;
        mount_delete_sub_org(&server, completed_sub_org_teardown()).await;

        let error = run_delete(&server).await.unwrap_err();

        assert!(matches!(
            error,
            BackupOperationError::Network { retryable: true }
        ));
        assert!(
            !called_paths(&server)
                .await
                .contains(&DELETE_SUB_ORG.to_string()),
            "Turnkey must survive a backup that may still exist"
        );
    }

    #[tokio::test]
    async fn a_revoked_device_cannot_tear_down_a_live_backup() {
        let server = MockServer::start().await;
        mount_metadata_then(&server, vec![turnkey_key()], "unauthorized_factor").await;
        mount_json(&server, DELETE_BACKUP_CHALLENGE, challenge_response()).await;
        mount(&server, DELETE_BACKUP, ResponseTemplate::new(503)).await;
        mount_delete_sub_org(&server, completed_sub_org_teardown()).await;

        let error = run_delete(&server).await.unwrap_err();

        assert!(matches!(
            error,
            BackupOperationError::Network { retryable: true }
        ));
        assert!(
            !called_paths(&server)
                .await
                .contains(&DELETE_SUB_ORG.to_string()),
            "the live backup's sub-organization must survive"
        );
    }
}
