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

    /// Reads the metadata, deletes the backup, then reclaims Turnkey
    async fn run(&self, ctx: &FlowContext<'_>) -> Result<(), BackupOperationError> {
        let suborg_id = match ctx.service.retrieve_metadata(ctx.sync_factor).await {
            Ok(metadata) => turnkey_suborg_id(&metadata),
            Err(error) if is_already_gone(&error) => {
                crate::warn!("delete_backup.nothing_to_delete (no backup reachable)");
                return Ok(());
            }
            // Aborting keeps the sub-organization reachable on a retry
            Err(error) => return Err(error),
        };

        // backup-service is authoritative, deleted first
        match ctx.service.delete_backup(ctx.sync_factor).await {
            Ok(()) => crate::info!("delete_backup.deleted"),
            Err(error) if is_already_gone(&error) => {
                // Logged as error because this shouldn't happen under normal circumstances
                crate::error!("delete_backup.raced_with_concurrent_deletion");
            }
            Err(error) => return Err(error),
        }

        if let Some(suborg_id) = suborg_id {
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

/// Whether the rejection means there is no backup left to delete, which is the end
/// state this flow exists to reach. Reported as success.
fn is_already_gone(error: &BackupOperationError) -> bool {
    // TODO: migrate to typed errors (from backup-service)
    matches!(error, BackupOperationError::BackupService { code }
        if matches!(
            code.as_str(),
                "backup_missing"
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
            "backup_untraceable",
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
        mount_rejection(&server, DELETE_BACKUP, "backup_untraceable").await;
        mount_delete_sub_org(&server, completed_sub_org_teardown()).await;

        run_delete(&server).await.unwrap();

        assert!(called_paths(&server)
            .await
            .contains(&DELETE_SUB_ORG.to_string()));
    }
}
