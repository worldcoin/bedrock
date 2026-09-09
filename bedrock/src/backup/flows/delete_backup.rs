//! BF-8 (delete the entire backup).

use async_trait::async_trait;

use crate::backup::flows::{BackupFlow, FlowContext};
use crate::backup::turnkey::{TurnkeyApiClient, TurnkeyApiError};
use crate::backup::{
    BackupEncryptionKey, BackupMetadata, BackupOperationError, SyncFactor,
};
use crate::primitives::retry::{retry_with_backoff, RetryError, RetryPolicy};
use crate::primitives::P256Signer;
use std::collections::BTreeSet;
use std::time::Duration;

/// Deletes the entire backup state from all remotes (backup-service and Turnkey)
/// and the local Bedrock state. Permanent, can't be undone.
pub struct DeleteBackup;

#[async_trait]
impl BackupFlow for DeleteBackup {
    type Output = ();

    /// Reads the metadata, deletes the backup, then deletes the Turnkey account
    async fn run(&self, ctx: &FlowContext<'_>) -> Result<(), BackupOperationError> {
        let metadata = match ctx
            .service
            .retrieve_metadata(ctx.sync_factor, ctx.backup_id)
            .await
        {
            Ok(metadata) => metadata,
            Err(e) => {
                if let BackupOperationError::BackupService { code } = &e {
                    if code == "backup_does_not_exist" {
                        crate::warn!(
                            "delete_backup.nothing_to_delete (backup already gone)"
                        );
                        return Ok(());
                    }
                }
                return Err(e);
            }
        };

        delete_from_metadata(ctx, metadata).await
    }
}

/// Deletes the backup using metadata already read during preflight.
pub(super) async fn delete_from_metadata(
    ctx: &FlowContext<'_>,
    metadata: BackupMetadata,
) -> Result<(), BackupOperationError> {
    let suborg_ids = metadata
        .keys
        .into_iter()
        .filter_map(|key| {
            if let BackupEncryptionKey::Turnkey {
                turnkey_account_id, ..
            } = key
            {
                Some(turnkey_account_id)
            } else {
                None
            }
        })
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    let policy = RetryPolicy {
        total_timeout: Duration::from_secs(45),
        ..Default::default()
    };

    let result = retry_with_backoff(
        &policy,
        "delete_backup",
        |error| matches!(error, BackupOperationError::Network { retryable: true }),
        || ctx.service.delete_backup(ctx.sync_factor),
    )
    .await
    .map_err(|e| match e {
        RetryError::Timeout => BackupOperationError::Timeout,
        RetryError::Operation(e) => e,
    });
    if let Err(error) = result {
        // A previous attempt may have committed before its response was lost.
        match error {
            BackupOperationError::BackupService { code }
                if code == "backup_does_not_exist" => {}
            error => return Err(error),
        }
    }

    delete_turnkey_account(ctx.turnkey, suborg_ids, ctx.sync_factor).await;
    Ok(())
}

/// Tears down each distinct Turnkey sub-organization (best-effort).
pub(in crate::backup::flows) async fn delete_turnkey_account(
    turnkey: &TurnkeyApiClient,
    suborg_ids: Vec<String>,
    sync_factor: &P256Signer,
) {
    for suborg_id in suborg_ids {
        if let Err(error) = turnkey
            .delete_sub_organization(&suborg_id, SyncFactor(sync_factor))
            .await
        {
            if matches!(error, TurnkeyApiError::ActivityPollingExceeded { .. }) {
                crate::warn!(
                    suborg_id = suborg_id,
                    error_message = error,
                    "turnkey_suborg_teardown_pending"
                );
                continue;
            }
            crate::critical!(
                suborg_id = suborg_id,
                code = error.code(),
                error_message = error,
                "turnkey_suborg could not be deleted"
            );
        }
    }
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
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    const RETRIEVE_META_CHALLENGE: &str = "/v1/retrieve-metadata/challenge/keypair";
    const RETRIEVE_META: &str = "/v1/retrieve-metadata";
    const DELETE_BACKUP_CHALLENGE: &str = "/v1/delete-backup/challenge/keypair";
    const DELETE_BACKUP: &str = "/v1/delete-backup";
    const DELETE_SUB_ORG: &str = "/public/v1/submit/delete_sub_organization";
    const TEST_BACKUP_ID: &str = "backup-1";

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
            backup_id: TEST_BACKUP_ID,
            main_factor: None,
        };
        DeleteBackup.run(&ctx).await
    }

    #[tokio::test]
    async fn deletes_the_backup_then_tears_down_the_sub_organization() {
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
        let server = MockServer::start().await;
        mount_json(&server, RETRIEVE_META_CHALLENGE, challenge_response()).await;
        mount_rejection(&server, RETRIEVE_META, "backup_does_not_exist").await;

        run_delete(&server)
            .await
            .expect("an already-deleted backup is a success");

        assert!(!called_paths(&server)
            .await
            .contains(&DELETE_BACKUP.to_string()));
    }

    #[tokio::test]
    async fn mismatched_metadata_aborts_before_any_deletion() {
        let server = MockServer::start().await;
        mount_json(&server, RETRIEVE_META_CHALLENGE, challenge_response()).await;
        let mut response = metadata(vec![turnkey_key()]);
        response["id"] = json!("another-backup");
        mount_json(&server, RETRIEVE_META, response).await;

        let error = run_delete(&server).await.unwrap_err();

        assert!(matches!(error, BackupOperationError::Consistency));
        assert_eq!(
            called_paths(&server).await,
            [RETRIEVE_META_CHALLENGE, RETRIEVE_META]
        );
    }

    #[tokio::test]
    async fn an_already_gone_backup_during_commit_still_tears_down_turnkey() {
        for endpoint in [DELETE_BACKUP_CHALLENGE, DELETE_BACKUP] {
            let server = MockServer::start().await;
            mount_metadata(&server, vec![turnkey_key()]).await;
            mount_rejection(&server, endpoint, "backup_does_not_exist").await;
            mount_delete_backup(&server).await;
            mount_delete_sub_org(&server, completed_sub_org_teardown()).await;

            run_delete(&server).await.unwrap();

            assert!(called_paths(&server)
                .await
                .contains(&DELETE_SUB_ORG.to_string()));
        }
    }

    #[tokio::test]
    async fn a_lost_delete_response_then_missing_backup_is_success() {
        let server = MockServer::start().await;
        mount_metadata(&server, vec![turnkey_key()]).await;
        Mock::given(method("POST"))
            .and(path(DELETE_BACKUP_CHALLENGE))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(challenge_response()),
            )
            .up_to_n_times(1)
            .mount(&server)
            .await;
        mount_rejection(&server, DELETE_BACKUP_CHALLENGE, "backup_does_not_exist")
            .await;
        // A gateway can fail the response after the service commits the delete.
        mount(&server, DELETE_BACKUP, ResponseTemplate::new(502)).await;
        mount_delete_sub_org(&server, completed_sub_org_teardown()).await;

        run_delete(&server).await.unwrap();

        let paths = called_paths(&server).await;
        assert_eq!(paths.iter().filter(|p| *p == DELETE_BACKUP).count(), 1);
        assert_eq!(
            paths
                .iter()
                .filter(|p| *p == DELETE_BACKUP_CHALLENGE)
                .count(),
            2
        );
        assert_eq!(paths.iter().filter(|p| *p == DELETE_SUB_ORG).count(), 1);
    }

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
    async fn a_turnkey_deadline_preserves_the_committed_deletion() {
        let server = Arc::new(MockServer::start().await);
        mount_metadata(&server, vec![turnkey_key()]).await;
        mount_delete_backup(&server).await;
        mount_delete_sub_org(
            &server,
            completed_sub_org_teardown().set_delay(Duration::from_secs(60)),
        )
        .await;
        let deletion = tokio::spawn({
            let server = Arc::clone(&server);
            async move { run_delete(&server).await }
        });
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                if called_paths(&server)
                    .await
                    .contains(&DELETE_SUB_ORG.to_string())
                {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("Turnkey cleanup must start after the backup is deleted");

        tokio::time::pause();
        tokio::time::advance(Duration::from_secs(31)).await;
        deletion
            .await
            .unwrap()
            .expect("the backup is already deleted");
        tokio::time::resume();
    }

    #[tokio::test]
    async fn a_transient_failure_is_retried_then_succeeds() {
        let server = MockServer::start().await;
        mount_metadata(&server, vec![turnkey_key()]).await;
        mount_json(&server, DELETE_BACKUP_CHALLENGE, challenge_response()).await;
        Mock::given(method("POST"))
            .and(path(DELETE_BACKUP))
            .respond_with(ResponseTemplate::new(503))
            .up_to_n_times(1)
            .mount(&server)
            .await;
        mount(&server, DELETE_BACKUP, ResponseTemplate::new(204)).await;
        mount_delete_sub_org(&server, completed_sub_org_teardown()).await;

        run_delete(&server).await.unwrap();

        let paths = called_paths(&server).await;
        assert_eq!(
            paths.iter().filter(|p| *p == DELETE_BACKUP).count(),
            2,
            "the delete is attempted again after a transient failure"
        );
        assert_eq!(
            paths
                .iter()
                .filter(|p| *p == DELETE_BACKUP_CHALLENGE)
                .count(),
            2,
            "every attempt needs a fresh challenge"
        );
        assert!(paths.contains(&DELETE_SUB_ORG.to_string()));
    }

    #[tokio::test]
    async fn retries_are_bounded_and_then_the_error_surfaces() {
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
        let paths = called_paths(&server).await;
        assert_eq!(
            paths.iter().filter(|p| *p == DELETE_BACKUP).count(),
            RetryPolicy::default().max_attempts as usize,
            "bounded by the shared retry policy"
        );
        assert!(
            !paths.contains(&DELETE_SUB_ORG.to_string()),
            "Turnkey must survive a backup that may still exist"
        );
    }

    #[tokio::test]
    async fn a_terminal_rejection_is_not_retried() {
        let server = MockServer::start().await;
        mount_metadata(&server, vec![turnkey_key()]).await;
        mount_json(&server, DELETE_BACKUP_CHALLENGE, challenge_response()).await;
        mount_rejection(&server, DELETE_BACKUP, "invalid_challenge").await;
        mount_delete_sub_org(&server, completed_sub_org_teardown()).await;

        let error = run_delete(&server).await.unwrap_err();

        assert!(matches!(error, BackupOperationError::BackupService { .. }));
        let paths = called_paths(&server).await;
        assert_eq!(paths.iter().filter(|p| *p == DELETE_BACKUP).count(), 1);
        assert!(!paths.contains(&DELETE_SUB_ORG.to_string()));
    }

    #[tokio::test]
    async fn an_untraceable_backup_aborts_before_the_delete() {
        let server = MockServer::start().await;
        mount_json(&server, RETRIEVE_META_CHALLENGE, challenge_response()).await;
        mount_rejection(&server, RETRIEVE_META, "backup_untraceable").await;

        let error = run_delete(&server).await.unwrap_err();

        assert!(matches!(error, BackupOperationError::BackupService { .. }));
        assert!(!called_paths(&server)
            .await
            .contains(&DELETE_BACKUP.to_string()));
    }

    #[tokio::test]
    async fn several_turnkey_keys_are_all_deleted() {
        let server = MockServer::start().await;
        let second_key = json!({
            "kind": "TURNKEY",
            "encryptedKey": "ek2",
            "turnkeyAccountId": "suborg-2",
            "turnkeyUserId": "user-2",
            "turnkeyPrivateKeyId": "pk-2",
        });
        mount_metadata(&server, vec![turnkey_key(), second_key]).await;
        mount_delete_backup(&server).await;
        mount_delete_sub_org(&server, completed_sub_org_teardown()).await;

        run_delete(&server).await.unwrap();

        let paths = called_paths(&server).await;
        assert!(paths.contains(&DELETE_BACKUP.to_string()));
        assert_eq!(
            paths.iter().filter(|p| *p == DELETE_SUB_ORG).count(),
            2,
            "both sub-organizations MUST be deleted"
        );
    }
}
