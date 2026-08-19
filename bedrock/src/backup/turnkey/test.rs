//! Shared test helpers for the Turnkey module.

use p256::ecdsa::signature::hazmat::PrehashSigner;
use p256::elliptic_curve::sec1::ToEncodedPoint;

use crate::primitives::logger::{LogLevel, Logger};
use crate::primitives::{KeypairSigner, KeypairSignerError};

/// A deterministic, obviously-non-secret P-256 private key for tests (all `0x01`
/// bytes). Never put anything resembling a real key in tests.
pub const TEST_PRIVATE_KEY: [u8; 32] = [1u8; 32];

/// An in-process [`KeypairSigner`] backed by [`TEST_PRIVATE_KEY`], for tests.
pub struct TestSigner {
    secret: p256::SecretKey,
}

impl TestSigner {
    /// Builds the canonical test signer from [`TEST_PRIVATE_KEY`].
    pub fn new() -> Self {
        let secret =
            p256::SecretKey::from_slice(&TEST_PRIVATE_KEY).expect("valid p256 key");
        Self { secret }
    }

    /// Builds a signer from a hex-encoded P-256 private key.
    ///
    /// For integration tests that load a real key from the environment — do not
    /// hardcode real key material in source.
    pub fn from_hex(hex_key: &str) -> Self {
        let bytes = hex::decode(hex_key).expect("valid hex key");
        let secret = p256::SecretKey::from_slice(&bytes).expect("valid p256 key");
        Self { secret }
    }
}

impl Default for TestSigner {
    fn default() -> Self {
        Self::new()
    }
}

impl KeypairSigner for TestSigner {
    fn public_key(&self) -> Result<Vec<u8>, KeypairSignerError> {
        Ok(self
            .secret
            .public_key()
            .to_encoded_point(true)
            .as_bytes()
            .to_vec())
    }

    fn sign_digest(&self, digest: Vec<u8>) -> Result<Vec<u8>, KeypairSignerError> {
        let signing_key = p256::ecdsa::SigningKey::from(self.secret.clone());
        let signature: p256::ecdsa::Signature = signing_key
            .sign_prehash(&digest)
            .map_err(|_| KeypairSignerError::InvalidKey)?;
        Ok(signature.to_der().as_bytes().to_vec())
    }
}

/// A [`Logger`] that prints Bedrock's log records to stdout, so `crate::info!`
/// and friends are visible when an integration test runs with `--nocapture`.
/// Install it once per test process via
/// [`crate::primitives::logger::set_logger`].
pub struct StdoutLogger;

impl Logger for StdoutLogger {
    fn log(&self, level: LogLevel, message: String) {
        println!("[bedrock][{level:?}] {message}");
    }
}

/// Integration tests that hit the **real Turnkey API**. Ignored by default; run
/// explicitly against a real sub-organization with real credentials.
mod integration_tests {
    use super::{StdoutLogger, TestSigner};
    use crate::backup::turnkey::TurnkeyManager;
    use crate::primitives::filesystem::init_test_filesystem;
    use crate::primitives::logger::set_logger;
    use crate::primitives::P256Signer;
    use std::sync::Arc;

    #[tokio::test]
    #[ignore = "integration: hits the real Turnkey API; requires real credentials"]
    async fn run_migrations_against_real_turnkey() {
        init_test_filesystem();
        set_logger(Arc::new(StdoutLogger));

        let sync_key = std::env::var("TURNKEY_SYNC_KEY").unwrap();
        let sync_factor = P256Signer::verify(Arc::new(TestSigner::from_hex(&sync_key)))
            .expect("valid sync factor key");

        let main_factor = std::env::var("TURNKEY_MAIN_KEY").ok().map(|key| {
            Arc::new(
                P256Signer::verify(Arc::new(TestSigner::from_hex(&key)))
                    .expect("valid main factor key"),
            )
        });

        let suborganization_id = std::env::var("TURNKEY_SUBORG_ID").ok();

        let outcome = TurnkeyManager::new()
            .run_migrations(suborganization_id, &sync_factor, main_factor)
            .await
            .expect("run_migrations should succeed against real Turnkey");

        println!("run_migrations outcome: {outcome:?}");
    }
}

/// Full coverage of the entire migration run process (`run_migration_list`) with
/// mocked API calls to Turnkey (follows same mocking patterns as Turnkey's SDK).
mod functional_tests {
    use super::TestSigner;
    use crate::backup::turnkey::api::TurnkeyApiClient;
    use crate::backup::turnkey::migrations::{
        run_migration_list, TurnkeyMigrationOutcome, MIGRATIONS,
    };
    use crate::backup::turnkey::policies::{
        sync_factor_policy_consensus, sync_factor_policy_name, APPLE_ISSUER,
        AUTH_USER_MAIN_USERNAME, SYNC_FACTOR_POLICY_CONDITION,
        SYNC_FACTOR_USERNAME_PREFIX,
    };
    use crate::primitives::config::BedrockEnvironment;
    use crate::primitives::P256Signer;
    use serde_json::json;
    use std::sync::Arc;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    const LIST_USERS_PATH: &str = "/public/v1/query/list_users";
    const CREATE_OAUTH_PATH: &str = "/public/v1/submit/create_oauth_providers";
    const LIST_POLICIES_PATH: &str = "/public/v1/query/list_policies";
    const CREATE_POLICY_PATH: &str = "/public/v1/submit/create_policy";
    const UPDATE_POLICY_PATH: &str = "/public/v1/submit/update_policy";
    const DELETE_POLICY_PATH: &str = "/public/v1/submit/delete_policy";

    /// A sync factor user id (UUID) used across the policy tests.
    const SYNC_ID: &str = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";

    fn signer() -> P256Signer {
        P256Signer::verify(Arc::new(TestSigner::new())).expect("valid test signer")
    }

    /// `auth_user_main` carrying an Apple provider for each `audiences` entry.
    fn main_user(audiences: &[&str], subject: &str) -> serde_json::Value {
        let providers: Vec<serde_json::Value> = audiences
            .iter()
            .map(|aud| {
                json!({
                    "providerId": format!("p-{aud}"),
                    "providerName": "apple",
                    "issuer": APPLE_ISSUER,
                    "audience": aud,
                    "subject": subject,
                })
            })
            .collect();
        json!({
            "userId": "user-main",
            "userName": AUTH_USER_MAIN_USERNAME,
            "oauthProviders": providers,
        })
    }

    /// Mounts both read endpoints the migration list depends on: `list_users` and
    /// `list_policies`. Every functional test needs both, since the run executes the
    /// full [`MIGRATIONS`] list.
    async fn mount_reads(
        server: &MockServer,
        users: Vec<serde_json::Value>,
        policies: Vec<serde_json::Value>,
    ) {
        Mock::given(method("POST"))
            .and(path(LIST_USERS_PATH))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(json!({ "users": users })),
            )
            .mount(server)
            .await;
        Mock::given(method("POST"))
            .and(path(LIST_POLICIES_PATH))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(json!({ "policies": policies })),
            )
            .mount(server)
            .await;
    }

    /// A minimal COMPLETED `CreateOauthProviders` activity response.
    fn completed_create(provider_ids: &[&str]) -> serde_json::Value {
        json!({
            "activity": {
                "id": "act-1",
                "organizationId": "suborg-1",
                "status": "ACTIVITY_STATUS_COMPLETED",
                "type": "ACTIVITY_TYPE_CREATE_OAUTH_PROVIDERS_V2",
                "fingerprint": "fp-1",
                "result": {
                    "createOauthProvidersResultV2": { "providerIds": provider_ids }
                }
            }
        })
    }

    /// `auth_user_main` with no OAuth providers, so the Apple migration is a no-op
    /// and the policy migration is exercised in isolation.
    fn main_user_without_apple() -> serde_json::Value {
        json!({
            "userId": "user-main",
            "userName": AUTH_USER_MAIN_USERNAME,
            "oauthProviders": [],
        })
    }

    /// A sync factor user named `sync_factor_user_<user_id>`.
    fn sync_factor_user(user_id: &str) -> serde_json::Value {
        json!({
            "userId": user_id,
            "userName": format!("{SYNC_FACTOR_USERNAME_PREFIX}{user_id}"),
        })
    }

    /// A sync factor policy record for `list_policies`, bound to `user_id`
    /// with an arbitrary `condition` (to model an outdated one).
    fn user_policy_record(
        policy_id: &str,
        user_id: &str,
        condition: &str,
    ) -> serde_json::Value {
        json!({
            "policyId": policy_id,
            "policyName": sync_factor_policy_name(user_id),
            "effect": "EFFECT_ALLOW",
            "notes": "",
            "consensus": sync_factor_policy_consensus(user_id)
                .expect("test user id is valid"),
            "condition": condition,
        })
    }

    /// A COMPLETED `CreatePolicy` activity response returning `policy_id`.
    fn completed_create_policy(policy_id: &str) -> serde_json::Value {
        json!({
            "activity": {
                "id": "act-create-policy",
                "organizationId": "suborg-1",
                "status": "ACTIVITY_STATUS_COMPLETED",
                "type": "ACTIVITY_TYPE_CREATE_POLICY_V3",
                "fingerprint": "fp-create-policy",
                "result": { "createPolicyResult": { "policyId": policy_id } }
            }
        })
    }

    /// A COMPLETED `UpdatePolicy` activity response returning `policy_id`.
    fn completed_update_policy(policy_id: &str) -> serde_json::Value {
        json!({
            "activity": {
                "id": "act-update-policy",
                "organizationId": "suborg-1",
                "status": "ACTIVITY_STATUS_COMPLETED",
                "type": "ACTIVITY_TYPE_UPDATE_POLICY_V2",
                "fingerprint": "fp-update-policy",
                "result": { "updatePolicyResultV2": { "policyId": policy_id } }
            }
        })
    }

    /// A COMPLETED `DeletePolicy` activity response returning `policy_id`.
    fn completed_delete_policy(policy_id: &str) -> serde_json::Value {
        json!({
            "activity": {
                "id": "act-delete-policy",
                "organizationId": "suborg-1",
                "status": "ACTIVITY_STATUS_COMPLETED",
                "type": "ACTIVITY_TYPE_DELETE_POLICY",
                "fingerprint": "fp-delete-policy",
                "result": { "deletePolicyResult": { "policyId": policy_id } }
            }
        })
    }

    /// Functional tests for the `apple_audience` migration.
    mod apple_audiences {
        use crate::backup::{MainFactor, SyncFactor};

        use super::*;

        #[tokio::test]
        async fn apple_audiences_creates_missing_audiences_with_main_factor() {
            let server = MockServer::start().await;
            // Only the first staging audience present → the other three missing.
            mount_reads(
                &server,
                vec![main_user(&["org.worldcoin.insight.staging"], "sub-apple")],
                vec![],
            )
            .await;
            Mock::given(method("POST"))
                .and(path(CREATE_OAUTH_PATH))
                .respond_with(
                    ResponseTemplate::new(200)
                        .set_body_json(completed_create(&["n1", "n2", "n3"])),
                )
                .expect(1)
                .mount(&server)
                .await;

            let api = TurnkeyApiClient::with_base_url(server.uri());
            let sync = signer();
            let main = signer();
            let outcome = run_migration_list(
                MIGRATIONS,
                "suborg-1",
                SyncFactor(&sync),
                Some(MainFactor(&main)),
                &api,
                BedrockEnvironment::Staging,
            )
            .await
            .unwrap();

            assert_eq!(outcome, TurnkeyMigrationOutcome::Completed);

            // The create request carried exactly the missing staging audiences and
            // reused the existing subject.
            let requests = server.received_requests().await.unwrap();
            let create = requests
                .iter()
                .find(|request| request.url.path() == CREATE_OAUTH_PATH)
                .expect("create request was sent");
            let body = String::from_utf8_lossy(&create.body);
            for aud in [
                "org.world.staging.id",
                "org.world.sandbox.id",
                "app.world.apple.staging",
            ] {
                assert!(body.contains(aud), "create body missing audience {aud}");
            }
            assert!(body.contains("sub-apple"), "create body missing subject");
            assert!(
                !body.contains("org.worldcoin.insight.staging"),
                "create body should not re-add the already-present audience"
            );
        }

        #[tokio::test]
        async fn apple_audiences_skips_when_all_audiences_present() {
            let server = MockServer::start().await;
            mount_reads(
                &server,
                vec![main_user(
                    &[
                        "org.worldcoin.insight.staging",
                        "org.world.staging.id",
                        "org.world.sandbox.id",
                        "app.world.apple.staging",
                    ],
                    "sub-apple",
                )],
                vec![],
            )
            .await;
            // Any create call is a bug.
            Mock::given(method("POST"))
                .and(path(CREATE_OAUTH_PATH))
                .respond_with(ResponseTemplate::new(500))
                .expect(0)
                .mount(&server)
                .await;

            let api = TurnkeyApiClient::with_base_url(server.uri());
            let sync = signer();
            let main = signer();
            let outcome = run_migration_list(
                MIGRATIONS,
                "suborg-1",
                SyncFactor(&sync),
                Some(MainFactor(&main)),
                &api,
                BedrockEnvironment::Staging,
            )
            .await
            .unwrap();

            assert_eq!(outcome, TurnkeyMigrationOutcome::Completed);
        }

        #[tokio::test]
        async fn apple_audiences_defers_without_main_factor_and_never_writes() {
            let server = MockServer::start().await;
            mount_reads(
                &server,
                vec![main_user(&["org.worldcoin.insight.staging"], "sub-apple")],
                vec![],
            )
            .await;
            Mock::given(method("POST"))
                .and(path(CREATE_OAUTH_PATH))
                .respond_with(ResponseTemplate::new(500))
                .expect(0)
                .mount(&server)
                .await;

            let api = TurnkeyApiClient::with_base_url(server.uri());
            let sync = signer();
            let outcome = run_migration_list(
                MIGRATIONS,
                "suborg-1",
                SyncFactor(&sync),
                None,
                &api,
                BedrockEnvironment::Staging,
            )
            .await
            .unwrap();

            let TurnkeyMigrationOutcome::MainFactorRequired { pending } = outcome
            else {
                panic!("expected MainFactorRequired, got {outcome:?}");
            };
            assert_eq!(pending.len(), 1);
        }
    }

    /// Functional tests for the `sync_factor` migration.
    mod sync_factor {
        use super::*;
        use crate::backup::{MainFactor, SyncFactor};

        #[tokio::test]
        async fn sync_factor_policy_creates_policy_when_missing() {
            let server = MockServer::start().await;
            mount_reads(
                &server,
                vec![main_user_without_apple(), sync_factor_user(SYNC_ID)],
                vec![],
            )
            .await;
            Mock::given(method("POST"))
                .and(path(CREATE_POLICY_PATH))
                .respond_with(
                    ResponseTemplate::new(200)
                        .set_body_json(completed_create_policy("new-policy")),
                )
                .expect(1)
                .mount(&server)
                .await;

            let api = TurnkeyApiClient::with_base_url(server.uri());
            let sync = signer();
            let main = signer();
            let outcome = run_migration_list(
                MIGRATIONS,
                "suborg-1",
                SyncFactor(&sync),
                Some(MainFactor(&main)),
                &api,
                BedrockEnvironment::Staging,
            )
            .await
            .unwrap();

            assert_eq!(outcome, TurnkeyMigrationOutcome::Completed);

            // The create request carried the canonical condition bound to this user.
            let requests = server.received_requests().await.unwrap();
            let create = requests
                .iter()
                .find(|request| request.url.path() == CREATE_POLICY_PATH)
                .expect("create_policy request was sent");
            let body = String::from_utf8_lossy(&create.body);
            assert!(
                body.contains(SYNC_FACTOR_POLICY_CONDITION),
                "create body missing the canonical condition"
            );
            let consensus =
                sync_factor_policy_consensus(SYNC_ID).expect("SYNC_ID is valid");
            assert!(
                body.contains(&consensus),
                "create body missing the per-user consensus"
            );
        }

        #[tokio::test]
        async fn sync_factor_policy_updates_outdated_policy() {
            let server = MockServer::start().await;
            // A narrower condition from before ORGANIZATION/USER deletions were granted.
            let outdated =
                "activity.action == 'DELETE' && (activity.resource == 'CREDENTIAL')";
            mount_reads(
                &server,
                vec![main_user_without_apple(), sync_factor_user(SYNC_ID)],
                vec![user_policy_record("policy-old", SYNC_ID, outdated)],
            )
            .await;
            Mock::given(method("POST"))
                .and(path(UPDATE_POLICY_PATH))
                .respond_with(
                    ResponseTemplate::new(200)
                        .set_body_json(completed_update_policy("policy-old")),
                )
                .expect(1)
                .mount(&server)
                .await;
            // Creating a fresh policy would be a bug: the existing one must be updated.
            Mock::given(method("POST"))
                .and(path(CREATE_POLICY_PATH))
                .respond_with(ResponseTemplate::new(500))
                .expect(0)
                .mount(&server)
                .await;

            let api = TurnkeyApiClient::with_base_url(server.uri());
            let sync = signer();
            let main = signer();
            let outcome = run_migration_list(
                MIGRATIONS,
                "suborg-1",
                SyncFactor(&sync),
                Some(MainFactor(&main)),
                &api,
                BedrockEnvironment::Staging,
            )
            .await
            .unwrap();

            assert_eq!(outcome, TurnkeyMigrationOutcome::Completed);

            let requests = server.received_requests().await.unwrap();
            let update = requests
                .iter()
                .find(|request| request.url.path() == UPDATE_POLICY_PATH)
                .expect("update_policy request was sent");
            let body = String::from_utf8_lossy(&update.body);
            assert!(
                body.contains("policy-old"),
                "update targeted the wrong policy"
            );
            assert!(
                body.contains(SYNC_FACTOR_POLICY_CONDITION),
                "update body missing the canonical condition"
            );
        }

        #[tokio::test]
        async fn sync_factor_policy_defers_without_main_factor() {
            let server = MockServer::start().await;
            mount_reads(
                &server,
                vec![main_user_without_apple(), sync_factor_user(SYNC_ID)],
                vec![],
            )
            .await;
            Mock::given(method("POST"))
                .and(path(CREATE_POLICY_PATH))
                .respond_with(ResponseTemplate::new(500))
                .expect(0)
                .mount(&server)
                .await;

            let api = TurnkeyApiClient::with_base_url(server.uri());
            let sync = signer();
            let outcome = run_migration_list(
                MIGRATIONS,
                "suborg-1",
                SyncFactor(&sync),
                None,
                &api,
                BedrockEnvironment::Staging,
            )
            .await
            .unwrap();

            // Apple skips (no provider); only the policy migration defers.
            let TurnkeyMigrationOutcome::MainFactorRequired { pending } = outcome
            else {
                panic!("expected MainFactorRequired, got {outcome:?}");
            };
            assert_eq!(pending.len(), 1);
        }

        #[tokio::test]
        async fn sync_factor_policy_skips_when_policy_correct() {
            let server = MockServer::start().await;
            mount_reads(
                &server,
                vec![main_user_without_apple(), sync_factor_user(SYNC_ID)],
                vec![user_policy_record(
                    "policy-ok",
                    SYNC_ID,
                    SYNC_FACTOR_POLICY_CONDITION,
                )],
            )
            .await;
            // Any write is a bug when the policy already matches.
            for write_path in [CREATE_POLICY_PATH, UPDATE_POLICY_PATH] {
                Mock::given(method("POST"))
                    .and(path(write_path))
                    .respond_with(ResponseTemplate::new(500))
                    .expect(0)
                    .mount(&server)
                    .await;
            }

            let api = TurnkeyApiClient::with_base_url(server.uri());
            let sync = signer();
            let main = signer();
            let outcome = run_migration_list(
                MIGRATIONS,
                "suborg-1",
                SyncFactor(&sync),
                Some(MainFactor(&main)),
                &api,
                BedrockEnvironment::Staging,
            )
            .await
            .unwrap();

            assert_eq!(outcome, TurnkeyMigrationOutcome::Completed);
        }

        #[tokio::test]
        async fn get_policies_is_cached_within_a_client() {
            let server = MockServer::start().await;
            // `.expect(1)` fails if a second call reaches the server instead of the cache.
            Mock::given(method("POST"))
                .and(path(LIST_POLICIES_PATH))
                .respond_with(
                    ResponseTemplate::new(200).set_body_json(json!({ "policies": [] })),
                )
                .expect(1)
                .mount(&server)
                .await;

            let api = TurnkeyApiClient::with_base_url(server.uri());
            let sync = signer();
            api.get_policies("suborg-1", SyncFactor(&sync))
                .await
                .unwrap();
            api.get_policies("suborg-1", SyncFactor(&sync))
                .await
                .unwrap();
        }

        /// A client serves exactly one sub-organization. Querying a second one is a
        /// consistency violation, caught from the cache without a second network call.
        #[tokio::test]
        async fn get_policies_rejects_a_second_sub_org() {
            use crate::backup::turnkey::error::TurnkeyApiError;

            let server = MockServer::start().await;
            Mock::given(method("POST"))
                .and(path(LIST_POLICIES_PATH))
                .respond_with(
                    ResponseTemplate::new(200).set_body_json(json!({ "policies": [] })),
                )
                .expect(1)
                .mount(&server)
                .await;

            let api = TurnkeyApiClient::with_base_url(server.uri());
            let sync = signer();
            api.get_policies("suborg-1", SyncFactor(&sync))
                .await
                .unwrap();
            let error = api
                .get_policies("suborg-2", SyncFactor(&sync))
                .await
                .expect_err("a different sub-org must be rejected");
            assert!(matches!(error, TurnkeyApiError::Consistency));
        }

        #[tokio::test]
        async fn sync_factor_policy_prunes_stale_policy() {
            let server = MockServer::start().await;
            let gone_user = "99999999-9999-9999-9999-999999999999";
            mount_reads(
                &server,
                vec![main_user_without_apple(), sync_factor_user(SYNC_ID)],
                vec![
                    // The live sync factor's policy is already correct.
                    user_policy_record(
                        "policy-live",
                        SYNC_ID,
                        SYNC_FACTOR_POLICY_CONDITION,
                    ),
                    // A leftover policy bound to a user no longer in the org.
                    user_policy_record(
                        "policy-stale",
                        gone_user,
                        SYNC_FACTOR_POLICY_CONDITION,
                    ),
                ],
            )
            .await;
            Mock::given(method("POST"))
                .and(path(DELETE_POLICY_PATH))
                .respond_with(
                    ResponseTemplate::new(200)
                        .set_body_json(completed_delete_policy("policy-stale")),
                )
                .expect(1)
                .mount(&server)
                .await;
            // No create/update: the live sync factor is already correct.
            for write_path in [CREATE_POLICY_PATH, UPDATE_POLICY_PATH] {
                Mock::given(method("POST"))
                    .and(path(write_path))
                    .respond_with(ResponseTemplate::new(500))
                    .expect(0)
                    .mount(&server)
                    .await;
            }

            let api = TurnkeyApiClient::with_base_url(server.uri());
            let sync = signer();
            let main = signer();
            let outcome = run_migration_list(
                MIGRATIONS,
                "suborg-1",
                SyncFactor(&sync),
                Some(MainFactor(&main)),
                &api,
                BedrockEnvironment::Staging,
            )
            .await
            .unwrap();

            assert_eq!(outcome, TurnkeyMigrationOutcome::Completed);

            let requests = server.received_requests().await.unwrap();
            let delete = requests
                .iter()
                .find(|request| request.url.path() == DELETE_POLICY_PATH)
                .expect("delete_policy request was sent");
            let body = String::from_utf8_lossy(&delete.body);
            assert!(body.contains("policy-stale"), "deleted the wrong policy");
        }
    }
}
