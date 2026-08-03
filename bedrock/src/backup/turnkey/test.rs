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
    use crate::primitives::config::{set_config, BedrockEnvironment, Os};
    use crate::primitives::logger::set_logger;
    use crate::primitives::P256Signer;
    use std::sync::Arc;

    #[tokio::test]
    #[ignore = "integration: hits the real Turnkey API; requires real credentials"]
    async fn run_migrations_against_real_turnkey() {
        set_config(BedrockEnvironment::Staging, Os::Ios);
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
mod migration_functional_tests {
    use super::TestSigner;
    use crate::backup::turnkey::api::{MainFactor, SyncFactor, TurnkeyApiClient};
    use crate::backup::turnkey::migrations::{
        run_migration_list, TurnkeyMigrationOutcome, MIGRATIONS,
    };
    use crate::backup::turnkey::policies::{APPLE_ISSUER, AUTH_USER_MAIN_USERNAME};
    use crate::primitives::config::BedrockEnvironment;
    use crate::primitives::P256Signer;
    use serde_json::json;
    use std::sync::Arc;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    const LIST_USERS_PATH: &str = "/public/v1/query/list_users";
    const CREATE_OAUTH_PATH: &str = "/public/v1/submit/create_oauth_providers";

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

    async fn mount_list_users(server: &MockServer, user: serde_json::Value) {
        Mock::given(method("POST"))
            .and(path(LIST_USERS_PATH))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(json!({ "users": [user] })),
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

    #[tokio::test]
    async fn apple_audiences_creates_missing_audiences_with_main_factor() {
        let server = MockServer::start().await;
        // Only the first staging audience present → the other three missing.
        mount_list_users(
            &server,
            main_user(&["org.worldcoin.insight.staging"], "sub-apple"),
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
        mount_list_users(
            &server,
            main_user(
                &[
                    "org.worldcoin.insight.staging",
                    "org.world.staging.id",
                    "org.world.sandbox.id",
                    "app.world.apple.staging",
                ],
                "sub-apple",
            ),
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
        mount_list_users(
            &server,
            main_user(&["org.worldcoin.insight.staging"], "sub-apple"),
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

        let TurnkeyMigrationOutcome::MainFactorRequired { pending } = outcome else {
            panic!("expected MainFactorRequired, got {outcome:?}");
        };
        assert_eq!(pending.len(), 1);
    }
}
