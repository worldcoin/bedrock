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
    use crate::primitives::KeypairSigner;
    use std::sync::Arc;

    #[tokio::test]
    #[ignore = "integration: hits the real Turnkey API; requires real credentials"]
    async fn run_migrations_against_real_turnkey() {
        set_config(BedrockEnvironment::Staging, Os::Ios);
        set_logger(Arc::new(StdoutLogger));

        let sync_key = std::env::var("TURNKEY_SYNC_KEY").unwrap();
        let sync_factor: Arc<dyn KeypairSigner> =
            Arc::new(TestSigner::from_hex(&sync_key));

        let main_factor: Option<Arc<dyn KeypairSigner>> =
            std::env::var("TURNKEY_MAIN_KEY").ok().map(|key| {
                Arc::new(TestSigner::from_hex(&key)) as Arc<dyn KeypairSigner>
            });

        let suborganization_id = std::env::var("TURNKEY_SUBORG_ID").ok();

        let outcome = TurnkeyManager::new()
            .run_migrations(suborganization_id, sync_factor, main_factor)
            .await
            .expect("run_migrations should succeed against real Turnkey");

        println!("run_migrations outcome: {outcome:?}");
    }
}
