//! Shared test helpers for the Turnkey module.

use p256::ecdsa::signature::hazmat::PrehashSigner;
use p256::elliptic_curve::sec1::ToEncodedPoint;

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
