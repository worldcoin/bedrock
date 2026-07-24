//! Shared test helpers for the Turnkey module.

use p256::ecdsa::signature::hazmat::PrehashSigner;
use p256::elliptic_curve::sec1::ToEncodedPoint;

use crate::primitives::{KeypairSigner, KeypairSignerError};

/// An in-process [`KeypairSigner`] backed by a known P-256 key, for tests.
pub struct TestSigner {
    secret: p256::SecretKey,
}

impl TestSigner {
    /// Builds a signer from a 32-byte hex-encoded P-256 private key.
    pub fn from_hex(hex_key: &str) -> Self {
        let bytes = hex::decode(hex_key).expect("valid hex key");
        let secret = p256::SecretKey::from_slice(&bytes).expect("valid p256 key");
        Self { secret }
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
