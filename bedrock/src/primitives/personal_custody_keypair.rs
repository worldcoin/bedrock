use std::sync::Arc;

use base64::Engine;
use crypto_box::SecretKey;
use sha2::{Digest, Sha512};
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::bedrock_export;

/// Errors that can occur with personal custody keypairs
#[derive(Debug, Error, uniffi::Error)]
pub enum PersonalCustodyKeypairError {
    /// Failed to generate random key
    #[error("failed to generate random key")]
    RandomnessError,
}

/// A keypair for personal custody operations using NaCl/libsodium `crypto_box`
#[derive(uniffi::Object, Clone, Debug)]
pub struct PersonalCustodyKeypair {
    pk: crypto_box::PublicKey,
    sk: crypto_box::SecretKey,
}

impl PersonalCustodyKeypair {
    /// Create a keypair from an existing private key
    #[must_use]
    pub fn from_private_key(private_key: SecretKey) -> Self {
        Self {
            pk: private_key.public_key(),
            sk: private_key,
        }
    }

    /// Create a keypair from private key bytes
    #[must_use]
    /// # Panics
    ///
    /// Panics if the private key bytes are not exactly 32 bytes long.
    pub fn from_private_key_bytes(private_key_bytes: &[u8]) -> Self {
        let private_key = SecretKey::from_slice(private_key_bytes).unwrap();
        Self::from_private_key(private_key)
    }

    /// Get the public key
    #[must_use]
    pub fn pk(&self) -> crypto_box::PublicKey {
        self.pk.clone()
    }

    /// Get the secret key
    #[must_use]
    pub fn sk(&self) -> crypto_box::SecretKey {
        self.sk.clone()
    }

    /// Derive a keypair from a seed (backwards compatible with libsodium)
    ///
    /// This is backwards compatible with libsodium's `crypto_box_curve25519xsalsa20poly1305_seed_keypair`
    /// <https://github.com/jedisct1/libsodium/blob/59a98bc7f9d507175f551a53bfc0b2081f06e3ba/src/libsodium/crypto_box/curve25519xsalsa20poly1305/box_curve25519xsalsa20poly1305.c#L18>
    #[must_use]
    /// # Panics
    ///
    /// Panics if the seed hash cannot be converted to a valid secret key.
    pub fn derive_from_seed(seed: &[u8]) -> Self {
        let mut hasher = Sha512::new();
        hasher.update(seed);
        let seed_hash = hasher.finalize();
        let secret_key = SecretKey::from_slice(&seed_hash[..32]).unwrap();
        let public_key = secret_key.public_key();
        Self {
            pk: public_key,
            sk: secret_key,
        }
    }
}

#[bedrock_export]
impl PersonalCustodyKeypair {
    /// Create a new random keypair
    ///
    /// # Errors
    /// Returns `PersonalCustodyKeypairError::RandomnessError` if randomness generation fails
    #[uniffi::constructor]
    pub fn new() -> Result<Arc<Self>, PersonalCustodyKeypairError> {
        let private_key = SecretKey::generate(&mut rand::thread_rng());

        Ok(Arc::new(Self {
            pk: private_key.public_key(),
            sk: private_key,
        }))
    }

    /// Get the public key as bytes
    #[must_use]
    pub fn pk_as_bytes(&self) -> Vec<u8> {
        self.pk.as_bytes().to_vec()
    }

    /// Get the secret key as bytes
    #[must_use]
    pub fn sk_as_bytes(&self) -> Vec<u8> {
        self.sk.to_bytes().to_vec()
    }

    /// Get the public key as base64
    #[must_use]
    pub fn pk_as_base64(&self) -> String {
        base64::engine::general_purpose::STANDARD.encode(self.pk_as_bytes())
    }

    /// Get the public key as PEM format
    #[must_use]
    pub fn pk_as_pem(&self) -> String {
        let base64_key = self.pk_as_base64();
        format!("-----BEGIN PUBLIC KEY-----\n{base64_key}\n-----END PUBLIC KEY-----")
    }
}

impl Zeroize for PersonalCustodyKeypair {
    fn zeroize(&mut self) {
        self.pk = crypto_box::PublicKey::from_bytes([0; 32]);
        self.sk = crypto_box::SecretKey::from_bytes([0; 32]);
    }
}

impl ZeroizeOnDrop for PersonalCustodyKeypair {}

#[cfg(test)]
impl PersonalCustodyKeypair {
    /// Create a test keypair for testing purposes
    #[must_use]
    pub fn test_keypair() -> Self {
        let private_key = SecretKey::generate(&mut rand::thread_rng());
        Self {
            pk: private_key.public_key(),
            sk: private_key,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keypair_creation() {
        let keypair = PersonalCustodyKeypair::new().unwrap();
        assert!(!keypair.pk_as_bytes().iter().all(|&b| b == 0));
        assert!(!keypair.sk_as_bytes().iter().all(|&b| b == 0));
    }

    #[test]
    fn test_keypair_from_bytes() {
        let keypair1 = PersonalCustodyKeypair::test_keypair();
        let sk_bytes = keypair1.sk_as_bytes();
        let keypair2 = PersonalCustodyKeypair::from_private_key_bytes(&sk_bytes);

        assert_eq!(keypair1.pk_as_bytes(), keypair2.pk_as_bytes());
        assert_eq!(keypair1.sk_as_bytes(), keypair2.sk_as_bytes());
    }

    #[test]
    fn test_derive_from_seed() {
        let seed = b"test seed for keypair derivation";
        let keypair1 = PersonalCustodyKeypair::derive_from_seed(seed);
        let keypair2 = PersonalCustodyKeypair::derive_from_seed(seed);

        // Should be deterministic
        assert_eq!(keypair1.pk_as_bytes(), keypair2.pk_as_bytes());
        assert_eq!(keypair1.sk_as_bytes(), keypair2.sk_as_bytes());
    }
}
