//! Foreign-implemented keypair signer.
//!
//! Bedrock never handles the persistent private key material: the host keeps the
//! key in secure storage — a hardware-backed secure enclave (iOS Secure Enclave /
//! Android Keystore / StrongBox) is recommended — and exposes a [`KeypairSigner`]
//! that signs pre-computed digests on Bedrock's behalf.

use std::sync::Arc;

/// A foreign-implemented signer backed by an elliptic-curve keypair.
///
/// The key stays in the host's secure storage (ideally a hardware-backed secure
/// enclave) and never crosses the FFI boundary: Bedrock hands the signer a digest
/// and receives a signature plus the public key.
///
/// This is a **curve-agnostic** signing primitive.
///
/// # Contract
/// Implementations MUST:
/// - [`Self::public_key`]: return the compressed public key as a **SEC1-encoded point**
///   (compressed `0x02`/`0x03`).
/// - [`Self::sign_digest`]: sign the provided pre-computed digest **directly** (no
///   additional hashing) with ECDSA over the key's curve, returning a
///   **DER-encoded, low-S-normalized** signature. Synchronous.
#[uniffi::export(with_foreign)]
pub trait KeypairSigner: Send + Sync {
    /// Returns the public key as a SEC1-encoded point.
    ///
    /// # Errors
    /// Returns [`KeypairSignerError`] if the key material is unavailable or invalid.
    fn public_key(&self) -> Result<Vec<u8>, KeypairSignerError>;

    /// Signs a pre-computed digest with the private key.
    ///
    /// # Errors
    /// Returns [`KeypairSignerError`] if signing is rejected or the key is unavailable.
    fn sign_digest(&self, digest: Vec<u8>) -> Result<Vec<u8>, KeypairSignerError>;
}

/// Errors returned by a [`KeypairSigner`] implementation.
#[crate::bedrock_error]
pub enum KeypairSignerError {
    /// The signing key is unavailable or the operation was rejected (for example
    /// secure storage is locked or the user cancelled a prompt).
    #[error("signing key unavailable or operation rejected")]
    Unavailable,
    /// The key material is malformed or of an unexpected type.
    #[error("invalid signing key material")]
    InvalidKey,
    /// The trait implementation provided an invalid signature for the specific curve.
    #[error("invalid signature received")]
    InvalidSignature,
    /// The public key returned by the signer is malformed: wrong length, not a
    /// valid compressed SEC1 encoding, or not a point on the P-256 curve.
    #[error("invalid public key: {error_message}")]
    InvalidPublicKey {
        /// Human-readable reason the key was rejected.
        error_message: String,
    },
}

/// Converts unexpected UniFFI callback errors (foreign panics/exceptions) into a
/// typed error instead of unwinding across the FFI boundary.
impl From<uniffi::UnexpectedUniFFICallbackError> for KeypairSignerError {
    fn from(error: uniffi::UnexpectedUniFFICallbackError) -> Self {
        Self::Generic {
            error_message: error.to_string(),
        }
    }
}

/// A [`KeypairSigner`] pinned to the **P-256** curve.
///
/// Its public key is fetched once and validated as a compressed SEC1 P-256 point,
/// so downstream stamping can reuse it without re-querying or re-validating.
#[derive(Clone, uniffi::Object)]
pub struct P256Signer {
    signer: Arc<dyn KeypairSigner>,
    /// Compressed SEC1 public key, hex-encoded
    public_key_hex: String,
}

#[crate::bedrock_export]
impl P256Signer {
    /// Validates `signer`'s public key and wraps it for reuse.
    ///
    /// Foreign callers construct this **before** invoking migration APIs, so an
    /// invalid key fails here with a clear [`KeypairSignerError`] rather than an
    /// opaque error from a later call. The public key is fetched once and checked
    /// to be a 33-byte compressed SEC1 P-256 point; the resulting handle can be
    /// reused across calls (e.g. re-invoking with the main factor).
    ///
    /// # Errors
    /// - [`KeypairSignerError`] if the signer cannot produce its public key.
    /// - [`KeypairSignerError::InvalidPublicKey`] if the key is not a 33-byte
    ///   compressed SEC1 encoding or not a valid point on the P-256 curve.
    #[uniffi::constructor]
    pub fn verify(signer: Arc<dyn KeypairSigner>) -> Result<Self, KeypairSignerError> {
        let bytes = signer.public_key()?;
        if bytes.len() != Self::COMPRESSED_PUBLIC_KEY_LEN {
            return Err(KeypairSignerError::InvalidPublicKey {
                error_message: format!(
                    "expected {}-byte compressed SEC1 key, got {} bytes",
                    Self::COMPRESSED_PUBLIC_KEY_LEN,
                    bytes.len()
                ),
            });
        }
        // enforces a valid compressed SEC1 encoding and an on-curve point.
        p256::PublicKey::from_sec1_bytes(&bytes).map_err(|error| {
            KeypairSignerError::InvalidPublicKey {
                error_message: format!("not a valid P-256 point: {error}"),
            }
        })?;
        Ok(Self {
            signer,
            public_key_hex: hex::encode(&bytes),
        })
    }
}

impl P256Signer {
    /// Length in bytes of a compressed SEC1 P-256 public key.
    const COMPRESSED_PUBLIC_KEY_LEN: usize = 33;

    /// The validated compressed SEC1 public key, hex-encoded.
    #[must_use]
    pub fn public_key_hex(&self) -> &str {
        &self.public_key_hex
    }

    /// Signs a pre-computed 32-byte digest with the underlying signer. Will
    /// perform low-s normalization on all signatures.
    ///
    /// # Errors
    /// Returns [`KeypairSignerError`] if signing is rejected, an invalid signature
    /// is provided by the implementer, or the key is unavailable.
    pub fn sign_digest(
        &self,
        digest: Vec<u8>,
    ) -> Result<p256::ecdsa::Signature, KeypairSignerError> {
        let signature = self.signer.sign_digest(digest)?;
        let signature = p256::ecdsa::Signature::from_der(&signature)
            .map_err(|_| KeypairSignerError::InvalidSignature)?;

        Ok(signature.normalize_s().unwrap_or(signature))
    }
}

#[cfg(test)]
mod p256_signer_tests {
    use super::*;
    use hex_literal::hex;
    use p256::ecdsa::signature::hazmat::PrehashSigner;
    use p256::elliptic_curve::sec1::ToEncodedPoint;
    use p256::elliptic_curve::PrimeField;

    const DIGEST: [u8; 32] = [0x42; 32];

    #[derive(Default)]
    struct MockSigner {
        public_key: Option<Vec<u8>>,
        signature: Vec<u8>,
    }

    impl KeypairSigner for MockSigner {
        fn public_key(&self) -> Result<Vec<u8>, KeypairSignerError> {
            self.public_key
                .clone()
                .ok_or(KeypairSignerError::Unavailable)
        }
        fn sign_digest(&self, _digest: Vec<u8>) -> Result<Vec<u8>, KeypairSignerError> {
            Ok(self.signature.clone())
        }
    }

    fn valid_compressed_key() -> Vec<u8> {
        p256::SecretKey::from_slice(&[1u8; 32])
            .expect("valid scalar")
            .public_key()
            .to_encoded_point(true)
            .as_bytes()
            .to_vec()
    }

    /// A [`P256Signer`] whose underlying signer always returns `signature`.
    fn signer_returning(signature: Vec<u8>) -> P256Signer {
        P256Signer::verify(Arc::new(MockSigner {
            public_key: Some(valid_compressed_key()),
            signature,
        }))
        .unwrap()
    }

    /// A valid, low-S signature over [`DIGEST`].
    fn low_s_signature() -> p256::ecdsa::Signature {
        let key = p256::ecdsa::SigningKey::from_slice(&[1u8; 32]).unwrap();
        let signature: p256::ecdsa::Signature = key.sign_prehash(&DIGEST).unwrap();
        signature.normalize_s().unwrap_or(signature)
    }

    fn to_high_s(signature: &p256::ecdsa::Signature) -> p256::ecdsa::Signature {
        let (r, _) = signature.split_bytes();
        let s = -*signature.s().as_ref();
        p256::ecdsa::Signature::from_scalars(r, s.to_repr()).expect("non-zero scalars")
    }

    #[test]
    fn accepts_valid_compressed_key() {
        let key = valid_compressed_key();
        let verified = P256Signer::verify(Arc::new(MockSigner {
            public_key: Some(key.clone()),
            ..MockSigner::default()
        }))
        .unwrap();
        assert_eq!(verified.public_key_hex(), hex::encode(&key));
    }

    #[test]
    fn rejects_wrong_length_key() {
        let result = P256Signer::verify(Arc::new(MockSigner {
            public_key: Some(vec![0x02; 32]),
            ..MockSigner::default()
        }));
        assert!(matches!(
            result,
            Err(KeypairSignerError::InvalidPublicKey { .. })
        ));
    }

    #[test]
    fn rejects_invalid_encoding() {
        // Correct length, but an invalid SEC1 tag byte (not 0x02/0x03).
        let mut key = valid_compressed_key();
        key[0] = 0x01;
        let result = P256Signer::verify(Arc::new(MockSigner {
            public_key: Some(key),
            ..MockSigner::default()
        }));
        assert!(matches!(
            result,
            Err(KeypairSignerError::InvalidPublicKey { .. })
        ));
    }

    #[test]
    fn propagates_public_key_error() {
        let result = P256Signer::verify(Arc::new(MockSigner::default()));
        assert!(matches!(result, Err(KeypairSignerError::Unavailable)));
    }

    #[test]
    fn normalizes_high_s_signature() {
        let expected = low_s_signature();
        let high_s = to_high_s(&expected);
        assert_ne!(high_s, expected);

        let signature = signer_returning(high_s.to_der().as_bytes().to_vec())
            .sign_digest(DIGEST.to_vec())
            .unwrap();

        assert_eq!(signature, expected);
        assert!(signature.normalize_s().is_none());
    }

    /// Tests the low-s normalization with a static test vector for a signature.
    ///
    /// The test vector is obtained from [RFC 6979](https://datatracker.ietf.org/doc/html/rfc6979) §A.2.5
    /// (With SHA-256, message = "sample")
    #[test]
    fn normalizes_deterministic_high_s_signature() {
        let s =
            hex!("F7CB1C942D657C41D436C7A1B6E29F65F3E900DBB9AFF4064DC4AB2F843ACDA8");
        let r =
            hex!("EFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716");
        let signature = p256::ecdsa::Signature::from_scalars(r, s).unwrap();
        let sig_der = signature.to_der().as_bytes().to_vec();

        let signature = signer_returning(sig_der.clone())
            .sign_digest(DIGEST.to_vec())
            .unwrap();

        assert_ne!(
            signature.to_der().as_bytes(),
            &sig_der,
            "normalized signature MUST differ"
        );
    }

    #[test]
    fn preserves_low_s_signature() {
        let expected = low_s_signature();

        let signature = signer_returning(expected.to_der().as_bytes().to_vec())
            .sign_digest(DIGEST.to_vec())
            .unwrap();

        assert_eq!(signature, expected);
    }

    #[test]
    fn rejects_non_der_signature() {
        // Raw 64-byte concatenated (r, s) instead of the required DER encoding.
        let raw = low_s_signature().to_bytes().to_vec();
        let result = signer_returning(raw).sign_digest(DIGEST.to_vec());
        assert!(matches!(result, Err(KeypairSignerError::InvalidSignature)));
    }
}
