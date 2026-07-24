//! Foreign-implemented keypair signer.
//!
//! Bedrock never handles the persistent private key material: the host keeps the
//! key in secure storage — a hardware-backed secure enclave (iOS Secure Enclave /
//! Android Keystore / StrongBox) is recommended — and exposes a [`KeypairSigner`]
//! that signs pre-computed digests on Bedrock's behalf.

/// A foreign-implemented signer backed by a P-256 keypair.
///
/// The key stays in the host's secure storage (ideally a hardware-backed secure
/// enclave) and never crosses the FFI boundary: Bedrock hands the signer a digest
/// and receives a signature plus the public key.
///
/// This is a general-purpose signing primitive. Producing Turnkey API request
/// "stamps" is one use case; anything that needs a P-256 ECDSA signature over a
/// digest from a host-held key can use it.
///
/// # Contract
/// Implementations MUST:
/// - [`Self::public_key`]: return the **compressed SEC1** encoding of the P-256
///   public key (33 bytes).
/// - [`Self::sign_digest`]: sign the provided 32-byte digest **directly** (no
///   additional hashing) with ECDSA over the NIST P-256 curve, returning a
///   **DER-encoded, low-S-normalized** signature.
///
/// Signing is synchronous: implementations should read the key from secure
/// storage and sign without blocking on interactive prompts.
#[uniffi::export(with_foreign)]
pub trait KeypairSigner: Send + Sync {
    /// Returns the compressed SEC1-encoded P-256 public key (33 bytes).
    ///
    /// # Errors
    /// Returns [`KeypairSignerError`] if the key material is unavailable or invalid.
    fn public_key(&self) -> Result<Vec<u8>, KeypairSignerError>;

    /// Signs a pre-computed 32-byte digest with the P-256 private key.
    ///
    /// The `digest` is already the SHA-256 hash of the request body; implementations
    /// must sign it directly without re-hashing, returning a DER-encoded,
    /// low-S-normalized ECDSA signature.
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
