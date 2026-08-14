//! Foreign-implemented attestation-token provider.
//!
//! Some backend calls sit behind TFH's [Attestation Gateway](https://github.com/worldcoin/attestation-gateway),
//! requiring an attestation token.

use std::sync::{Arc, OnceLock};

use crate::HttpError;

/// Global attestation-token provider set by the host.
static ATTESTATION_PROVIDER: OnceLock<Arc<dyn AttestationTokenProvider>> =
    OnceLock::new();

/// A provider of Attestation Gateway tokens.
#[uniffi::export(with_foreign)]
#[async_trait::async_trait]
pub trait AttestationTokenProvider: Send + Sync {
    /// Returns an Attestation Gateway token bound to `request_hash`. Bedrock is responsible
    /// for providing the final request hash. The native app signs the opaque hash.
    ///
    /// `request_hash` is the hex-encoded SHA-256 the gateway will recompute from the
    /// outgoing request; the returned token's `jti` claim MUST equal it.
    ///
    /// # Errors
    /// Returns [`HttpError`] if the token cannot be produced (e.g. attestation is
    /// unavailable or the gateway call fails).
    async fn attestation_token(
        &self,
        request_hash: String,
    ) -> Result<String, HttpError>;
}

/// Sets the global attestation-token provider. Returns `false` if already set.
#[uniffi::export]
pub fn set_attestation_token_provider(
    provider: Arc<dyn AttestationTokenProvider>,
) -> bool {
    ATTESTATION_PROVIDER.set(provider).is_ok()
}

/// Returns the configured attestation-token provider, if any.
#[must_use]
pub fn get_attestation_provider() -> Option<Arc<dyn AttestationTokenProvider>> {
    ATTESTATION_PROVIDER.get().cloned()
}
