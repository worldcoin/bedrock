/// Constants for enclave verification
pub mod constants;

/// Types for enclave verification
pub mod types;

/// Verifies the attestation document from the enclave.
pub mod verifier;

#[cfg(test)]
mod tests;

pub use crate::primitives::config::BedrockEnvironment;
pub use types::{
    EnclaveAttestationError, EnclaveAttestationResult, PcrConfiguration,
    VerifiedAttestation,
};
pub use verifier::EnclaveAttestationVerifier;

/// Verify an enclave attestation document and extract the public key
///
/// This function verifies:
/// - The COSE Sign1 signature
/// - The certificate chain chains to AWS Nitro root and is not expired
/// - The PCR values match expected values
/// - The attestation is not stale (< 3 hours old)
/// - The public key is present and valid
#[uniffi::export]
pub fn verify_enclave_attestation_document(
    attestation_doc: String,
) -> EnclaveAttestationResult<VerifiedAttestation> {
    let config = crate::primitives::config::get_config().ok_or(
        EnclaveAttestationError::AttestationDocumentParseError(
            "Bedrock config not initialized. Call set_config() first.".to_string(),
        ),
    )?;

    let verifier = EnclaveAttestationVerifier::new(&config.environment());

    // Base 64 decode the attestation document
    let attestation_doc_bytes = base64::Engine::decode(
        &base64::engine::general_purpose::STANDARD,
        attestation_doc,
    )
    .expect("Failed to decode base64");

    verifier.verify_attestation_document(&attestation_doc_bytes)
}
