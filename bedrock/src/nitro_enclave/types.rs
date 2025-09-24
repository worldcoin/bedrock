//! Enclave attestation document types and data structures.
//!
//! This module contains the core types used for AWS Nitro Enclave attestation
//! document parsing, verification, and PCR configuration management.

use serde::{Deserialize, Serialize};

/// Represents errors that can occur during enclave attestation verification
#[crate::bedrock_error]
pub enum EnclaveAttestationError {
    /// Failed to parse attestation document
    #[error("Failed to parse attestation document: {0}")]
    AttestationDocumentParseError(String),

    /// Certificate chain validation failed
    #[error("Certificate chain validation failed: {0}")]
    AttestationChainInvalid(String),

    /// Signature verification failed
    #[error("Signature verification failed: {0}")]
    AttestationSignatureInvalid(String),

    /// PCR value did not match the expected value
    #[error("PCR{pcr_index} value not trusted: {actual}")]
    CodeUntrusted {
        /// The index of the PCR value that failed validation
        pcr_index: usize,
        /// The actual value of the PCR that failed validation
        actual: String,
    },

    /// Attestation timestamp is too old
    #[error("Attestation is too old: {age_millis}ms (max: {max_age}ms)")]
    AttestationStale {
        /// The age of the attestation in milliseconds
        age_millis: u64,
        /// The maximum age of the attestation in milliseconds
        max_age: u64,
    },

    /// Invalid timestamp
    #[error("Invalid timestamp: {0}")]
    AttestationInvalidTimestamp(String),

    /// Invalid enclave public key
    #[error("Invalid enclave public key: {0}")]
    InvalidEnclavePublicKey(String),

    /// Failed to encrypt data
    #[error("Failed to encrypt data")]
    EncryptionError,
}

/// Result type for enclave attestation operations
pub type EnclaveAttestationResult<T, E = EnclaveAttestationError> = Result<T, E>;

/// PCR configuration
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PcrConfiguration {
    /// The index of the PCR{index} value
    /// eg. 0, 1, 2, 3, 4, 8
    pub index: usize,
    /// The expected value of the PCR
    pub expected_value: Vec<u8>,
    /// The description of the PCR
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, uniffi::Record)]
/// Verified attestation data from the enclave.
pub struct VerifiedAttestation {
    /// The base64 encoded public key of the enclave
    pub enclave_public_key: String,

    /// The timestamp of the attestation
    pub timestamp: u64,
    /// The module ID of the enclave
    pub module_id: String,
}

impl VerifiedAttestation {
    /// Creates a new `VerifiedAttestation`
    ///
    /// # Arguments
    /// * `enclave_public_key` - The hex encoded public key of the enclave
    /// * `pcr_values` - The PCR values of the enclave
    /// * `timestamp` - The timestamp of the attestation
    #[must_use]
    pub const fn new(
        enclave_public_key: String,
        timestamp: u64,
        module_id: String,
    ) -> Self {
        Self {
            enclave_public_key,
            timestamp,
            module_id,
        }
    }
}

/// Verified attestation with ciphertext
#[derive(Debug, Clone, Serialize, Deserialize, uniffi::Record)]
pub struct VerifiedAttestationWithCiphertext {
    /// The verified attestation
    pub verified_attestation: VerifiedAttestation,
    /// The base64 encoded ciphertext
    pub ciphertext_base64: String,
}
