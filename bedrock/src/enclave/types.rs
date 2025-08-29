//! Enclave attestation document types and data structures.
//!
//! This module contains the core types used for AWS Nitro Enclave attestation
//! document parsing, verification, and PCR configuration management.

use crate::primitives::PrimitiveError;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

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

    /// Primitive error
    #[error("Primitive error: {0}")]
    Primitive(#[from] PrimitiveError),
}

/// Result type for enclave attestation operations
pub type EnclaveAttestationResult<T, E = EnclaveAttestationError> = Result<T, E>;

/// PCR configuration
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PcrConfiguration {
    /// The index of the PCR value
    pub index: usize,
    /// The expected value of the PCR
    pub expected_value: Vec<u8>,
    /// The description of the PCR
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, uniffi::Record)]
/// Verified attestation data from the enclave.
pub struct VerifiedAttestation {
    /// The hex encoded public key of the enclave
    pub enclave_public_key: String,
    /// The PCR values of the enclave
    pub pcr_values: HashMap<u32, Vec<u8>>,
    /// The timestamp of the attestation
    pub timestamp: u64,
    /// The module ID of the enclave
    pub module_id: String,
}

impl VerifiedAttestation {
    /// Creates a new VerifiedAttestation
    ///
    /// # Arguments
    /// * `enclave_public_key` - The hex encoded public key of the enclave
    /// * `pcr_values` - The PCR values of the enclave
    /// * `timestamp` - The timestamp of the attestation
    pub fn new(
        enclave_public_key: String,
        pcr_values: HashMap<u32, Vec<u8>>,
        timestamp: u64,
        module_id: String,
    ) -> Self {
        Self {
            enclave_public_key,
            pcr_values,
            timestamp,
            module_id,
        }
    }
}
