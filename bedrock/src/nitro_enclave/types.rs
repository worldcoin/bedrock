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
        pcr_index: u32,
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
    /// The ciphertext bytes
    pub ciphertext: Vec<u8>,
}

/// Enum representing different enclave applications
#[derive(PartialEq, Eq, Hash, uniffi::Enum)]
pub enum EnclaveApplication {
    /// World Chat Notifications Enclave
    WorldChatNotifications,
}

/// Represents a PCR measurement with its index and value
/// Used to define expected PCR values for attestation verification
#[derive(Clone, Debug)]
pub struct PcrMeasurement {
    /// Index of the PCR measurement
    pub index: u32,
    /// Byte array representing the PCR value
    pub value: Vec<u8>,
}

impl PcrMeasurement {
    /// Creates a new `PcrMeasurement`
    ///
    /// # Arguments
    /// * `pcr_index` - The index of the PCR
    /// * `pcr_value` - The expected value of the PCR
    #[must_use]
    pub const fn new(index: u32, value: Vec<u8>) -> Self {
        Self { index, value }
    }

    /// Creates a new `PcrMeasurement` from a hex string
    ///
    /// # Panics
    ///
    /// Panics if the provided hex string is not valid hex.
    #[must_use]
    pub fn from_hex(index: u32, value_hex: &str) -> Self {
        Self {
            index,
            value: hex::decode(value_hex).unwrap(),
        }
    }
}
