use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

use aws_nitro_enclaves_nsm_api::api::AttestationDoc;
use base64::Engine;
use coset::{AsCborValue, CborSerializable, CoseSign1};
use p384::ecdsa::{signature::Verifier as _, Signature, VerifyingKey};
use webpki::{EndEntityCert, TrustAnchor};
use x509_cert::{der::Decode, Certificate};

use crate::{bedrock_export, primitives::config::BedrockEnvironment};

/// Constants for enclave verification
pub mod constants;

/// Types for enclave verification  
pub mod types;

#[cfg(test)]
mod tests;

pub use types::{
    EnclaveAttestationError, EnclaveAttestationResult, PcrConfiguration,
    VerifiedAttestation,
};

use constants::{
    production_pcr_configs, staging_pcr_configs, AWS_NITRO_ROOT_CERT_PROD,
    AWS_NITRO_ROOT_CERT_STAGING, MAX_ATTESTATION_AGE_MILLISECONDS, VALID_PCR_LENGTHS,
};

/// Verifies AWS Nitro Enclave attestation documents
///
/// This class performs comprehensive verification of attestation documents including:
/// - COSE Sign1 signature verification
/// - Certificate chain validation against AWS Nitro root certificates
/// - PCR (Platform Configuration Register) value validation  
/// - Attestation document freshness checks
/// - Public key extraction
#[derive(Debug, uniffi::Object)]
pub struct EnclaveAttestationVerifier {
    allowed_pcr_configs: Vec<PcrConfiguration>,
    root_certificate: Vec<u8>,
    max_age_millis: u64,
    #[cfg(test)]
    skip_certificate_time_check: bool,
}

#[bedrock_export]
impl EnclaveAttestationVerifier {
    /// Creates a new `EnclaveAttestationVerifier`
    ///
    /// # Arguments
    /// * `environment` - The environment to use for this verifier
    #[uniffi::constructor]
    #[must_use]
    pub fn new(environment: &BedrockEnvironment) -> Self {
        let allowed_pcr_configs = match environment {
            BedrockEnvironment::Production => production_pcr_configs(),
            BedrockEnvironment::Staging => staging_pcr_configs(),
        };

        let root_certificate = match environment {
            BedrockEnvironment::Production => AWS_NITRO_ROOT_CERT_PROD.to_vec(),
            BedrockEnvironment::Staging => AWS_NITRO_ROOT_CERT_STAGING.to_vec(),
        };

        Self {
            allowed_pcr_configs,
            root_certificate,
            max_age_millis: MAX_ATTESTATION_AGE_MILLISECONDS,
            #[cfg(test)]
            skip_certificate_time_check: false,
        }
    }

    /// Verifies a base64-encoded attestation document
    ///
    /// This is a convenience method that handles base64 decoding and then verifies the document
    ///
    /// # Arguments
    /// * `attestation_doc_base64` - The base64-encoded attestation document
    ///
    /// # Returns
    /// A verified attestation containing the enclave's public key and PCR values
    ///
    /// # Errors
    /// Returns an error if the base64 decoding fails or the attestation document verification fails
    pub fn verify_attestation_document_base64(
        &self,
        attestation_doc_base64: &str,
    ) -> EnclaveAttestationResult<VerifiedAttestation> {
        let attestation_doc_bytes = base64::engine::general_purpose::STANDARD
            .decode(attestation_doc_base64)
            .map_err(|e| {
                EnclaveAttestationError::AttestationDocumentParseError(format!(
                    "Failed to decode base64 attestation document: {e}"
                ))
            })?;

        self.verify_attestation_document(&attestation_doc_bytes)
    }

    /// Verifies the attestation document from the enclave.
    ///
    /// Follows the AWS Nitro Enclave Attestation Document Specification:
    /// <https://docs.aws.amazon.com/enclaves/latest/user/nitro-enclave-attestation-document.html>
    pub fn verify_attestation_document(
        &self,
        attestation_doc_bytes: &[u8],
    ) -> EnclaveAttestationResult<VerifiedAttestation> {
        // 1. Syntactical validation
        let cose_sign1 = self.parse_cose_sign1(attestation_doc_bytes)?;
        let attestation = self.parse_cbor_payload(&cose_sign1)?;

        // 2. Semantic validation
        let leaf_cert = self.verify_certificate_chain(&attestation)?;

        // 3. Cryptographic validation
        self.verify_cose_signature(&cose_sign1, &leaf_cert)?;
        self.validate_pcr_values(&attestation)?;
        self.check_attestation_freshness(&attestation)?;
        let public_key = self.extract_public_key(&attestation)?;

        Ok(VerifiedAttestation::new(
            hex::encode(public_key),
            attestation.timestamp,
            attestation.module_id,
        ))
    }
}

impl EnclaveAttestationVerifier {
    fn parse_cose_sign1(&self, bytes: &[u8]) -> EnclaveAttestationResult<CoseSign1> {
        // Validate before loading into buffer
        if bytes.is_empty() {
            return Err(EnclaveAttestationError::AttestationDocumentParseError(
                "Empty attestation document".to_string(),
            ));
        }

        let first_byte = bytes[0];
        if !(0x80..=0x97).contains(&first_byte) && first_byte != 0x9f {
            return Err(EnclaveAttestationError::AttestationDocumentParseError(
                format!("Invalid CBOR magic byte: expected array marker (0x80-0x97 or 0x9f), got 0x{first_byte:02x}")
            ));
        }

        let cbor_value: ciborium::Value =
            ciborium::from_reader(bytes).map_err(|e| {
                EnclaveAttestationError::AttestationDocumentParseError(format!(
                    "Failed to parse CBOR: {e}"
                ))
            })?;

        CoseSign1::from_cbor_value(cbor_value).map_err(|e| {
            EnclaveAttestationError::AttestationDocumentParseError(format!(
                "Failed to parse COSE Sign1: {e}"
            ))
        })
    }

    fn parse_cbor_payload(
        &self,
        cose_sign1: &CoseSign1,
    ) -> EnclaveAttestationResult<AttestationDoc> {
        let payload = cose_sign1.payload.as_ref().ok_or_else(|| {
            EnclaveAttestationError::AttestationDocumentParseError(
                "Missing payload in COSE Sign1".to_string(),
            )
        })?;

        ciborium::from_reader::<AttestationDoc, _>(payload.as_slice()).map_err(|e| {
            EnclaveAttestationError::AttestationDocumentParseError(format!(
                "Failed to parse attestation document: {e}"
            ))
        })
    }

    fn verify_certificate_chain(
        &self,
        attestation: &AttestationDoc,
    ) -> EnclaveAttestationResult<Certificate> {
        // Parse root certificate from PEM
        let pem_str = std::str::from_utf8(&self.root_certificate).map_err(|e| {
            EnclaveAttestationError::AttestationChainInvalid(format!(
                "Invalid PEM encoding: {e}"
            ))
        })?;
        let pem = pem::parse(pem_str).map_err(|e| {
            EnclaveAttestationError::AttestationChainInvalid(format!(
                "Failed to parse PEM: {e}"
            ))
        })?;
        let root_cert_der = pem.contents();

        // Create trust anchor from root certificate
        let trust_anchor =
            TrustAnchor::try_from_cert_der(root_cert_der).map_err(|e| {
                EnclaveAttestationError::AttestationChainInvalid(format!(
                    "Failed to create trust anchor from root certificate: {e}"
                ))
            })?;

        // Collect intermediate certificates from cabundle,
        let intermediate_certs: Vec<&[u8]> = attestation
            .cabundle
            .iter()
            .skip(1)
            .map(|cert| cert.as_slice())
            .collect();

        // Get current time for certificate validity checking
        let should_skip_time_check = {
            #[cfg(test)]
            {
                self.skip_certificate_time_check
            }
            #[cfg(not(test))]
            {
                false
            }
        };

        // This is only used for tests
        let current_time = if should_skip_time_check {
            // Use the attestation timestamp converted to seconds for certificate validation
            // This ensures we're using the same time context as when the attestation was created
            webpki::Time::from_seconds_since_unix_epoch(attestation.timestamp / 1000)
        } else {
            let now = SystemTime::now().duration_since(UNIX_EPOCH).map_err(|e| {
                EnclaveAttestationError::AttestationInvalidTimestamp(format!(
                    "Failed to get current time: {e}"
                ))
            })?;
            webpki::Time::from_seconds_since_unix_epoch(now.as_secs())
        };

        // Create end entity certificate from the leaf certificate
        let end_entity_cert = EndEntityCert::try_from(
            attestation.certificate.as_slice(),
        )
        .map_err(|e| {
            EnclaveAttestationError::AttestationChainInvalid(format!(
                "Failed to parse leaf certificate: {e}"
            ))
        })?;

        // Verify the certificate chain
        end_entity_cert
            .verify_is_valid_tls_server_cert(
                &[&webpki::ECDSA_P384_SHA384],
                &webpki::TlsServerTrustAnchors(&[trust_anchor]),
                &intermediate_certs,
                current_time,
            )
            .map_err(|e| {
                EnclaveAttestationError::AttestationChainInvalid(format!(
                    "Certificate chain validation failed: {e}"
                ))
            })?;

        // Parse the leaf certificate for return
        Certificate::from_der(&attestation.certificate).map_err(|e| {
            EnclaveAttestationError::AttestationChainInvalid(format!(
                "Failed to parse leaf certificate for return: {e}"
            ))
        })
    }

    fn verify_cose_signature(
        &self,
        cose_sign1: &CoseSign1,
        leaf_cert: &Certificate,
    ) -> EnclaveAttestationResult<()> {
        // Extract public key from certificate
        let spki = &leaf_cert.tbs_certificate.subject_public_key_info;
        let public_key_bytes = spki.subject_public_key.as_bytes().ok_or_else(|| {
            EnclaveAttestationError::AttestationSignatureInvalid(
                "Failed to extract public key bytes".to_string(),
            )
        })?;

        // Parse as P-384 public key
        let verifying_key =
            VerifyingKey::from_sec1_bytes(public_key_bytes).map_err(|e| {
                EnclaveAttestationError::AttestationSignatureInvalid(format!(
                    "Failed to parse P-384 public key: {e}"
                ))
            })?;

        let signature = &cose_sign1.signature;

        // Nitro uses P-384 signatures which should be exactly 96 bytes
        if signature.len() != 96 {
            return Err(EnclaveAttestationError::AttestationSignatureInvalid(
                format!(
                    "Invalid signature length: expected 96 bytes, got {}",
                    signature.len()
                ),
            ));
        }

        // Reconstruct the signed data according to COSE Sign1 structure
        let protected_bytes = cose_sign1.protected.clone().to_vec().map_err(|e| {
            EnclaveAttestationError::AttestationSignatureInvalid(format!(
                "Failed to serialize protected headers: {e}"
            ))
        })?;

        let payload = cose_sign1.payload.as_ref().ok_or_else(|| {
            EnclaveAttestationError::AttestationSignatureInvalid(
                "Missing payload in COSE Sign1".to_string(),
            )
        })?;

        // Create the Sig_structure for COSE_Sign1
        let mut sig_structure = Vec::new();
        let sig_structure_cbor = ciborium::Value::Array(vec![
            ciborium::Value::Text("Signature1".to_string()),
            ciborium::Value::Bytes(protected_bytes),
            ciborium::Value::Bytes(vec![]),
            ciborium::Value::Bytes(payload.clone()),
        ]);

        ciborium::into_writer(&sig_structure_cbor, &mut sig_structure).map_err(
            |e| {
                EnclaveAttestationError::AttestationSignatureInvalid(format!(
                    "Failed to encode Sig_structure: {e}"
                ))
            },
        )?;

        // Parse and verify the signature
        let ecdsa_signature =
            Signature::from_bytes(signature.as_slice().try_into().map_err(|_| {
                EnclaveAttestationError::AttestationSignatureInvalid(format!(
                    "Invalid signature length: expected 96 bytes, got {}",
                    signature.len()
                ))
            })?)
            .map_err(|e| {
                EnclaveAttestationError::AttestationSignatureInvalid(format!(
                    "Failed to parse ECDSA signature: {e}"
                ))
            })?;

        verifying_key
            .verify(&sig_structure, &ecdsa_signature)
            .map_err(|e| {
                EnclaveAttestationError::AttestationSignatureInvalid(format!(
                    "Signature verification failed: {e}"
                ))
            })?;

        Ok(())
    }

    fn validate_pcr_values(
        &self,
        attestation: &AttestationDoc,
    ) -> EnclaveAttestationResult<()> {
        if attestation.pcrs.is_empty() {
            return Err(EnclaveAttestationError::CodeUntrusted {
                pcr_index: 0,
                actual: "empty".to_string(),
            });
        }

        let mut configs_by_index: HashMap<usize, Vec<Vec<u8>>> = HashMap::new();
        for config in &self.allowed_pcr_configs {
            configs_by_index
                .entry(config.index)
                .or_default()
                .push(config.expected_value.clone());
        }

        for (index, actual_value) in &attestation.pcrs {
            let value_len = actual_value.len();
            if !VALID_PCR_LENGTHS.contains(&value_len) {
                return Err(EnclaveAttestationError::AttestationDocumentParseError(
                    format!(
                        "Invalid PCR{index} length: {value_len} bytes. Expected one of {VALID_PCR_LENGTHS:?}"
                    ),
                ));
            }

            if let Some(allowed_values) = configs_by_index.get(index) {
                if !allowed_values
                    .iter()
                    .any(|allowed| allowed == actual_value.as_slice())
                {
                    return Err(EnclaveAttestationError::CodeUntrusted {
                        pcr_index: *index,
                        actual: hex::encode(actual_value),
                    });
                }
            }
        }

        Ok(())
    }

    fn check_attestation_freshness(
        &self,
        attestation: &AttestationDoc,
    ) -> EnclaveAttestationResult<()> {
        let now = u64::try_from(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|e| {
                    EnclaveAttestationError::AttestationInvalidTimestamp(format!(
                        "Failed to get current time: {e}"
                    ))
                })?
                .as_millis(),
        )
        .map_err(|e| {
            EnclaveAttestationError::AttestationInvalidTimestamp(format!(
                "Failed to convert current time to milliseconds: {e}"
            ))
        })?;

        let age = now.checked_sub(attestation.timestamp).ok_or_else(|| {
            EnclaveAttestationError::AttestationInvalidTimestamp(format!(
                "Attestation timestamp is {} ms in the future",
                attestation.timestamp - now
            ))
        })?;

        if age > self.max_age_millis {
            return Err(EnclaveAttestationError::AttestationStale {
                age_millis: age,
                max_age: self.max_age_millis,
            });
        }

        Ok(())
    }

    fn extract_public_key(
        &self,
        attestation: &AttestationDoc,
    ) -> EnclaveAttestationResult<Vec<u8>> {
        attestation
            .public_key
            .clone()
            .map(|key| key.into_vec())
            .ok_or_else(|| {
                EnclaveAttestationError::InvalidEnclavePublicKey(
                    "No public key in attestation document".to_string(),
                )
            })
    }
}

#[cfg(test)]
impl EnclaveAttestationVerifier {
    /// Creates a new `EnclaveAttestationVerifier` with custom PCR configurations, used for testing.
    #[must_use]
    pub fn new_with_config_and_time_skip(
        allowed_pcr_configs: Vec<PcrConfiguration>,
        root_certificate: Vec<u8>,
        max_age_millis: u64,
        skip_certificate_time_check: bool,
    ) -> Self {
        Self {
            allowed_pcr_configs,
            root_certificate,
            max_age_millis,
            skip_certificate_time_check,
        }
    }

    /// Adds a custom PCR configuration, used for testing.
    pub fn add_allowed_pcr_config(&mut self, pcr_config: PcrConfiguration) {
        self.allowed_pcr_configs.push(pcr_config);
    }
}

/// Verify an enclave attestation document and extract the public key
///
/// This is a convenience function that creates a verifier from the global config
/// and verifies the base64-encoded attestation document.
#[uniffi::export]
pub fn verify_enclave_attestation_document(
    attestation_doc: &str,
) -> EnclaveAttestationResult<VerifiedAttestation> {
    let config = crate::primitives::config::get_config().ok_or(
        EnclaveAttestationError::AttestationDocumentParseError(
            "Bedrock config not initialized. Call set_config() first.".to_string(),
        ),
    )?;

    let verifier = EnclaveAttestationVerifier::new(&config.environment());
    verifier.verify_attestation_document_base64(attestation_doc)
}
