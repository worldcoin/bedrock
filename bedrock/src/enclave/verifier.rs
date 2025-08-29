use super::constants::{
    production_pcr_configs, staging_pcr_configs, AWS_NITRO_ROOT_CERT_PROD,
    AWS_NITRO_ROOT_CERT_STAGING, MAX_ATTESTATION_AGE_MILLISECONDS, VALID_PCR_LENGTHS,
};
use super::types::{
    EnclaveAttestationError, EnclaveAttestationResult, PcrConfiguration,
    VerifiedAttestation,
};
use crate::primitives::config::BedrockEnvironment;
use aws_nitro_enclaves_nsm_api::api::AttestationDoc;
use coset::{AsCborValue, CborSerializable, CoseSign1};
use p384::ecdsa::{signature::Verifier as _, Signature, VerifyingKey};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};
use webpki::{EndEntityCert, TrustAnchor};
use x509_cert::{der::Decode, Certificate};

/// Verifies the attestation document from the enclave.
///
/// # Arguments
/// * `environment` - The environment to use for this verifier
///
/// # Examples
pub struct EnclaveAttestationVerifier {
    allowed_pcr_configs: Vec<PcrConfiguration>,
    root_certificate: Vec<u8>,
    max_age_millis: u64,
    #[cfg(test)]
    skip_certificate_time_check: bool,
}

impl EnclaveAttestationVerifier {
    /// Creates a new EnclaveAttestationVerifier
    ///
    /// # Arguments
    /// * `environment` - The environment to use for this verifier
    ///
    /// # Examples
    pub fn new(environment: &BedrockEnvironment) -> Self {
        let allowed_pcr_configs = match environment {
            BedrockEnvironment::Production => production_pcr_configs(),
            BedrockEnvironment::Staging => staging_pcr_configs(),
        };

        let root_certificate = match environment {
            BedrockEnvironment::Production => AWS_NITRO_ROOT_CERT_PROD.to_vec(),
            BedrockEnvironment::Staging => AWS_NITRO_ROOT_CERT_STAGING.to_vec(),
        };
        // We are using 3 hours as the max age because the certificate is valid for 3 hours
        // https://aws.amazon.com/blogs/compute/validating-attestation-documents-produced-by-aws-nitro-enclaves/
        Self {
            allowed_pcr_configs,
            root_certificate,
            max_age_millis: MAX_ATTESTATION_AGE_MILLISECONDS, // 3 HOURS
            #[cfg(test)]
            skip_certificate_time_check: false,
        }
    }

    /// Creates a new EnclaveAttestationVerifier with custom PCR configurations, used for testing.
    ///
    /// # Arguments
    /// * `allowed_pcr_configs` - The PCR configurations to use for this verifier
    /// * `root_certificate` - The root certificate to use for this verifier
    /// * `max_age_millis` - The maximum age of the attestation document in milliseconds
    /// * `skip_certificate_time_check` - Whether to skip certificate time validation
    #[cfg(test)]
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
    ///
    /// # Arguments
    /// * `pcr_config` - The PCR configuration to add
    #[cfg(test)]
    pub fn add_allowed_pcr_config(&mut self, pcr_config: PcrConfiguration) {
        self.allowed_pcr_configs.push(pcr_config);
    }

    /// Verifies the attestation document from the enclave.
    ///
    /// Follows the AWS Nitro Enclave Attestation Document Specification:
    /// https://docs.aws.amazon.com/enclaves/latest/user/nitro-enclave-attestation-document.html
    ///
    /// # Arguments
    /// * `attestation_doc_bytes` - The bytes of the attestation document
    ///
    /// # Examples
    pub fn verify_attestation_document(
        &self,
        attestation_doc_bytes: &[u8],
    ) -> EnclaveAttestationResult<VerifiedAttestation, EnclaveAttestationError> {
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

        // Convert BTreeMap<usize, ByteBuf> to HashMap<u32, Vec<u8>>
        let pcr_values_u32: HashMap<u32, Vec<u8>> = attestation
            .pcrs
            .into_iter()
            .map(|(k, v)| (k as u32, v.into_vec()))
            .collect();

        Ok(VerifiedAttestation::new(
            hex::encode(public_key),
            pcr_values_u32,
            attestation.timestamp,
            attestation.module_id.clone(),
        ))
    }

    /// Parses the COSE Sign1 structure from the attestation document.
    ///
    /// # Arguments
    /// * `bytes` - The bytes of the attestation document
    ///
    /// # Examples
    fn parse_cose_sign1(&self, bytes: &[u8]) -> EnclaveAttestationResult<CoseSign1> {
        let cbor_value: ciborium::Value =
            ciborium::from_reader(bytes).map_err(|e| {
                EnclaveAttestationError::AttestationDocumentParseError(format!(
                    "Failed to parse CBOR: {}",
                    e
                ))
            })?;

        CoseSign1::from_cbor_value(cbor_value).map_err(|e| {
            EnclaveAttestationError::AttestationDocumentParseError(format!(
                "Failed to parse COSE Sign1: {}",
                e
            ))
        })
    }

    /// Parses the CBOR payload from the attestation document.
    ///
    /// # Arguments
    /// * `cose_sign1` - The COSE Sign1 structure to parse
    ///
    /// # Examples
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
                "Failed to parse attestation document: {}",
                e
            ))
        })
    }

    /// Verifies the certificate chain from the attestation document.
    ///
    /// This performs full certificate chain validation including:
    /// - Verifying the chain roots to our trusted AWS Nitro root certificate
    /// - Checking certificate signatures
    /// - Validating certificate validity periods (unless skipped in tests)
    ///
    /// # Arguments
    /// * `attestation` - The attestation document to verify
    fn verify_certificate_chain(
        &self,
        attestation: &AttestationDoc,
    ) -> EnclaveAttestationResult<Certificate> {
        // Parse root certificate from PEM
        let pem_str = std::str::from_utf8(&self.root_certificate).map_err(|e| {
            EnclaveAttestationError::AttestationChainInvalid(format!(
                "Invalid PEM encoding: {}",
                e
            ))
        })?;
        let pem = pem::parse(pem_str).map_err(|e| {
            EnclaveAttestationError::AttestationChainInvalid(format!(
                "Failed to parse PEM: {}",
                e
            ))
        })?;
        let root_cert_der = pem.contents();

        // Create trust anchor from root certificate
        let trust_anchor =
            TrustAnchor::try_from_cert_der(&root_cert_der).map_err(|e| {
                EnclaveAttestationError::AttestationChainInvalid(format!(
                    "Failed to create trust anchor from root certificate: {}",
                    e
                ))
            })?;

        // Collect intermediate certificates from cabundle
        // Skip the first certificate in cabundle as it's typically the root cert
        let intermediate_certs: Vec<&[u8]> = attestation
            .cabundle
            .iter()
            .skip(1)
            .map(|cert| cert.as_slice())
            .collect();

        // Get current time for certificate validity checking
        #[cfg(test)]
        let current_time = if self.skip_certificate_time_check {
            // Use a fixed time for testing when skip_certificate_time_check is true
            webpki::Time::from_seconds_since_unix_epoch(0)
        } else {
            let now = SystemTime::now().duration_since(UNIX_EPOCH).map_err(|e| {
                EnclaveAttestationError::AttestationInvalidTimestamp(format!(
                    "Failed to get current time: {}",
                    e
                ))
            })?;
            webpki::Time::from_seconds_since_unix_epoch(now.as_secs())
        };
        
        #[cfg(not(test))]
        let current_time = {
            let now = SystemTime::now().duration_since(UNIX_EPOCH).map_err(|e| {
                EnclaveAttestationError::AttestationInvalidTimestamp(format!(
                    "Failed to get current time: {}",
                    e
                ))
            })?;
            webpki::Time::from_seconds_since_unix_epoch(now.as_secs())
        };

        // Create end entity certificate from the leaf certificate
        let leaf_cert_der = &attestation.certificate;
        let end_entity_cert = EndEntityCert::try_from(leaf_cert_der.as_slice())
            .map_err(|e| {
                EnclaveAttestationError::AttestationChainInvalid(format!(
                    "Failed to parse leaf certificate: {}",
                    e
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
                    "Certificate chain validation failed: {}",
                    e
                ))
            })?;

        // Parse the leaf certificate for return (we still need it for signature verification)
        let leaf_cert =
            Certificate::from_der(&attestation.certificate).map_err(|e| {
                EnclaveAttestationError::AttestationChainInvalid(format!(
                    "Failed to parse leaf certificate for return: {}",
                    e
                ))
            })?;

        Ok(leaf_cert)
    }

    /// Verifies the COSE signature on the attestation document.
    ///
    /// The signature on the attestation document is created with the key pair inside the certificate
    /// Reference C implementation from AWS is below:
    /// https://docs.aws.amazon.com/enclaves/latest/user/nitro-enclave-attestation-document.html
    ///
    /// # Arguments
    /// * `cose_sign1` - The COSE Sign1 structure to verify
    /// * `leaf_cert` - The leaf certificate to verify
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
                    "Failed to parse P-384 public key: {}",
                    e
                ))
            })?;

        let signature = &cose_sign1.signature;

        // Nitro uses P-384 signatures which should be exactly 96 bytes (48 bytes for R, 48 bytes for S)
        if signature.len() != 96 {
            return Err(EnclaveAttestationError::AttestationSignatureInvalid(
                format!(
                    "Invalid signature length: expected 96 bytes, got {}",
                    signature.len()
                ),
            ));
        }

        // Reconstruct the signed data according to COSE Sign1 structure (RFC 8152 Section 4.4)
        // The signature is over the Sig_structure which contains:
        // 1. Context string "Signature1"
        // 2. Protected headers (as bytes)
        // 3. External AAD (empty for AWS Nitro Enclaves)
        // 4. Payload
        let protected_bytes = cose_sign1.protected.clone().to_vec().map_err(|e| {
            EnclaveAttestationError::AttestationSignatureInvalid(format!(
                "Failed to serialize protected headers: {}",
                e
            ))
        })?;

        let payload = cose_sign1.payload.as_ref().ok_or_else(|| {
            EnclaveAttestationError::AttestationSignatureInvalid(
                "Missing payload in COSE Sign1".to_string(),
            )
        })?;

        // Create the Sig_structure for COSE_Sign1
        // According to RFC 8152 Section 4.4, this must be encoded as a CBOR array
        let mut sig_structure = Vec::new();

        // Encode as CBOR array with 4 elements
        let sig_structure_cbor = ciborium::Value::Array(vec![
            ciborium::Value::Text("Signature1".to_string()), // Context: https://www.rfc-editor.org/rfc/rfc8152.html#section-4.4
            ciborium::Value::Bytes(protected_bytes),         // Protected headers
            ciborium::Value::Bytes(vec![]), // Nitro does not use the unprotected headers
            ciborium::Value::Bytes(payload.clone()), // Payload
        ]);

        ciborium::into_writer(&sig_structure_cbor, &mut sig_structure).map_err(
            |e| {
                EnclaveAttestationError::AttestationSignatureInvalid(format!(
                    "Failed to encode Sig_structure: {}",
                    e
                ))
            },
        )?;

        // The signature in COSE is in raw R||S format (48 bytes each for P-384)
        // p384 crate expects this exact format for from_bytes
        let ecdsa_signature =
            Signature::from_bytes(signature.as_slice().try_into().map_err(|_| {
                EnclaveAttestationError::AttestationSignatureInvalid(format!(
                    "Invalid signature length: expected 96 bytes, got {}",
                    signature.len()
                ))
            })?)
            .map_err(|e| {
                EnclaveAttestationError::AttestationSignatureInvalid(format!(
                    "Failed to parse ECDSA signature: {}",
                    e
                ))
            })?;

        // AWS Nitro Enclaves use P-384 with SHA-384 for signing
        // The verify method will internally hash with SHA-384
        verifying_key
            .verify(&sig_structure, &ecdsa_signature)
            .map_err(|e| {
                EnclaveAttestationError::AttestationSignatureInvalid(format!(
                    "Signature verification failed: {}",
                    e
                ))
            })?;

        Ok(())
    }

    /// Validates the PCR values from the attestation document.
    ///
    /// # Arguments
    /// * `attestation` - The attestation document to validate
    ///
    /// # Examples
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
                .or_insert_with(Vec::new)
                .push(config.expected_value.clone());
        }

        for (index, actual_value) in &attestation.pcrs {
            let value_len = actual_value.len();
            if !VALID_PCR_LENGTHS.contains(&value_len) {
                return Err(EnclaveAttestationError::AttestationDocumentParseError(
                    format!(
                        "Invalid PCR{} length: {} bytes. Expected one of {:?}",
                        index, value_len, VALID_PCR_LENGTHS
                    ),
                ));
            }

            if let Some(allowed_values) = configs_by_index.get(index) {
                if !allowed_values
                    .iter()
                    .any(|allowed| allowed == &actual_value.as_slice())
                {
                    return Err(EnclaveAttestationError::CodeUntrusted {
                        pcr_index: *index,
                        actual: hex::encode(&actual_value),
                    });
                }
            }
        }

        Ok(())
    }

    /// Checks the freshness of the attestation document.
    ///
    /// # Arguments
    /// * `attestation` - The attestation document to check
    ///
    /// # Examples
    fn check_attestation_freshness(
        &self,
        attestation: &AttestationDoc,
    ) -> EnclaveAttestationResult<()> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| {
                EnclaveAttestationError::AttestationInvalidTimestamp(format!(
                    "Failed to get current time: {}",
                    e
                ))
            })?
            .as_millis() as u64;

        let age = now.checked_sub(attestation.timestamp).ok_or_else(|| {
            EnclaveAttestationError::AttestationInvalidTimestamp(format!(
                "Attestation timestamp is {} ms in the future",
                attestation.timestamp - now
            ))
        })?;

        let max_age = self.max_age_millis;
        if age > max_age {
            return Err(EnclaveAttestationError::AttestationStale {
                age_millis: age,
                max_age: self.max_age_millis,
            });
        }

        Ok(())
    }

    /// Extracts the public key from the attestation document.
    ///
    /// # Arguments
    /// * `attestation` - The attestation document to extract the public key from
    ///
    /// # Examples
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
