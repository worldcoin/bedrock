use super::types::PcrConfiguration;
use once_cell::sync::OnceCell;

/// AWS Nitro Root Certificate for Production
/// Source: <https://aws-nitro-enclaves.amazonaws.com/AWS_NitroEnclaves_Root-G1.zip>
/// Stored at `bedrock/src/nitro_enclave/aws_nitro_root_g1.der`
pub const AWS_NITRO_ROOT_CERT_PROD: &[u8] = include_bytes!("aws_nitro_root_g1.der");

/// AWS Nitro Root Certificate for Staging
/// Source: <https://aws-nitro-enclaves.amazonaws.com/AWS_NitroEnclaves_Root-G1.zip>
pub const AWS_NITRO_ROOT_CERT_STAGING: &[u8] = AWS_NITRO_ROOT_CERT_PROD;

/// Compile-time constants for PCR expected values (48 bytes each for SHA-384)
const PRODUCTION_PCR0_VALUE: &[u8] = &[0; 48];
const PRODUCTION_PCR1_VALUE: &[u8] = &[0; 48];
const PRODUCTION_PCR2_VALUE: &[u8] = &[0; 48];

/// Expected PCR configurations for production enclaves
static PRODUCTION_PCR_CONFIGS: OnceCell<Vec<PcrConfiguration>> = OnceCell::new();

/// Returns the lazily-initialized PCR configurations for production.
#[must_use]
pub fn production_pcr_configs() -> Vec<PcrConfiguration> {
    PRODUCTION_PCR_CONFIGS
        .get_or_init(|| {
            vec![
                PcrConfiguration {
                    index: 0,
                    expected_value: PRODUCTION_PCR0_VALUE.to_vec(),
                    description: "Production enclave image v1.0.0".to_string(),
                },
                PcrConfiguration {
                    index: 1,
                    expected_value: PRODUCTION_PCR1_VALUE.to_vec(),
                    description: "Production kernel and bootstrap".to_string(),
                },
                PcrConfiguration {
                    index: 2,
                    expected_value: PRODUCTION_PCR2_VALUE.to_vec(),
                    description: "Production application layer".to_string(),
                },
            ]
        })
        .clone()
}

// Compile-time constants for staging PCR expected values (48 bytes each for SHA-384)
const STAGING_PCR0_VALUE: &[u8] = &[0; 48];
const STAGING_PCR1_VALUE: &[u8] = &[0; 48];
const STAGING_PCR2_VALUE: &[u8] = &[0; 48];

/// Expected PCR configurations for staging enclaves
static STAGING_PCR_CONFIGS: OnceCell<Vec<PcrConfiguration>> = OnceCell::new();

/// Returns the lazily-initialized PCR configurations for staging.
#[must_use]
pub fn staging_pcr_configs() -> Vec<PcrConfiguration> {
    STAGING_PCR_CONFIGS
        .get_or_init(|| {
            vec![
                PcrConfiguration {
                    index: 0,
                    expected_value: STAGING_PCR0_VALUE.to_vec(),
                    description: "Staging enclave image v1.0.0-staging".to_string(),
                },
                PcrConfiguration {
                    index: 1,
                    expected_value: STAGING_PCR1_VALUE.to_vec(),
                    description: "Staging kernel and bootstrap".to_string(),
                },
                PcrConfiguration {
                    index: 2,
                    expected_value: STAGING_PCR2_VALUE.to_vec(),
                    description: "Staging application layer".to_string(),
                },
            ]
        })
        .clone()
}

/// Maximum age for attestation documents (in milliseconds)
pub const MAX_ATTESTATION_AGE_MILLISECONDS: u64 = 3 * 60 * 60 * 1000; // 3 hours

/// Minimum PCR value lengths
/// <https://docs.aws.amazon.com/enclaves/latest/user/verify-root.html>
pub const VALID_PCR_LENGTHS: &[usize] = &[32, 48, 64];
