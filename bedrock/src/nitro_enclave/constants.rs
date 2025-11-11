use std::collections::HashMap;

use crate::nitro_enclave::types::{EnclaveApplication, PcrMeasurement};

use aws_nitro_enclaves_nsm_api::api::Digest;
use once_cell::sync::OnceCell;

/// AWS Nitro Root Certificate for Production
/// Source: <https://aws-nitro-enclaves.amazonaws.com/AWS_NitroEnclaves_Root-G1.zip>
/// Stored at `bedrock/src/nitro_enclave/aws_nitro_root_g1.der`
pub const AWS_NITRO_ROOT_CERT_PROD: &[u8] = include_bytes!("aws_nitro_root_g1.der");

/// AWS Nitro Root Certificate for Staging
/// Source: <https://aws-nitro-enclaves.amazonaws.com/AWS_NitroEnclaves_Root-G1.zip>
pub const AWS_NITRO_ROOT_CERT_STAGING: &[u8] = AWS_NITRO_ROOT_CERT_PROD;

/// Compile-time constants for PCR expected values (48 bytes each for SHA-384)
const PROD_WORLD_CHAT_NOTIFICATIONS_V1_PCR0_VALUE: [u8; 48] = [0; 48];
const PROD_WORLD_CHAT_NOTIFICATIONS_V1_PCR1_VALUE: [u8; 48] = [0; 48];
const PROD_WORLD_CHAT_NOTIFICATIONS_V1_PCR2_VALUE: [u8; 48] = [0; 48];

/// Expected PCR configurations for production enclaves
static PRODUCTION_PCR_CONFIGS: OnceCell<
    HashMap<EnclaveApplication, Vec<Vec<PcrMeasurement>>>,
> = OnceCell::new();

/// Returns the lazily-initialized PCR configurations for production.
///
/// # Panics
///
/// This function will panic if the `enclave_application` is not found in the configurations.
/// This should not happen and we have tests to ensure all applications are covered.
#[must_use]
pub fn production_pcr_configs(
    enclave_application: &EnclaveApplication,
) -> Vec<Vec<PcrMeasurement>> {
    PRODUCTION_PCR_CONFIGS
        .get_or_init(|| {
            let mut map: HashMap<EnclaveApplication, Vec<Vec<PcrMeasurement>>> =
                HashMap::new();
            map.insert(
                EnclaveApplication::WorldChatNotifications,
                vec![vec![
                    PcrMeasurement::new(
                        0,
                        PROD_WORLD_CHAT_NOTIFICATIONS_V1_PCR0_VALUE.to_vec(),
                    ),
                    PcrMeasurement::new(
                        1,
                        PROD_WORLD_CHAT_NOTIFICATIONS_V1_PCR1_VALUE.to_vec(),
                    ),
                    PcrMeasurement::new(
                        2,
                        PROD_WORLD_CHAT_NOTIFICATIONS_V1_PCR2_VALUE.to_vec(),
                    ),
                ]],
            );
            map
        })
        .get(enclave_application)
        .unwrap()
        .clone()
}

// Compile-time constants for staging PCR expected values (48 bytes each for SHA-384)
const STAGING_PCR0_VALUE: [u8; 48] = [0; 48];
const STAGING_PCR1_VALUE: [u8; 48] = [0; 48];
const STAGING_PCR2_VALUE: [u8; 48] = [0; 48];

/// Expected PCR configurations for staging enclaves
static STAGING_PCR_CONFIGS: OnceCell<
    HashMap<EnclaveApplication, Vec<Vec<PcrMeasurement>>>,
> = OnceCell::new();

/// Returns the lazily-initialized PCR configurations for staging.
///
/// # Panics
///
/// Panics if the enclave application is not found in the staging configurations.
/// This should not happen and we have tests to ensure all applications are covered.
#[must_use]
pub fn staging_pcr_configs(
    enclave_application: &EnclaveApplication,
) -> Vec<Vec<PcrMeasurement>> {
    STAGING_PCR_CONFIGS
        .get_or_init(|| {
            let mut map: HashMap<EnclaveApplication, Vec<Vec<PcrMeasurement>>> =
                HashMap::new();
            map.insert(
                EnclaveApplication::WorldChatNotifications,
                vec![vec![
                    PcrMeasurement::new(0, STAGING_PCR0_VALUE.to_vec()),
                    PcrMeasurement::new(1, STAGING_PCR1_VALUE.to_vec()),
                    PcrMeasurement::new(2, STAGING_PCR2_VALUE.to_vec()),
                ]],
            );
            map
        })
        .get(enclave_application)
        .unwrap()
        .clone()
}

/// Maximum age for attestation documents (in milliseconds)
pub const MAX_ATTESTATION_AGE_MILLISECONDS: u64 = 3 * 60 * 60 * 1000; // 3 hours

/// Get the expected PCR length depending on the hashing algorithm used
/// As of right now, only SHA-384 is used
/// More info: <https://docs.aws.amazon.com/enclaves/latest/user/set-up-attestation.html>
#[must_use]
pub const fn get_expected_pcr_length(digest: Digest) -> usize {
    match digest {
        Digest::SHA384 => 48,
        Digest::SHA256 => 32,
        Digest::SHA512 => 64,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pcr_configs() {
        let production_configs =
            production_pcr_configs(&EnclaveApplication::WorldChatNotifications);
        assert_eq!(production_configs.len(), 1);
        let staging_configs =
            staging_pcr_configs(&EnclaveApplication::WorldChatNotifications);
        assert_eq!(staging_configs.len(), 1);
    }
}
