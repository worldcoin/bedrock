#![doc = include_str!("device_proof/README.md")]

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use bedrock_macros::{bedrock_error, bedrock_export};
use p256_auth::ecdsa::signature::hazmat::PrehashSigner;
use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::{primitives::ntp::now_with_ntp, root_key::RootKey};

const PROOF_DOMAIN: &[u8] = b"WORLD-ID/IDP/DEVICE-PROOF/V1\0";

/// A device proof's public material. The mobile bridge adds `credential_type: "device"`.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct WorldIdDeviceProof {
    /// Compressed SEC1 P-256 public key, encoded as unpadded base64url.
    pub public_key: String,
    /// Low-S DER ECDSA signature, encoded as unpadded base64url.
    pub signature: String,
}

/// Failures when validating or signing an Auth device challenge.
#[bedrock_error]
pub enum DeviceProofError {
    /// The request is malformed, expired, or does not belong to the trusted issuer.
    #[error("invalid World ID device proof challenge")]
    InvalidChallenge,
    /// Key derivation or signing failed.
    #[error("World ID device proof signing failed: {error_message}")]
    Signing {
        /// Safe operation context, without key or challenge material.
        error_message: String,
    },
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Challenge {
    version: u8,
    issuer: String,
    ceremony_id: String,
    nonce: String,
    expires_at: i64,
}

#[bedrock_export]
impl RootKey {
    /// Approves an Auth challenge using the dedicated, restorable device key.
    ///
    /// `challenge` is the exact decoded JSON byte string from `device_proof_request.challenge`.
    /// `expected_issuer` must come from trusted app configuration, never the QR or request.
    ///
    /// # Errors
    /// Rejects invalid, expired, or foreign challenges and propagates signing failures.
    pub fn create_world_id_device_proof(
        &self,
        challenge: &[u8],
        expected_issuer: &str,
    ) -> Result<WorldIdDeviceProof, DeviceProofError> {
        create(self, challenge, expected_issuer, now_with_ntp().timestamp())
    }
}

fn create(
    root: &RootKey,
    bytes: &[u8],
    expected_issuer: &str,
    now: i64,
) -> Result<WorldIdDeviceProof, DeviceProofError> {
    if bytes.is_empty() || bytes.len() > 1024 {
        return Err(DeviceProofError::InvalidChallenge);
    }
    let challenge: Challenge = serde_json::from_slice(bytes)
        .map_err(|_| DeviceProofError::InvalidChallenge)?;
    let issuer: http::Uri = expected_issuer
        .parse()
        .map_err(|_| DeviceProofError::InvalidChallenge)?;
    let valid_origin = issuer.authority().is_some()
        && !expected_issuer.contains('@')
        && issuer.path() == "/"
        && issuer.query().is_none()
        && (issuer.scheme_str() == Some("https")
            || (issuer.scheme_str() == Some("http")
                && matches!(issuer.host(), Some("127.0.0.1" | "localhost"))));
    let nonce = URL_SAFE_NO_PAD
        .decode(&challenge.nonce)
        .map_err(|_| DeviceProofError::InvalidChallenge)?;
    let ceremony = uuid::Uuid::parse_str(&challenge.ceremony_id)
        .map_err(|_| DeviceProofError::InvalidChallenge)?;
    if !valid_origin
        || challenge.version != 1
        || challenge.issuer != expected_issuer
        || ceremony.is_nil()
        || ceremony.hyphenated().to_string() != challenge.ceremony_id
        || nonce.len() != 32
        || URL_SAFE_NO_PAD.encode(&nonce) != challenge.nonce
        || challenge.expires_at <= now
        // Allow 30 seconds of clock skew around the server's five-minute maximum.
        || challenge.expires_at.saturating_sub(now) > 330
    {
        return Err(DeviceProofError::InvalidChallenge);
    }
    let key =
        root.derive_device_proof_key()
            .map_err(|_| DeviceProofError::Signing {
                error_message: "derive Auth key".to_string(),
            })?;
    let digest = Sha256::new()
        .chain_update(PROOF_DOMAIN)
        .chain_update(bytes)
        .finalize();
    let signature: p256_auth::ecdsa::Signature =
        key.sign_prehash(&digest)
            .map_err(|_| DeviceProofError::Signing {
                error_message: "sign Auth challenge".to_string(),
            })?;
    let signature = signature.normalize_s();
    Ok(WorldIdDeviceProof {
        public_key: URL_SAFE_NO_PAD
            .encode(key.verifying_key().to_sec1_point(true).as_bytes()),
        signature: URL_SAFE_NO_PAD.encode(signature.to_der().as_bytes()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: i64 = 2_000_000_000;
    const CHALLENGE: &str = r#"{"version":1,"issuer":"https://auth.world.org","ceremony_id":"019af784-3d00-7000-8000-000000000001","nonce":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","expires_at":2000000300}"#;

    #[test]
    fn restored_roots_match_the_cross_language_vectors() {
        #[derive(Deserialize)]
        struct Vector {
            root_key_json: String,
            public_key: String,
            signature: String,
        }
        #[derive(Deserialize)]
        struct Fixture {
            now: i64,
            issuer: String,
            challenge: String,
            vectors: Vec<Vector>,
        }
        let fixture: Fixture =
            serde_json::from_str(include_str!("device_proof/testdata/v1.json"))
                .unwrap();
        for vector in fixture.vectors {
            let root = RootKey::from_json(&vector.root_key_json).unwrap();
            let proof = create(
                &root,
                fixture.challenge.as_bytes(),
                &fixture.issuer,
                fixture.now,
            )
            .unwrap();
            assert_eq!(
                proof,
                WorldIdDeviceProof {
                    public_key: vector.public_key,
                    signature: vector.signature
                }
            );
            let restored = RootKey::from_json(&root.danger_to_json().unwrap()).unwrap();
            assert_eq!(
                proof,
                create(
                    &restored,
                    fixture.challenge.as_bytes(),
                    &fixture.issuer,
                    fixture.now
                )
                .unwrap()
            );
        }
    }

    #[test]
    fn public_api_signs_a_current_challenge() {
        use p256_auth::ecdsa::signature::hazmat::PrehashVerifier;
        let root = RootKey::from_json(&format!(
            r#"{{"version":"V1","key":"{}"}}"#,
            "11".repeat(32)
        ))
        .unwrap();
        let bytes = CHALLENGE
            .replace(
                "2000000300",
                &(now_with_ntp().timestamp() + 300).to_string(),
            )
            .into_bytes();
        let proof = root
            .create_world_id_device_proof(&bytes, "https://auth.world.org")
            .unwrap();
        assert_eq!(
            proof.public_key,
            "A78Nb3lXB_knP6aCAH-jz__oN54VcvsG8pPSq4Nb1JNI"
        );
        let key = p256_auth::ecdsa::VerifyingKey::from_sec1_bytes(
            &URL_SAFE_NO_PAD.decode(proof.public_key).unwrap(),
        )
        .unwrap();
        let signature = p256_auth::ecdsa::Signature::from_der(
            &URL_SAFE_NO_PAD.decode(proof.signature).unwrap(),
        )
        .unwrap();
        let digest = Sha256::new()
            .chain_update(PROOF_DOMAIN)
            .chain_update(bytes)
            .finalize();
        key.verify_prehash(&digest, &signature).unwrap();
    }

    #[test]
    fn rejects_foreign_expired_and_malformed_challenges() {
        let root = RootKey::from_json(&format!(
            r#"{{"version":"V1","key":"{}"}}"#,
            "11".repeat(32)
        ))
        .unwrap();
        assert!(
            create(&root, CHALLENGE.as_bytes(), "https://auth.world.org", NOW).is_ok()
        );
        assert!(
            create(&root, CHALLENGE.as_bytes(), "https://other.world.org", NOW)
                .is_err()
        );
        assert!(create(
            &root,
            CHALLENGE.as_bytes(),
            "https://auth.world.org",
            NOW + 300
        )
        .is_err());
        for bytes in [
            CHALLENGE.replace("\"version\":1", "\"version\":2"),
            CHALLENGE.replace("\"version\":1", "\"version\":1,\"version\":1"),
            CHALLENGE.replace("2000000300", "2000000331"),
        ] {
            assert!(
                create(&root, bytes.as_bytes(), "https://auth.world.org", NOW).is_err()
            );
        }
    }
}
