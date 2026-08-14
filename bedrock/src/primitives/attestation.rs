//! Foreign-implemented attestation-token provider.
//!
//! Some backend calls sit behind TFH's [Attestation Gateway](https://github.com/worldcoin/attestation-gateway),
//! requiring an attestation token.

use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::sync::{Arc, OnceLock};

use crate::HttpError;

/// Global attestation-token provider set by the host.
static ATTESTATION_PROVIDER: OnceLock<Arc<AttestationGateway>> = OnceLock::new();

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
    if ATTESTATION_PROVIDER.get().is_some() {
        return false;
    }
    let gateway = AttestationGateway::new(provider);
    ATTESTATION_PROVIDER.set(Arc::new(gateway)).is_ok()
}

/// Returns the configured attestation-token provider, if any.
#[must_use]
pub fn get_attestation_provider() -> Option<Arc<AttestationGateway>> {
    ATTESTATION_PROVIDER.get().cloned()
}

/// Enables hashing and token computation for endpoints requiring an Attesetation Gateway token
pub struct AttestationGateway {
    pub(crate) provider: Arc<dyn AttestationTokenProvider>,
}

impl AttestationGateway {
    /// Initializes a new Attestation Gateway provider
    pub fn new(provider: Arc<dyn AttestationTokenProvider>) -> Self {
        Self { provider }
    }

    /// Fetches a fully qualified Attestation Gateway token for a specific JSON request.
    ///
    /// # Errors
    /// If the native provider cannot assert to the request (e.g. Apple/Google/AttestationGateway downtime).
    pub async fn assert_json_request(
        &self,
        method: &str,
        path_uri: &str,
        body: &[u8],
    ) -> Result<String, HttpError> {
        let request_hash = self.hash_for_json_request(method, path_uri, body)?;

        self.provider.attestation_token(request_hash).await
    }

    /// Computes the expected hash for a JSON request matching the verification
    /// logic of the backup-service.
    ///
    /// # Errors
    /// Not expected as all payloads are constructed in the library.
    pub fn hash_for_json_request(
        &self,
        method: &str,
        path_uri: &str,
        body: &[u8],
    ) -> Result<String, HttpError> {
        let mut map = Map::new();

        // Important to keep keys' order
        if !body.is_empty() {
            let body_json: Value =
                serde_json::from_slice(body).map_err(|_| HttpError::Generic {
                    error_message: "unexpected. attestation body is not valid JSON"
                        .to_string(),
                })?;
            map.insert("body".to_string(), sort_json(&body_json));
        }
        map.insert("method".to_string(), Value::String(method.to_string()));
        map.insert("pathUri".to_string(), Value::String(path_uri.to_string()));

        let serialized =
            serde_json::to_string(&map).map_err(|_| HttpError::Generic {
                error_message: "unexpected. failed to serialize attestation payload."
                    .to_string(),
            })?;

        Ok(hex::encode(Sha256::digest(serialized.as_bytes())))
    }
}

/// Recursively sorts object keys ascending and drops null-valued entries; arrays
/// keep their order with each element sorted.
///
/// Reference: <https://github.com/worldcoin/backup-service/blob/a6edbe08baa3100ac7c3c2764f10d9c29ecc2318/src/attestation_gateway.rs#L436>
fn sort_json(value: &Value) -> Value {
    match value {
        Value::Object(map) => {
            let mut sorted = Map::new();
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            for key in keys {
                let val = &map[key];
                if !val.is_null() {
                    sorted.insert(key.clone(), sort_json(val));
                }
            }
            Value::Object(sorted)
        }
        Value::Array(items) => Value::Array(items.iter().map(sort_json).collect()),
        other => other.clone(),
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    struct MockAttestationProvider;

    #[async_trait::async_trait]
    impl AttestationTokenProvider for MockAttestationProvider {
        async fn attestation_token(
            &self,
            _request_hash: String,
        ) -> Result<String, HttpError> {
            Ok("mock-token".to_string())
        }
    }

    /// Pins the exact bytes hashed for a representative delete-factor body, so a
    /// drift from the service's algorithm is caught here.
    #[test]
    fn request_hash_matches_sorted_canonical_form() {
        let body = json!({
            "scope": "MAIN",
            "factorId": "f-1",
            "authorization": { "signature": "s", "publicKey": "p", "kind": "EC_KEYPAIR" },
            "challengeToken": "t",
            "encryptionKey": null,
        });
        let body_bytes = serde_json::to_vec(&body).unwrap();

        let provider = AttestationGateway::new(Arc::new(MockAttestationProvider));

        let hash = provider
            .hash_for_json_request("POST", "/v1/delete-factor", &body_bytes)
            .unwrap();

        let expected_canonical = concat!(
            r#"{"body":{"authorization":{"kind":"EC_KEYPAIR","publicKey":"p","signature":"s"},"#,
            r#""challengeToken":"t","factorId":"f-1","scope":"MAIN"},"#,
            r#""method":"POST","pathUri":"/v1/delete-factor"}"#,
        );
        let expected = hex::encode(Sha256::digest(expected_canonical.as_bytes()));
        assert_eq!(hash, expected);
    }

    #[test]
    fn request_hash_omits_body_when_empty() {
        let provider = AttestationGateway::new(Arc::new(MockAttestationProvider));
        let hash = provider
            .hash_for_json_request("POST", "/v1/x", &[])
            .unwrap();
        let expected_canonical = r#"{"method":"POST","pathUri":"/v1/x"}"#;
        let expected = hex::encode(Sha256::digest(expected_canonical.as_bytes()));
        assert_eq!(hash, expected);
    }

    #[test]
    fn request_hash_drops_nested_nulls() {
        let value = json!({ "b": null, "a": { "d": null, "c": 1 } });
        assert_eq!(sort_json(&value), json!({ "a": { "c": 1 } }));
    }
}
