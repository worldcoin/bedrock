use std::sync::Arc;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::{backup::SyncSigner, HttpError};
use serde_json::Value;

/// Lightweight multipart/form-data builder to avoid hand-concatenating bytes in callers.
struct MultipartBuilder {
    boundary: String,
    body: Vec<u8>,
}

impl MultipartBuilder {
    fn new() -> Self {
        Self {
            boundary: format!("----oxide-boundary-{}", uuid::Uuid::new_v4()),
            body: Vec::new(),
        }
    }

    fn content_type(&self) -> String {
        format!("multipart/form-data; boundary={}", self.boundary)
    }

    fn add_json_part(
        &mut self,
        name: &str,
        json: &serde_json::Value,
    ) -> Result<(), HttpError> {
        let crlf = b"\r\n";
        self.body
            .extend_from_slice(format!("--{}\r\n", &self.boundary).as_bytes());
        self.body.extend_from_slice(
            format!("Content-Disposition: form-data; name=\"{}\"\r\n", name).as_bytes(),
        );
        self.body
            .extend_from_slice(b"Content-Type: application/json\r\n\r\n");
        let bytes = serde_json::to_vec(json).map_err(|e| HttpError::Generic {
            message: e.to_string(),
        })?;
        self.body.extend_from_slice(&bytes);
        self.body.extend_from_slice(crlf);
        Ok(())
    }

    fn add_bytes_part(
        &mut self,
        name: &str,
        filename: &str,
        content_type: &str,
        bytes: &[u8],
    ) {
        let crlf = b"\r\n";
        self.body
            .extend_from_slice(format!("--{}\r\n", &self.boundary).as_bytes());
        self.body.extend_from_slice(
            format!(
                "Content-Disposition: form-data; name=\"{}\"; filename=\"{}\"\r\n",
                name, filename
            )
            .as_bytes(),
        );
        self.body.extend_from_slice(
            format!("Content-Type: {}\r\n\r\n", content_type).as_bytes(),
        );
        self.body.extend_from_slice(bytes);
        self.body.extend_from_slice(crlf);
    }

    fn build(mut self) -> (String, Vec<u8>) {
        self.body
            .extend_from_slice(format!("--{}--\r\n", &self.boundary).as_bytes());
        (self.content_type(), self.body)
    }
}

/// Lightweight client responsible for calling backup-service endpoints.
pub struct BackupServiceClient {
    http: Arc<dyn BackupHttpClient>,
}

#[derive(Debug, Deserialize)]
pub struct ChallengeResponse {
    pub challenge: String,
    pub token: String,
}

#[derive(Debug, Serialize)]
pub struct EcKeypairAuthorizationPayload {
    #[serde(rename = "kind")]
    pub kind: String, // "EC_KEYPAIR"
    #[serde(rename = "publicKey")]
    pub public_key: String,
    pub signature: String,
}

impl BackupServiceClient {
    /// Constructs a new client using a platform-provided HTTP adapter.
    pub fn new(http: Arc<dyn BackupHttpClient>) -> Self {
        Self { http }
    }

    /// POST /v1/sync/challenge/keypair → { challenge, token }
    pub async fn get_sync_challenge_keypair(
        &self,
    ) -> Result<ChallengeResponse, HttpError> {
        let body = b"{}".to_vec();
        let resp = self
            .http
            .post(
                "/v1/sync/challenge/keypair".to_string(),
                body,
                "application/json".to_string(),
            )
            .await?;
        let v: Value =
            serde_json::from_slice(&resp).map_err(|e| HttpError::Generic {
                message: e.to_string(),
            })?;
        let challenge =
            v.get("challenge").and_then(|x| x.as_str()).ok_or_else(|| {
                HttpError::Generic {
                    message: "missing 'challenge' in sync challenge response"
                        .to_string(),
                }
            })?;
        let token = v.get("token").and_then(|x| x.as_str()).ok_or_else(|| {
            HttpError::Generic {
                message: "missing 'token' in sync challenge response".to_string(),
            }
        })?;
        Ok(ChallengeResponse {
            challenge: challenge.to_string(),
            token: token.to_string(),
        })
    }

    /// POST /v1/sync (multipart) with payload JSON and backup bytes.
    /// Returns raw JSON for now; typed response can be added later.
    pub async fn post_sync_with_keypair(
        &self,
        signer: &dyn SyncSigner,
        challenge: &ChallengeResponse,
        current_manifest_hash: String,
        new_manifest_hash: String,
        sealed_backup: Vec<u8>,
    ) -> Result<serde_json::Value, HttpError> {
        // 1) Build authorization JSON from signer: { kind: "EC_KEYPAIR", publicKey, signature }
        let sig_b64 = signer.sign_challenge_base64(&challenge.challenge);
        let pk_b64 = signer.public_key_base64();
        let payload = serde_json::json!({
            "authorization": {
                "kind": "EC_KEYPAIR",
                "publicKey": pk_b64,
                "signature": sig_b64,
            },
            "challengeToken": challenge.token,
            "currentManifestHash": current_manifest_hash,
            "newManifestHash": new_manifest_hash,
        });

        // 2) Build multipart body via helper
        let mut mp = MultipartBuilder::new();
        mp.add_json_part("payload", &payload)?;
        mp.add_bytes_part(
            "backup",
            "backup.bin",
            "application/octet-stream",
            &sealed_backup,
        );
        let (content_type, body) = mp.build();

        //TODO: move to reqwuest
        let resp = self
            .http
            .post("/v1/sync".to_string(), body, content_type)
            .await?;
        let v: Value =
            serde_json::from_slice(&resp).map_err(|e| HttpError::Generic {
                message: e.to_string(),
            })?;
        Ok(v)
    }

    /// Retrieve metadata via keypair challenge/sign using provided signer.
    pub async fn get_remote_manifest_hash(
        &self,
        signer: &dyn SyncSigner,
    ) -> Result<String, HttpError> {
        // 1) Request challenge
        let challenge_bytes = self
            .http
            .post(
                "/v1/retrieve-metadata/challenge/keypair".to_string(),
                b"{}".to_vec(),
                "application/json".to_string(),
            )
            .await?;
        let v: Value = serde_json::from_slice(&challenge_bytes).map_err(|e| {
            HttpError::Generic {
                message: e.to_string(),
            }
        })?;
        let challenge =
            v.get("challenge").and_then(|x| x.as_str()).ok_or_else(|| {
                HttpError::Generic {
                    message:
                        "missing 'challenge' in retrieve-metadata challenge response"
                            .to_string(),
                }
            })?;
        let token = v.get("token").and_then(|x| x.as_str()).ok_or_else(|| {
            HttpError::Generic {
                message: "missing 'token' in retrieve-metadata challenge response"
                    .to_string(),
            }
        })?;

        // 2) Sign + post solution
        let sig_b64 = signer.sign_challenge_base64(challenge);
        let pk_b64 = signer.public_key_base64();
        let payload = serde_json::json!({
            "authorization": {
                "kind": "EC_KEYPAIR",
                "publicKey": pk_b64,
                "signature": sig_b64,
            },
            "challengeToken": token,
        });
        let resp_bytes = self
            .http
            .post(
                "/v1/retrieve-metadata".to_string(),
                serde_json::to_vec(&payload).map_err(|e| HttpError::Generic {
                    message: e.to_string(),
                })?,
                "application/json".to_string(),
            )
            .await?;
        let v: Value =
            serde_json::from_slice(&resp_bytes).map_err(|e| HttpError::Generic {
                message: e.to_string(),
            })?;
        let metadata = v.get("metadata").ok_or_else(|| HttpError::Generic {
            message: "missing 'metadata'".to_string(),
        })?;
        let hash = metadata
            .get("manifestHash")
            .and_then(|x| x.as_str())
            .ok_or_else(|| HttpError::Generic {
                message: "missing 'manifestHash'".to_string(),
            })?;
        Ok(hash.to_string())
    }
}

/// Minimal HTTP adapter native clients must implement for backup-service interactions.
#[uniffi::export(with_foreign)]
#[async_trait]
pub trait BackupHttpClient: Send + Sync {
    async fn get(&self, path: String) -> Result<Vec<u8>, HttpError>;
    async fn post(
        &self,
        path: String,
        body: Vec<u8>,
        content_type: String,
    ) -> Result<Vec<u8>, HttpError>;
}
