use reqwest::header::{HeaderMap, ACCEPT, CONTENT_TYPE};
use reqwest::Client;
use serde::Deserialize;

use crate::backup::manifest::SyncSigner;
use crate::primitives::config::{get_config, BedrockEnvironment};
use crate::HttpError;
use serde_json::Value;
use std::time::Duration;

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
            format!("Content-Disposition: form-data; name=\"{name}\"\r\n").as_bytes(),
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
                "Content-Disposition: form-data; name=\"{name}\"; filename=\"{filename}\"\r\n",
            )
            .as_bytes(),
        );
        self.body.extend_from_slice(
            format!("Content-Type: {content_type}\r\n\r\n").as_bytes(),
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
    http: Client,
    base_url: String,
}

#[derive(Debug, Deserialize)]
pub struct ChallengeResponse {
    pub challenge: String,
    pub token: String,
}

// Removed unused EcKeypairAuthorizationPayload; JSON is built inline.

impl BackupServiceClient {
    /// Constructs a new client using reqwest and the configured Bedrock environment.
    pub fn new() -> Result<Self, HttpError> {
        let base_url = resolve_base_url()?;
        let http = Client::builder()
            .use_rustls_tls()
            .tcp_keepalive(Duration::from_secs(30))
            .pool_idle_timeout(Duration::from_secs(90))
            .build()
            .map_err(|e| HttpError::Generic {
                message: e.to_string(),
            })?;
        Ok(Self { http, base_url })
    }

    fn url(&self, path: &str) -> String {
        format!("{}{}", self.base_url, path)
    }

    /// POST /v1/sync/challenge/keypair → { challenge, token }
    pub async fn get_sync_challenge_keypair(
        &self,
    ) -> Result<ChallengeResponse, HttpError> {
        let url = self.url("/v1/sync/challenge/keypair");
        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_TYPE, "application/json".parse().unwrap());
        headers.insert(ACCEPT, "application/json".parse().unwrap());
        let resp = self
            .http
            .post(url)
            .headers(headers)
            .body(b"{}".to_vec())
            .send()
            .await
            .map_err(|e| HttpError::Generic {
                message: e.to_string(),
            })?;
        let status = resp.status();
        let bytes = resp.bytes().await.map_err(|e| HttpError::Generic {
            message: e.to_string(),
        })?;
        if !status.is_success() {
            return Err(HttpError::BadStatusCode {
                code: u64::from(status.as_u16()),
                response_body: bytes.to_vec(),
            });
        }
        let v: Value =
            serde_json::from_slice(&bytes).map_err(|e| HttpError::Generic {
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
        let sig_b64 = signer.sign_challenge_base64(challenge.challenge.clone());
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

        let url = self.url("/v1/sync");
        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_TYPE, content_type.parse().unwrap());
        headers.insert(ACCEPT, "application/json".parse().unwrap());
        let resp = self
            .http
            .post(url)
            .headers(headers)
            .body(body)
            .send()
            .await
            .map_err(|e| HttpError::Generic {
                message: e.to_string(),
            })?;
        let status = resp.status();
        let bytes = resp.bytes().await.map_err(|e| HttpError::Generic {
            message: e.to_string(),
        })?;
        if !status.is_success() {
            return Err(HttpError::BadStatusCode {
                code: u64::from(status.as_u16()),
                response_body: bytes.to_vec(),
            });
        }
        let v: Value =
            serde_json::from_slice(&bytes).map_err(|e| HttpError::Generic {
                message: e.to_string(),
            })?;
        Ok(v)
    }

    /// Retrieve metadata via keypair challenge/sign using provided signer.
    #[allow(clippy::too_many_lines)] // FIXME
    pub async fn get_remote_manifest_hash(
        &self,
        signer: &dyn SyncSigner,
    ) -> Result<[u8; 32], HttpError> {
        // FIXME: type requests and responses?
        // 1) Request challenge
        let url_challenge = self.url("/v1/retrieve-metadata/challenge/keypair");
        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_TYPE, "application/json".parse().unwrap());
        headers.insert(ACCEPT, "application/json".parse().unwrap());
        let resp = self
            .http
            .post(url_challenge)
            .headers(headers.clone())
            .body(b"{}".to_vec())
            .send()
            .await
            .map_err(|e| HttpError::Generic {
                message: e.to_string(),
            })?;
        let status = resp.status();
        let bytes = resp.bytes().await.map_err(|e| HttpError::Generic {
            message: e.to_string(),
        })?;
        if !status.is_success() {
            return Err(HttpError::BadStatusCode {
                code: u64::from(status.as_u16()),
                response_body: bytes.to_vec(),
            });
        }
        let v: Value =
            serde_json::from_slice(&bytes).map_err(|e| HttpError::Generic {
                message: e.to_string(),
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
        let sig_b64 = signer.sign_challenge_base64(challenge.to_string());
        let pk_b64 = signer.public_key_base64();
        let payload = serde_json::json!({
            "authorization": {
                "kind": "EC_KEYPAIR",
                "publicKey": pk_b64,
                "signature": sig_b64,
            },
            "challengeToken": token,
        });
        let url_retrieve = self.url("/v1/retrieve-metadata");
        let resp = self
            .http
            .post(url_retrieve)
            .headers(headers)
            .body(
                serde_json::to_vec(&payload).map_err(|e| HttpError::Generic {
                    message: e.to_string(),
                })?,
            )
            .send()
            .await
            .map_err(|e| HttpError::Generic {
                message: e.to_string(),
            })?;
        let status = resp.status();
        let bytes = resp.bytes().await.map_err(|e| HttpError::Generic {
            message: e.to_string(),
        })?;
        if !status.is_success() {
            return Err(HttpError::BadStatusCode {
                code: u64::from(status.as_u16()),
                response_body: bytes.to_vec(),
            });
        }
        let v: Value =
            serde_json::from_slice(&bytes).map_err(|e| HttpError::Generic {
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

        let hash: [u8; 32] = hex::decode(hash)
            .map_err(|_| HttpError::Generic {
                message: "unable to hex decode manifest hash".to_string(),
            })?
            .try_into()
            .map_err(|_| HttpError::Generic {
                message: "unable to convert hex encoded manifest hash to [u8; 32]"
                    .to_string(),
            })?;

        Ok(hash)
    }
}

fn resolve_base_url() -> Result<String, HttpError> {
    let cfg = get_config().ok_or_else(|| HttpError::Generic {
        message: "Bedrock config not initialized; call set_config() first".to_string(),
    })?;
    let url = match cfg.environment() {
        BedrockEnvironment::Staging => STAGING_BACKUP_BASE_URL,
        BedrockEnvironment::Production => PRODUCTION_BACKUP_BASE_URL,
    };
    Ok(url.to_string())
}

const STAGING_BACKUP_BASE_URL: &str = "https://backup-staging.placeholder";
const PRODUCTION_BACKUP_BASE_URL: &str = "https://backup-prod.placeholder";
