//! Custom bundler RPC operations.
//!
//! Functions in this module communicate directly with a **client-provided** bundler
//! RPC URL (e.g. Pimlico, Alchemy, or a self-hosted bundler) using a Rust-native
//! HTTP client (`reqwest`).
//!
//! This is intentionally separate from [`super::rpc::RpcClient`], which routes
//! requests through the World App backend.

use alloy::hex::FromHex;
use alloy::primitives::{Address, FixedBytes};
use bedrock_macros::bedrock_export;
use serde_json::Value;
use std::str::FromStr;
use std::sync::OnceLock;
use std::time::Duration;

use crate::{
    primitives::{HexEncodedData, Network},
    smart_account::{SafeSmartAccount, UserOperation, ENTRYPOINT_4337},
    transactions::{
        foreign::UnparsedUserOperation,
        rpc::{ErrorPayload, Id, JsonRpcRequest, RpcError, RpcMethod},
        TransactionError,
    },
};

/// Global reqwest client for direct HTTP requests to bundler endpoints.
static REQWEST_CLIENT: OnceLock<reqwest::Client> = OnceLock::new();

// ── URL validation ────────────────────────────────────────────────────────────

/// Validates that the given URL is safe to use as an RPC endpoint.
///
/// Requires `https://` scheme for all hosts, with `http://` permitted only
/// for loopback addresses.
fn validate_rpc_url(url: &str) -> Result<(), RpcError> {
    let parsed = reqwest::Url::parse(url).map_err(|e| RpcError::InvalidUrl {
        error_message: format!("Failed to parse URL: {e}"),
    })?;

    match parsed.scheme() {
        "https" => Ok(()),
        "http" => match parsed.host_str() {
            Some("127.0.0.1" | "localhost" | "::1" | "[::1]") => Ok(()),
            _ => Err(RpcError::InvalidUrl {
                error_message: "Only https:// URLs are allowed for non-loopback hosts"
                    .to_string(),
            }),
        },
        scheme => Err(RpcError::InvalidUrl {
            error_message: format!(
                "Unsupported URL scheme '{scheme}://', only https:// is allowed"
            ),
        }),
    }
}

// ── Low-level HTTP ────────────────────────────────────────────────────────────

/// Makes a JSON-RPC POST request to an arbitrary URL using `reqwest`.
///
/// The client is configured with a 15 s timeout to prevent indefinitely hanging requests.
async fn post_json_rpc_to_url(url: &str, body: Vec<u8>) -> Result<Vec<u8>, RpcError> {
    let client = REQWEST_CLIENT.get_or_init(|| {
        reqwest::Client::builder()
            .timeout(Duration::from_secs(15))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .expect("failed to build reqwest client")
    });
    let response = client
        .post(url)
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .body(body)
        .send()
        .await
        // Strip the related url from this error to avoid leaking API keys
        .map_err(|e| RpcError::HttpError(e.without_url().to_string()))?;

    let status = response.status();
    let bytes = response
        .bytes()
        .await
        .map_err(|e| RpcError::HttpError(e.without_url().to_string()))?;

    if !status.is_success() {
        return Err(RpcError::HttpError(format!(
            "HTTP {status}: {}",
            String::from_utf8_lossy(&bytes)
        )));
    }

    Ok(bytes.to_vec())
}

// ── Parsing helper ────────────────────────────────────────────────────────────

/// Parses a JSON-RPC response, extracting the `result` field or surfacing the `error`.
fn parse_json_rpc_response(response_bytes: &[u8]) -> Result<Value, RpcError> {
    let json: Value =
        serde_json::from_slice(response_bytes).map_err(|_| RpcError::JsonError)?;

    if let Some(error) = json.get("error") {
        let ep: ErrorPayload =
            serde_json::from_value(error.clone()).map_err(|_| RpcError::JsonError)?;
        return Err(RpcError::RpcResponseError {
            code: ep.code,
            error_message: ep.message,
        });
    }

    json.get("result")
        .cloned()
        .ok_or_else(|| RpcError::InvalidResponse {
            error_message: "Response missing both 'result' and 'error' fields"
                .to_string(),
        })
}

// ── Public API ────────────────────────────────────────────────────────────────

/// Submits a signed `UserOperation` via `eth_sendUserOperation` to an external RPC URL.
///
/// # Errors
///
/// Returns an error if:
/// - The URL is invalid or uses a disallowed scheme
/// - The HTTP request fails
/// - The request serialization fails
/// - The response parsing fails
/// - The RPC returns an error response
/// - The returned user operation hash is invalid
pub async fn send_user_operation_to_url(
    rpc_url: &str,
    user_operation: &UserOperation,
    entrypoint: Address,
) -> Result<FixedBytes<32>, RpcError> {
    validate_rpc_url(rpc_url)?;

    let params = vec![
        serde_json::to_value(user_operation).map_err(|_| RpcError::JsonError)?,
        serde_json::Value::String(format!("{entrypoint:?}")),
    ];

    let id = Id::Number(u64::from(rand::random::<u32>()));
    let request = JsonRpcRequest::new(RpcMethod::SendUserOperation, id, params);
    let request_bytes =
        serde_json::to_vec(&request).map_err(|_| RpcError::JsonError)?;

    let response_bytes = post_json_rpc_to_url(rpc_url, request_bytes).await?;
    let result = parse_json_rpc_response(&response_bytes)?;

    let hash_str: String =
        serde_json::from_value(result).map_err(|_| RpcError::JsonError)?;

    FixedBytes::from_hex(&hash_str).map_err(|e| RpcError::InvalidResponse {
        error_message: format!("Invalid userOpHash format: {e}"),
    })
}

/// Verifies that a bundler RPC endpoint supports the v0.7 `EntryPoint` used by World App.
///
/// Calls `eth_supportedEntryPoints` on the given URL and checks that the response
/// contains the expected `EntryPoint` address.
///
/// # Errors
///
/// Returns an error if:
/// - The URL is invalid or uses a disallowed scheme
/// - The HTTP request fails
/// - The RPC returns an error response
/// - The expected `EntryPoint` is not in the returned list
#[uniffi::export(async_runtime = "tokio")]
pub async fn verify_bundler_rpc_entrypoint(rpc_url: String) -> Result<(), RpcError> {
    validate_rpc_url(&rpc_url)?;

    let request = JsonRpcRequest::new(
        RpcMethod::SupportedEntryPoints,
        Id::Number(1),
        Vec::<()>::new(),
    );
    let request_bytes =
        serde_json::to_vec(&request).map_err(|_| RpcError::JsonError)?;

    let response_bytes = post_json_rpc_to_url(&rpc_url, request_bytes).await?;
    let result = parse_json_rpc_response(&response_bytes)?;

    let entrypoints: Vec<String> =
        serde_json::from_value(result).map_err(|_| RpcError::InvalidResponse {
            error_message: "Expected array of entrypoint addresses".to_string(),
        })?;

    let expected = *ENTRYPOINT_4337;

    let supported = entrypoints
        .iter()
        .any(|ep| Address::from_str(ep).is_ok_and(|addr| addr == expected));

    if supported {
        Ok(())
    } else {
        Err(RpcError::InvalidResponse {
            error_message: format!(
                "Bundler does not support the expected EntryPoint ({expected:?}); supported: {entrypoints:?}"
            ),
        })
    }
}

// ── SafeSmartAccount extensions ───────────────────────────────────────────────

/// Extensions to [`SafeSmartAccount`] for operations against client-provided bundler RPC URLs.
#[bedrock_export]
impl SafeSmartAccount {
    /// Signs and sends a bundler-sponsored `UserOperation` to an external bundler RPC endpoint.
    ///
    /// This method takes an existing `UserOperation`, converts it to a bundler-sponsored
    /// format (zeroed paymaster and fee fields), signs it, and submits it directly to
    /// the provided bundler RPC URL via `eth_sendUserOperation`.
    ///
    /// In a bundler-sponsored user operation, the bundler itself covers all gas costs.
    /// The operation's core fields (`sender`, `nonce`, `callData`, `callGasLimit`,
    /// `verificationGasLimit`) are preserved from the original operation.
    ///
    /// # Arguments
    /// - `user_operation`: The user operation to convert and send.
    /// - `rpc_url`: The absolute URL of the bundler RPC endpoint (e.g. `https://bundler.example.com/rpc`).
    ///
    /// # Errors
    /// - Returns [`TransactionError::PrimitiveError`] if the user operation is invalid.
    /// - Returns [`TransactionError::Generic`] if signing or submission fails.
    pub async fn send_bundler_sponsored_user_operation(
        &self,
        user_operation: UnparsedUserOperation,
        rpc_url: String,
    ) -> Result<HexEncodedData, TransactionError> {
        let mut user_op: UserOperation = user_operation.try_into().map_err(
            |e: crate::primitives::PrimitiveError| {
                TransactionError::PrimitiveError(e.to_string())
            },
        )?;
        user_op = user_op.as_bundler_sponsored();

        // Extract host only to avoid logging API keys
        let bundler_host = reqwest::Url::parse(&rpc_url)
            .ok()
            .and_then(|u| u.host_str().map(String::from))
            .unwrap_or_else(|| "<unknown>".to_string());

        crate::info!("bundler_sponsored_user_op.sending bundler_host={bundler_host}");

        self.sign_user_operation(&mut user_op, Network::WorldChain)
            .map_err(|e| {
                crate::error!("bundler_sponsored_user_op.sign_failed error={e}");
                TransactionError::Generic {
                    error_message: format!("Failed to sign user operation: {e}"),
                }
            })?;

        let user_op_hash =
            send_user_operation_to_url(&rpc_url, &user_op, *ENTRYPOINT_4337)
                .await
                .map_err(|e| {
                    crate::error!(
                        "bundler_sponsored_user_op.send_failed bundler_host={bundler_host} error={e}"
                    );
                    TransactionError::Generic {
                        error_message: format!(
                            "Failed to send bundler-sponsored user operation: {e}"
                        ),
                    }
                })?;

        crate::info!("bundler_sponsored_user_op.submitted user_op_hash={user_op_hash}");

        Ok(HexEncodedData::new(&user_op_hash.to_string())?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_rpc_url_accepts_https() {
        assert!(validate_rpc_url("https://bundler.example.com/rpc").is_ok());
        assert!(validate_rpc_url("https://rpc.pimlico.io/v2/123").is_ok());
    }

    #[test]
    fn test_validate_rpc_url_accepts_http_loopback() {
        assert!(validate_rpc_url("http://127.0.0.1:8545").is_ok());
        assert!(validate_rpc_url("http://localhost:8080/rpc").is_ok());
        assert!(validate_rpc_url("http://[::1]:8545").is_ok());
    }

    #[test]
    fn test_validate_rpc_url_rejects_http_non_loopback() {
        assert!(validate_rpc_url("http://bundler.example.com/rpc").is_err());
        assert!(validate_rpc_url("http://169.254.169.254/metadata").is_err());
        assert!(validate_rpc_url("http://10.0.0.1:8545").is_err());
    }

    #[test]
    fn test_validate_rpc_url_rejects_dangerous_schemes() {
        assert!(validate_rpc_url("file:///etc/passwd").is_err());
        assert!(validate_rpc_url("ftp://example.com").is_err());
        assert!(validate_rpc_url("data:text/html,<h1>hi</h1>").is_err());
    }

    #[test]
    fn test_validate_rpc_url_rejects_invalid_urls() {
        assert!(validate_rpc_url("not a url").is_err());
        assert!(validate_rpc_url("").is_err());
    }
}
