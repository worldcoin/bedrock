//! App-backend RPC client for smart-account transactions and EVM reads.
//!
//! Supports `UserOperation` sponsorship, submission, and receipt lookup,
//! EVM calls and storage reads, and legacy Safe transaction relay.
//!
//! For operations against client-provided external bundler URLs, see [`super::custom_bundler`].

use crate::{
    primitives::http_client::{get_http_client, HttpHeader},
    primitives::{
        AuthenticatedHttpClient, HttpError, HttpMethod, Network, PrimitiveError,
    },
    smart_account::{SafeSmartAccountError, UserOperation},
};
use alloy::primitives::{Address, Bytes, FixedBytes, B256};
use alloy::sol_types::SolCall;
use alloy::{hex::FromHex, providers::MULTICALL3_ADDRESS};

pub use crate::primitives::contracts::IMulticall3;

use serde::{de::DeserializeOwned, Serialize};
use serde_json::{Map, Value};
use std::sync::{Arc, OnceLock};

mod wire;

pub use wire::{
    Id, PmSponsorUserOperationResponse, RelaySafeTransactionRequest, RpcMethod,
    RpcProviderName, SponsorUserOperationResponse, SponsorshipContext,
    SponsorshipDecline, SponsorshipDeclineReason, WaGetUserOperationReceiptResponse,
};
pub(crate) use wire::{JsonRpcError, JsonRpcRequest};

#[cfg(test)]
mod tests;

/// Global RPC client instance for Bedrock operations
static RPC_CLIENT_INSTANCE: OnceLock<RpcClient> = OnceLock::new();

const SPONSORSHIP_DECLINED_CODE: i64 = -32602;
const SPONSORSHIP_DECLINED_MESSAGE: &str = "sponsorship declined";

impl TryFrom<JsonRpcError> for SponsorshipDecline {
    type Error = JsonRpcError;

    fn try_from(error: JsonRpcError) -> Result<Self, Self::Error> {
        if error.code != SPONSORSHIP_DECLINED_CODE
            || error.message != SPONSORSHIP_DECLINED_MESSAGE
        {
            return Err(error);
        }

        let Some(data) = error.data.as_ref() else {
            return Err(error);
        };
        let Ok(decline) = serde_json::from_value(data.clone()) else {
            return Err(error);
        };

        Ok(decline)
    }
}

/// Errors that can occur when interacting with RPC operations.
#[crate::bedrock_error]

pub enum RpcError {
    /// HTTP request failed
    #[error("HTTP request failed: {0}")]
    HttpError(String),

    /// JSON parsing error
    #[error("JSON parsing error")]
    JsonError,

    /// RPC returned an error response
    #[error("RPC error {code}: {error_message}")]
    RpcResponseError {
        /// The error code from the RPC response
        code: i64,
        /// The error message from the RPC response
        error_message: String,
    },

    /// Invalid response format
    #[error("Invalid response format: {error_message}")]
    InvalidResponse {
        /// The error message describing the format issue
        error_message: String,
    },

    /// HTTP client has not been initialized
    #[error("HTTP client not initialized. Call set_http_client() first.")]
    HttpClientNotInitialized,

    /// The provided URL is invalid or uses a disallowed scheme
    #[error("Invalid RPC URL: {error_message}")]
    InvalidUrl {
        /// Description of why the URL was rejected
        error_message: String,
    },

    /// Primitive operation error
    #[error("Primitive operation failed: {0}")]
    PrimitiveError(String),

    /// Safe Smart Account operation error
    #[error("Safe Smart Account operation failed: {0}")]
    SafeSmartAccountError(String),
}

impl From<JsonRpcError> for RpcError {
    fn from(error: JsonRpcError) -> Self {
        Self::RpcResponseError {
            code: error.code,
            error_message: error.message,
        }
    }
}

/// Internal RPC failure that preserves structured JSON-RPC error responses.
#[derive(Debug)]
pub(crate) enum RpcCallError {
    Rpc(RpcError),
    Response(JsonRpcError),
}

impl From<RpcError> for RpcCallError {
    fn from(error: RpcError) -> Self {
        Self::Rpc(error)
    }
}

impl From<RpcCallError> for RpcError {
    fn from(error: RpcCallError) -> Self {
        match error {
            RpcCallError::Rpc(error) => error,
            // Preserve the existing public error shape at API boundaries.
            RpcCallError::Response(error) => error.into(),
        }
    }
}

impl From<HttpError> for RpcError {
    fn from(e: HttpError) -> Self {
        Self::HttpError(e.to_string())
    }
}

impl From<PrimitiveError> for RpcError {
    fn from(e: PrimitiveError) -> Self {
        Self::PrimitiveError(e.to_string())
    }
}

impl From<SafeSmartAccountError> for RpcError {
    fn from(e: SafeSmartAccountError) -> Self {
        Self::SafeSmartAccountError(e.to_string())
    }
}

/// Result of requesting paymaster sponsorship for a user operation.
#[derive(Debug)]
pub enum PmSponsorUserOperationOutcome {
    /// Sponsorship was approved with the returned gas and paymaster fields.
    Sponsored(PmSponsorUserOperationResponse),
    /// Protocol sponsorship was declined with a self-sponsorship advisory.
    Declined(SponsorshipDecline),
}

/// RPC client for handling 4337 `UserOperation` requests
///
/// This client communicates with the RPC endpoint at `/v1/rpc/{network}` and `/v2/rpc/{network}`.
pub struct RpcClient {
    http_client: Arc<dyn AuthenticatedHttpClient>,
}

impl RpcClient {
    /// Creates a new RPC client
    ///
    /// # Arguments
    /// * `http_client` - The authenticated HTTP client for making requests
    pub fn new(http_client: Arc<dyn AuthenticatedHttpClient>) -> Self {
        Self { http_client }
    }

    /// Constructs the RPC endpoint URL for the specified network and method
    fn rpc_endpoint(network: Network, method: &RpcMethod) -> String {
        let version = match method {
            RpcMethod::EthCall
            | RpcMethod::EthGetStorageAt
            | RpcMethod::PmSponsorUserOperation
            | RpcMethod::SendUserOperationV2 => "v2",
            _ => "v1",
        };
        format!("/{version}/rpc/{}", network.network_name())
    }

    /// Makes a generic RPC call with typed parameters and result, adding provider header
    ///
    /// # Arguments
    /// - `network`: target network
    /// - `method`: JSON-RPC method to invoke
    /// - `params`: JSON-RPC params (typed)
    /// - `provider`: selected 4337 provider to include in headers
    async fn rpc_call<P, R>(
        &self,
        network: Network,
        method: RpcMethod,
        params: P,
        provider: RpcProviderName,
    ) -> Result<R, RpcCallError>
    where
        P: Serialize,
        R: DeserializeOwned,
    {
        // unique request ID
        let id = Id::String(format!("tx_{}", hex::encode(rand::random::<[u8; 16]>())));

        let endpoint = Self::rpc_endpoint(network, &method);
        let request = JsonRpcRequest::new(method, id, params);
        let request = serde_json::to_vec(&request).map_err(|_| RpcError::JsonError)?;

        let provider_name = provider.as_str();
        let headers = vec![
            HttpHeader {
                name: "provider-name".to_string(),
                value: provider_name.to_string(),
            },
            HttpHeader {
                name: "Content-Type".to_string(),
                value: "application/json".to_string(),
            },
        ];

        let response_bytes = self
            .http_client
            .as_ref()
            .fetch_from_app_backend(endpoint, HttpMethod::Post, headers, Some(request))
            .await
            .map_err(RpcError::from)?;

        let json_response: Value =
            serde_json::from_slice(&response_bytes).map_err(|_| RpcError::JsonError)?;

        // Check if it's an error response
        if let Some(error) = json_response.get("error") {
            let error_payload: JsonRpcError = serde_json::from_value(error.clone())
                .map_err(|_| RpcError::JsonError)?;

            return Err(RpcCallError::Response(error_payload));
        }

        json_response.get("result").map_or_else(
            || {
                Err(RpcError::InvalidResponse {
                    error_message: "Response missing both 'result' and 'error' fields"
                        .to_string(),
                }
                .into())
            },
            |result| {
                serde_json::from_value(result.clone())
                    .map_err(|_| RpcError::JsonError.into())
            },
        )
    }

    /// Requests sponsorship for a `UserOperation` via `wa_sponsorUserOperation`
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The HTTP request fails
    /// - The request serialization fails
    /// - The response parsing fails
    /// - The RPC returns an error response
    pub async fn sponsor_user_operation(
        &self,
        network: Network,
        user_operation: &UserOperation,
        entry_point: Address,
        self_sponsor_token: Option<Address>,
        provider: RpcProviderName,
    ) -> Result<SponsorUserOperationResponse, RpcError> {
        // Build params as a positional array. If no token is provided, omit the 3rd param entirely
        // so the backend can auto-fill an empty object as needed.
        let mut params: Vec<serde_json::Value> = Vec::with_capacity(3);
        params.push(
            serde_json::to_value(user_operation).map_err(|_| RpcError::JsonError)?,
        );
        params.push(serde_json::Value::String(format!("{entry_point:?}")));
        if let Some(token) = self_sponsor_token {
            params.push(serde_json::json!({ "token": format!("{token:?}") }));
        }

        self.rpc_call(network, RpcMethod::SponsorUserOperation, params, provider)
            .await
            .map_err(RpcError::from)
    }

    /// Requests sponsorship for a `UserOperation` via `pm_sponsorUserOperation` (V2)
    ///
    /// Sends the three-element params vec `[userOperation, entryPoint, context]`
    /// per the V2 contract. `context` is `SponsorshipContext::Protocol`
    /// (serializes to `{}`) for the initial attempt and
    /// `SponsorshipContext::SelfSponsoredToken` for the self-sponsored retry
    /// after a decline.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The HTTP request fails
    /// - The request serialization fails
    /// - The response parsing fails
    /// - The RPC returns an unexpected error response
    pub async fn pm_sponsor_user_operation(
        &self,
        network: Network,
        user_operation: &UserOperation,
        entry_point: Address,
        context: &SponsorshipContext,
    ) -> Result<PmSponsorUserOperationOutcome, RpcError> {
        let params = vec![
            serde_json::to_value(user_operation).map_err(|_| RpcError::JsonError)?,
            serde_json::Value::String(format!("{entry_point:?}")),
            context.to_json_value(),
        ];
        match self
            .rpc_call(
                network,
                RpcMethod::PmSponsorUserOperation,
                params,
                RpcProviderName::Any,
            )
            .await
        {
            Ok(response) => Ok(PmSponsorUserOperationOutcome::Sponsored(response)),
            Err(RpcCallError::Response(error)) => {
                match SponsorshipDecline::try_from(error) {
                    Ok(decline) => Ok(PmSponsorUserOperationOutcome::Declined(decline)),
                    Err(error) => Err(error.into()),
                }
            }
            Err(RpcCallError::Rpc(error)) => Err(error),
        }
    }

    /// Submits a signed `UserOperation` via `eth_sendUserOperation`
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The HTTP request fails
    /// - The request serialization fails
    /// - The response parsing fails
    /// - The RPC returns an error response
    /// - The returned user operation hash is invalid
    pub async fn send_user_operation(
        &self,
        network: Network,
        user_operation: &UserOperation,
        entrypoint: Address,
        provider: RpcProviderName,
    ) -> Result<FixedBytes<32>, RpcError> {
        let params = vec![
            serde_json::to_value(user_operation).map_err(|_| RpcError::JsonError)?,
            serde_json::Value::String(format!("{entrypoint:?}")),
        ];

        let result: String = self
            .rpc_call(network, RpcMethod::SendUserOperation, params, provider)
            .await?;

        FixedBytes::from_hex(&result).map_err(|e| RpcError::InvalidResponse {
            error_message: format!("Invalid userOpHash format: {e}"),
        })
    }

    /// Submits a signed `UserOperation` via the V2 RPC endpoint (`/v2/rpc/{network}`).
    ///
    /// Identical wire format to [`send_user_operation`] but routed to the V2 path.
    /// Use this from V2 execution flows (e.g. `sign_and_execute_v2`) so that
    /// V1 callers remain fully on the legacy path.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The HTTP request fails
    /// - The request serialization fails
    /// - The response parsing fails
    /// - The RPC returns an error response
    /// - The returned user operation hash is invalid
    pub async fn send_user_operation_v2(
        &self,
        network: Network,
        user_operation: &UserOperation,
        entrypoint: Address,
    ) -> Result<FixedBytes<32>, RpcError> {
        let params = vec![
            serde_json::to_value(user_operation).map_err(|_| RpcError::JsonError)?,
            serde_json::Value::String(format!("{entrypoint:?}")),
        ];

        let result: String = self
            .rpc_call(
                network,
                RpcMethod::SendUserOperationV2,
                params,
                RpcProviderName::Any,
            )
            .await?;

        FixedBytes::from_hex(&result).map_err(|e| RpcError::InvalidResponse {
            error_message: format!("Invalid userOpHash format: {e}"),
        })
    }

    /// Gets a custom user operation receipt for a given userOp hash
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The HTTP request fails
    /// - The request serialization fails
    /// - The response parsing fails
    /// - The RPC returns an error response
    /// - The returned user operation hash is invalid
    pub async fn wa_get_user_operation_receipt(
        &self,
        network: Network,
        user_operation_hash: &str,
    ) -> Result<WaGetUserOperationReceiptResponse, RpcError> {
        let params = vec![serde_json::to_value(user_operation_hash)
            .map_err(|_| RpcError::JsonError)?];

        self.rpc_call(
            network,
            RpcMethod::WaGetUserOperationReceipt,
            params,
            RpcProviderName::Any,
        )
        .await
        .map_err(RpcError::from)
    }

    /// Makes multiple read calls in a single `eth_call` via Multicall3 `aggregate3`.
    ///
    /// All calls are made with `allowFailure = true`. Callers should inspect
    /// each `Result.success` field to determine if the individual call succeeded.
    ///
    /// # Arguments
    /// - `network`: target network
    /// - `calls`: slice of `(target_address, calldata)` pairs
    ///
    /// # Errors
    /// - Will return an RPC error if the outer `eth_call` itself fails.
    pub async fn eth_call_batched(
        &self,
        network: Network,
        calls: &[(Address, Bytes)],
    ) -> Result<Vec<IMulticall3::Result>, RpcError> {
        let multicall3_calls: Vec<IMulticall3::Call3> = calls
            .iter()
            .map(|(target, data)| IMulticall3::Call3 {
                target: *target,
                allowFailure: false,
                callData: data.clone(),
            })
            .collect();

        let calldata = IMulticall3::aggregate3Call {
            calls: multicall3_calls,
        }
        .abi_encode();

        let result = self
            .eth_call(network, MULTICALL3_ADDRESS, calldata.into())
            .await?;

        let decoded = IMulticall3::aggregate3Call::abi_decode_returns(&result)
            .map_err(|e| RpcError::InvalidResponse {
                error_message: format!("Failed to decode Multicall3 response: {e}"),
            })?;

        Ok(decoded)
    }

    /// Makes a read call to a smart contract via `eth_call` on latest block
    ///
    /// # Arguments
    /// - `network`: target network
    /// - `to`: address of the contract to call
    /// - `data`: data to call the contract with
    /// # Errors
    /// - Will throw an RPC error if the RPC call fails.
    pub async fn eth_call(
        &self,
        network: Network,
        to: Address,
        data: Bytes,
    ) -> Result<Bytes, RpcError> {
        let params = vec![
            serde_json::Value::Object(Map::from_iter([
                (
                    "to".to_string(),
                    serde_json::Value::String(format!("{to:?}")),
                ),
                (
                    "data".to_string(),
                    serde_json::Value::String(format!("{data:?}")),
                ),
            ])),
            serde_json::Value::String("latest".to_string()),
        ];

        let result: String = self
            .rpc_call(network, RpcMethod::EthCall, params, RpcProviderName::Any)
            .await?;

        Bytes::from_hex(&result).map_err(|e| RpcError::InvalidResponse {
            error_message: format!("Invalid eth_call result format: {e}"),
        })
    }

    /// Reads a single storage slot of a contract via `eth_getStorageAt` on the
    /// latest block.
    ///
    /// # Arguments
    /// - `network`: target network
    /// - `address`: contract whose storage is read
    /// - `slot`: 32-byte storage slot key
    ///
    /// # Errors
    /// - Returns an RPC error if the call fails or the result is malformed.
    pub async fn eth_get_storage_at(
        &self,
        network: Network,
        address: Address,
        slot: B256,
    ) -> Result<B256, RpcError> {
        let params = vec![
            Value::String(format!("{address:?}")),
            Value::String(format!("{slot:?}")),
            Value::String("latest".to_string()),
        ];

        let result: String = self
            .rpc_call(
                network,
                RpcMethod::EthGetStorageAt,
                params,
                RpcProviderName::Any,
            )
            .await?;

        B256::from_hex(&result).map_err(|e| RpcError::InvalidResponse {
            error_message: format!("Invalid eth_getStorageAt result format: {e}"),
        })
    }

    /// Relays a signed Safe `execTransaction` via `wa_relaySafeTransaction` on
    /// the `/v1/rpc/{network}` endpoint.
    ///
    /// The backend submits the transaction on-chain and pays gas on the user's
    /// behalf. Used by the `Safe4337ModuleMigration`: a module-less Safe cannot
    /// pay its own gas via ERC-4337, so the repair must be relayed.
    ///
    /// # Returns
    /// The submitted transaction hash.
    ///
    /// # Errors
    /// - Returns an RPC error if the request fails to serialize, the HTTP call
    ///   fails, or the RPC returns an error response.
    pub async fn relay_safe_transaction(
        &self,
        network: Network,
        request: &RelaySafeTransactionRequest,
    ) -> Result<String, RpcError> {
        let params =
            vec![serde_json::to_value(request).map_err(|_| RpcError::JsonError)?];

        self.rpc_call(
            network,
            RpcMethod::RelaySafeTransaction,
            params,
            RpcProviderName::Any,
        )
        .await
        .map_err(RpcError::from)
    }
}

/// Gets the global RPC client, initializing it on first access.
///
/// This function will automatically initialize the global RPC client using the global HTTP client
/// if it hasn't been initialized yet. This provides a seamless experience where users only need
/// to set up the HTTP client and the RPC client will be created automatically as needed.
///
/// # Errors
/// Returns an error if the global HTTP client has not been initialized.
pub fn get_rpc_client() -> Result<&'static RpcClient, RpcError> {
    // Try to get the already-initialized global RPC client
    if let Some(rpc_client) = RPC_CLIENT_INSTANCE.get() {
        return Ok(rpc_client);
    }

    // RPC client not initialized yet - try to initialize it now
    let http_client = get_http_client().ok_or(RpcError::HttpClientNotInitialized)?;

    let rpc_client = RpcClient::new(http_client);

    // Try to set the global RPC client (ignore if already set by another thread)
    let _ = RPC_CLIENT_INSTANCE.set(rpc_client);

    // Get the RPC client (either the one we just set or one set by another thread)
    RPC_CLIENT_INSTANCE
        .get()
        .ok_or(RpcError::HttpClientNotInitialized)
}
