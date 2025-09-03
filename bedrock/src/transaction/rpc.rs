//! RPC module for handling 4337 `UserOperation` requests through authenticated HTTP client.
//!
//! This module provides functionality to:
//! - Request sponsorship for `UserOperations` via `wa_sponsorUserOperation`
//! - Submit signed `UserOperations` via `eth_sendUserOperation`

use crate::{
    primitives::http_client::{get_http_client, HttpHeader},
    primitives::{
        contracts::{IEntryPoint::PackedUserOperation, RpcUserOperationV0_7},
        AuthenticatedHttpClient, HttpError, HttpMethod, Network, PrimitiveError,
    },
    smart_account::{SafeSmartAccountError, UserOperation},
};
use alloy::hex::FromHex;
use alloy::primitives::{Address, Bytes, FixedBytes, U128, U256};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::sync::{Arc, OnceLock};

/// Global RPC client instance for Bedrock operations
static RPC_CLIENT_INSTANCE: OnceLock<RpcClient> = OnceLock::new();

/// JSON-RPC request ID
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Id {
    /// Numeric ID
    Number(u64),
    /// String ID
    String(String),
}

/// Supported RPC methods in Bedrock
#[derive(Debug, Clone, Serialize)]
pub enum RpcMethod {
    /// Request sponsorship for a `UserOperation`
    #[serde(rename = "wa_sponsorUserOperation")]
    SponsorUserOperation,
    /// Submit a signed `UserOperation`
    #[serde(rename = "eth_sendUserOperation")]
    SendUserOperation,
    /// Make a generic RPC `eth_call` to read data from a contract
    #[serde(rename = "eth_call")]
    EthCall,
}

/// 4337 provider selection to be passed by native apps
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum RpcProviderName {
    /// Use Alchemy as 4337 provider
    Alchemy,
    /// Use Pimlico as 4337 provider
    Pimlico,
}

impl RpcProviderName {
    /// Returns the wire/header value for the provider
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Alchemy => "alchemy",
            Self::Pimlico => "pimlico",
        }
    }
}

impl RpcMethod {
    /// Get the string representation of the RPC method
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::SponsorUserOperation => "wa_sponsorUserOperation",
            Self::SendUserOperation => "eth_sendUserOperation",
            Self::EthCall => "eth_call",
        }
    }
}

/// JSON-RPC request
#[derive(Debug, Serialize)]
struct JsonRpcRequest<T> {
    jsonrpc: &'static str,
    id: Id,
    method: RpcMethod,
    params: T,
}

impl<T> JsonRpcRequest<T> {
    /// Create a new JSON-RPC request
    const fn new(method: RpcMethod, id: Id, params: T) -> Self {
        Self {
            jsonrpc: "2.0",
            id,
            method,
            params,
        }
    }
}

/// JSON-RPC error payload
#[derive(Debug, Deserialize)]
struct ErrorPayload {
    code: i64,
    message: String,
    // This is currently unused, but we keep it here for future use + consistency
    #[serde(default)]
    #[allow(dead_code)]
    data: Option<Value>,
}

/// Errors that can occur when interacting with RPC operations.
#[crate::bedrock_error]
#[derive(Debug, Deserialize)]
pub enum RpcError {
    /// HTTP request failed
    #[error("HTTP request failed: {0}")]
    HttpError(#[from] HttpError),

    /// JSON parsing error
    #[error("JSON parsing error")]
    JsonError,

    /// RPC returned an error response
    #[error("RPC error {code}: {message}")]
    RpcResponseError {
        /// The error code from the RPC response
        code: i64,
        /// The error message from the RPC response
        message: String,
    },

    /// Invalid response format
    #[error("Invalid response format: {message}")]
    InvalidResponse {
        /// The error message describing the format issue
        message: String,
    },

    /// HTTP client has not been initialized
    #[error("HTTP client not initialized. Call set_http_client() first.")]
    HttpClientNotInitialized,

    /// Primitive operation error
    #[error("Primitive operation failed: {0}")]
    PrimitiveError(#[from] PrimitiveError),

    /// Safe Smart Account operation error
    #[error("Safe Smart Account operation failed: {0}")]
    SafeSmartAccountError(#[from] SafeSmartAccountError),

    /// Invalid inputs
    #[error("Invalid request: {0}")]
    InvalidRequest(String),
}

/// Response from `wa_sponsorUserOperation`
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SponsorUserOperationResponse {
    /// Paymaster address
    pub paymaster: Address,
    /// Paymaster data
    pub paymaster_data: Bytes,
    /// Pre-verification gas
    pub pre_verification_gas: U256,
    /// Verification gas limit
    pub verification_gas_limit: U128,
    /// Call gas limit
    pub call_gas_limit: U128,
    /// Paymaster verification gas limit
    pub paymaster_verification_gas_limit: U128,
    /// Paymaster post-op gas limit
    pub paymaster_post_op_gas_limit: U128,
    /// Max priority fee per gas
    pub max_priority_fee_per_gas: U128,
    /// Max fee per gas
    pub max_fee_per_gas: U128,
}

/// RPC client for handling 4337 `UserOperation` requests
///
/// This client communicates with the app-backend's RPC endpoint at `/v1/rpc/{network}`.
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

    /// Constructs the RPC endpoint URL for the specified network
    fn rpc_endpoint(network: Network) -> String {
        format!("/v1/rpc/{}", network.network_name())
    }

    // async fn call_pbh_contract

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
    ) -> Result<R, RpcError>
    where
        P: Serialize,
        R: for<'de> Deserialize<'de>,
    {
        // Generate a unique request ID
        let id = Id::String(format!("tx_{}", hex::encode(rand::random::<[u8; 16]>())));

        // Create the JSON-RPC request using Alloy's Request type
        let request = JsonRpcRequest::new(method, id, params);

        // Serialize the request
        let request_body =
            serde_json::to_vec(&request).map_err(|_| RpcError::JsonError)?;

        // Send the HTTP request
        let provider_name = provider.as_str();
        let headers = vec![HttpHeader {
            name: "provider-name".to_string(),
            value: provider_name.to_string(),
        }];

        let response_bytes = self
            .http_client
            .as_ref()
            .fetch_from_app_backend(
                Self::rpc_endpoint(network),
                HttpMethod::Post,
                headers,
                Some(request_body),
            )
            .await?;

        // Parse the response as a generic JSON value first to handle both success and error cases
        let json_response: Value =
            serde_json::from_slice(&response_bytes).map_err(|_| RpcError::JsonError)?;

        // Check if it's an error response
        if let Some(error) = json_response.get("error") {
            let error_payload: ErrorPayload = serde_json::from_value(error.clone())
                .map_err(|_| RpcError::JsonError)?;

            return Err(RpcError::RpcResponseError {
                code: error_payload.code,
                message: error_payload.message,
            });
        }

        // Try to parse as a successful response
        json_response.get("result").map_or_else(
            || {
                Err(RpcError::InvalidResponse {
                    message: "Response missing both 'result' and 'error' fields"
                        .to_string(),
                })
            },
            |result| {
                serde_json::from_value(result.clone()).map_err(|_| RpcError::JsonError)
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
        // TODO: Should this be RPCUserOperationV0_7?
        params.push(
            serde_json::to_value(user_operation).map_err(|_| RpcError::JsonError)?,
        );
        params.push(serde_json::Value::String(format!("{entry_point:?}")));
        if let Some(token) = self_sponsor_token {
            params.push(serde_json::json!({ "token": format!("{token:?}") }));
        }

        self.rpc_call(network, RpcMethod::SponsorUserOperation, params, provider)
            .await
    }

    /// Submits a signed `UserOperation` via `eth_sendUserOperation`
    ///
    /// # Arguments
    /// - `network`: target network
    /// - `user_operation`: the user operation to submit
    /// - `entrypoint`: the entry point contract address
    /// - `provider`: selected 4337 provider to include in headers
    /// - `aggregator`: optional aggregator address to include in the user operation
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
        aggregator: Option<Address>,
    ) -> Result<FixedBytes<32>, RpcError> {
        let packed_user_op: PackedUserOperation = user_operation.clone().into();

        // Convert to RpcUserOperationV0_7 based on whether aggregator is provided
        let rpc_user_op: RpcUserOperationV0_7 = if let Some(agg_addr) = aggregator {
            (packed_user_op, agg_addr).into()
        } else {
            packed_user_op.into()
        };

        // Serialize the RpcUserOperationV0_7 to JSON
        // Seralization will remove unused fields like factory and paymaster from JSON
        let user_op_value =
            serde_json::to_value(&rpc_user_op).map_err(|_| RpcError::JsonError)?;

        let params = vec![
            user_op_value,
            serde_json::Value::String(format!("{entrypoint:?}")),
        ];

        let result: String = self
            .rpc_call(network, RpcMethod::SendUserOperation, params, provider)
            .await?;

        FixedBytes::from_hex(&result).map_err(|e| RpcError::InvalidResponse {
            message: format!("Invalid userOpHash format: {e}"),
        })
    }

    /// Makes a generic RPC call with typed parameters and result, adding provider header
    ///
    /// # Arguments
    /// - `network`: target network
    /// - `method`: JSON-RPC method to invoke
    /// - `params`: JSON-RPC params (typed)
    /// - `provider`: selected 4337 provider to include in headers
    pub async fn eth_call(
        &self,
        network: Network,
        to: Address,
        data: Bytes,
    ) -> Result<Bytes, RpcError> {
        // var raw = JSON.stringify({
        // "method": "eth_call",
        // "params": [
        //     {
        //     "to": "0x6b175474e89094c44da98b954eedeac495271d0f",
        //     "data": "0x70a082310000000000000000000000006E0d01A76C3Cf4288372a29124A26D4353EE51BE"
        //     },
        //     "latest", Block number or "latest"
        // })

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
            serde_json::Value::String("latest".to_string()), // TODO: Allow passing in block number
        ];

        let result: String = self
            .rpc_call(
                network,
                RpcMethod::EthCall,
                params,
                RpcProviderName::Alchemy,
            )
            .await?;

        Bytes::from_hex(&result).map_err(|e| RpcError::InvalidResponse {
            message: format!("Invalid eth_call result format: {e}"),
        })
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

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::{address, bytes, U256};
    use serde_json::json;

    #[test]
    fn test_user_operation_serialization() {
        let user_op = UserOperation {
            sender: address!("5a6b47F4131bf1feAFA56A05573314BcF44C9149"),
            nonce: U256::from_str_radix("845ADB2C711129D4F3966735ED98A9F09FC4CE57", 16)
                .unwrap(),
            factory: Address::ZERO,
            factory_data: Bytes::default(),
            call_data: bytes!("0xe9ae5c53"),
            call_gas_limit: 0x13_880,
            verification_gas_limit: 0x60_B01,
            pre_verification_gas: U256::from(0xD3E3),
            max_fee_per_gas: 0x3B9A_CA00,
            max_priority_fee_per_gas: 0x3B9A_CA00,
            paymaster: Address::ZERO,
            paymaster_verification_gas_limit: 0,
            paymaster_post_op_gas_limit: 0,
            paymaster_data: Bytes::default(),
            signature: vec![0xff; 77].into(),
        };

        let serialized = serde_json::to_value(&user_op).unwrap();

        assert_eq!(
            serialized["sender"],
            "0x5a6b47f4131bf1feafa56a05573314bcf44c9149"
        );
        assert_eq!(
            serialized["nonce"],
            "0x845adb2c711129d4f3966735ed98a9f09fc4ce57"
        );
        assert_eq!(serialized["callData"], "0xe9ae5c53");
        assert_eq!(serialized["callGasLimit"], "0x13880"); // ERC-7769: numeric fields as hex strings
    }

    #[test]
    fn test_sponsor_response_parsing() {
        let json_response = json!({
            "paymaster": "0x0000000000000039cd5e8aE05257CE51C473ddd1",
            "paymasterData": "0x01000066d1a1a4",
            "preVerificationGas": "0x350f7",
            "verificationGasLimit": "0x501ab",
            "callGasLimit": "0x212df",
            "paymasterVerificationGasLimit": "0x6dae",
            "paymasterPostOpGasLimit": "0x706e",
            "maxPriorityFeePerGas": "0x3B9ACA00",
            "maxFeePerGas": "0x7A5CF70D5",
        });

        let response: SponsorUserOperationResponse =
            serde_json::from_value(json_response).unwrap();

        assert_eq!(
            response.paymaster,
            address!("0000000000000039cd5e8aE05257CE51C473ddd1")
        );
        assert_eq!(response.call_gas_limit, U128::from(0x212df));
    }

    #[test]
    fn test_error_payload_parsing() {
        let error_json = json!({
            "code": -32000,
            "message": "execution reverted",
            "data": null
        });

        let error_payload: ErrorPayload = serde_json::from_value(error_json).unwrap();

        assert_eq!(error_payload.code, -32000);
        assert_eq!(error_payload.message, "execution reverted");
    }

    #[test]
    fn test_user_operation_direct_serialization_works() {
        let user_op = UserOperation {
            sender: address!("5a6b47F4131bf1feAFA56A05573314BcF44C9149"),
            nonce: U256::from_str_radix("845ADB2C711129D4F3966735ED98A9F09FC4CE57", 16)
                .unwrap(),
            factory: Address::ZERO,
            factory_data: Bytes::default(),
            call_data: bytes!("0xe9ae5c53"),
            call_gas_limit: 0x13_880,
            verification_gas_limit: 0x60_B01,
            pre_verification_gas: U256::from(0xD3E3),
            max_fee_per_gas: 0x3B9A_CA00,
            max_priority_fee_per_gas: 0x3B9A_CA00,
            paymaster: Address::ZERO,
            paymaster_verification_gas_limit: 0,
            paymaster_post_op_gas_limit: 0,
            paymaster_data: Bytes::default(),
            signature: vec![0xff; 77].into(),
        };

        // Test that UserOperation can be serialized directly
        let serialized = serde_json::to_value(&user_op).unwrap();

        // Print the actual serialized output to see the format
        println!(
            "Direct UserOperation serialization: {}",
            serde_json::to_string_pretty(&serialized).unwrap()
        );

        // Check if the field names match the expected RPC format
        // Note: alloy's sol! macro might use different field names than camelCase
        println!(
            "Available fields: {:?}",
            serialized.as_object().unwrap().keys().collect::<Vec<_>>()
        );

        // Verify the key field is properly serialized with camelCase naming
        assert_eq!(serialized["callData"], "0xe9ae5c53");

        // ERC-7769: All fields MUST be present and hex-encoded; empty bytes must be "0x"
        assert_eq!(
            serialized["factory"],
            "0x0000000000000000000000000000000000000000"
        );
        assert_eq!(serialized["factoryData"], "0x");
        assert_eq!(
            serialized["paymaster"],
            "0x0000000000000000000000000000000000000000"
        );
        assert_eq!(serialized["paymasterData"], "0x");
        assert_eq!(serialized["paymasterVerificationGasLimit"], "0x0");
        assert_eq!(serialized["paymasterPostOpGasLimit"], "0x0");
    }
}
