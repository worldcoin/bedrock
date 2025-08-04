//! RPC module for handling 4337 `UserOperation` requests through authenticated HTTP client.
//!
//! This module provides functionality to:
//! - Request sponsorship for `UserOperations` via `wa_sponsorUserOperation`
//! - Submit signed `UserOperations` via `eth_sendUserOperation`
//!
//! All operations are performed on World Chain (chain ID: 480).

use alloy::hex::FromHex;
use alloy::primitives::{Address, Bytes, FixedBytes, U128, U256};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{
    primitives::{AuthenticatedHttpClient, HttpError, HttpMethod},
    smart_account::UserOperation,
};

/// JSON-RPC request ID
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Id {
    /// Numeric ID
    Number(u64),
    /// String ID
    String(String),
}

/// JSON-RPC request
#[derive(Debug, Serialize)]
struct JsonRpcRequest<T> {
    jsonrpc: &'static str,
    id: Id,
    method: String,
    params: T,
}

impl<T> JsonRpcRequest<T> {
    /// Create a new JSON-RPC request
    fn new(method: impl Into<String>, id: Id, params: T) -> Self {
        Self {
            jsonrpc: "2.0",
            id,
            method: method.into(),
            params,
        }
    }
}

/// JSON-RPC error payload
#[derive(Debug, Deserialize)]
struct ErrorPayload {
    code: i64,
    message: String,
    #[serde(default, rename = "data")]
    _data: Option<Value>,
}

/// Errors that can occur when interacting with RPC operations.
#[crate::bedrock_error]
pub enum RpcError {
    /// HTTP request failed
    #[error("HTTP request failed: {0}")]
    HttpError(#[from] HttpError),

    /// JSON parsing error
    #[error("JSON parsing error: {message}")]
    JsonError {
        /// The error message describing the JSON parsing issue
        message: String,
    },

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

/// Parameters for `wa_sponsorUserOperation` request
#[derive(Debug, Serialize)]
struct SponsorUserOperationParams(UserOperationJson, Option<TokenInfo>);

/// Token information for self-sponsorship
#[derive(Debug, Serialize)]
struct TokenInfo {
    token: Address,
}

/// `UserOperation` in JSON format for RPC requests
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct UserOperationJson {
    sender: Address,
    nonce: U256,
    #[serde(skip_serializing_if = "is_zero_address")]
    factory: Address,
    #[serde(skip_serializing_if = "is_empty_bytes")]
    factory_data: Bytes,
    call_data: Bytes,
    #[serde(skip_serializing_if = "Option::is_none")]
    call_gas_limit: Option<U128>,
    #[serde(skip_serializing_if = "Option::is_none")]
    verification_gas_limit: Option<U128>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pre_verification_gas: Option<U256>,
    #[serde(skip_serializing_if = "Option::is_none")]
    max_fee_per_gas: Option<U128>,
    #[serde(skip_serializing_if = "Option::is_none")]
    max_priority_fee_per_gas: Option<U128>,
    #[serde(skip_serializing_if = "Option::is_none")]
    paymaster: Option<Address>,
    #[serde(skip_serializing_if = "Option::is_none")]
    paymaster_verification_gas_limit: Option<U128>,
    #[serde(skip_serializing_if = "Option::is_none")]
    paymaster_post_op_gas_limit: Option<U128>,
    #[serde(skip_serializing_if = "Option::is_none")]
    paymaster_data: Option<Bytes>,
    #[serde(skip_serializing_if = "is_empty_bytes")]
    signature: Bytes,
}

fn is_zero_address(addr: &Address) -> bool {
    addr.is_zero()
}

fn is_empty_bytes(bytes: &Bytes) -> bool {
    bytes.is_empty()
}

impl From<&UserOperation> for UserOperationJson {
    fn from(op: &UserOperation) -> Self {
        Self {
            sender: op.sender,
            nonce: op.nonce,
            factory: op.factory,
            factory_data: op.factory_data.clone(),
            call_data: op.call_data.clone(),
            call_gas_limit: if op.call_gas_limit == 0 {
                None
            } else {
                Some(U128::from(op.call_gas_limit))
            },
            verification_gas_limit: if op.verification_gas_limit == 0 {
                None
            } else {
                Some(U128::from(op.verification_gas_limit))
            },
            pre_verification_gas: if op.pre_verification_gas.is_zero() {
                None
            } else {
                Some(op.pre_verification_gas)
            },
            max_fee_per_gas: if op.max_fee_per_gas == 0 {
                None
            } else {
                Some(U128::from(op.max_fee_per_gas))
            },
            max_priority_fee_per_gas: if op.max_priority_fee_per_gas == 0 {
                None
            } else {
                Some(U128::from(op.max_priority_fee_per_gas))
            },
            paymaster: if op.paymaster.is_zero() {
                None
            } else {
                Some(op.paymaster)
            },
            paymaster_verification_gas_limit: if op.paymaster_verification_gas_limit
                == 0
            {
                None
            } else {
                Some(U128::from(op.paymaster_verification_gas_limit))
            },
            paymaster_post_op_gas_limit: if op.paymaster_post_op_gas_limit == 0 {
                None
            } else {
                Some(U128::from(op.paymaster_post_op_gas_limit))
            },
            paymaster_data: if op.paymaster_data.is_empty() {
                None
            } else {
                Some(op.paymaster_data.clone())
            },
            signature: op.signature.clone(),
        }
    }
}

/// RPC client for handling 4337 `UserOperation` requests
///
/// This client communicates with the app-backend's RPC endpoint at `/v1/rpc/worldchain`.
/// All operations are performed on World Chain (chain ID: 480).
pub struct RpcClient<'a> {
    http_client: &'a dyn AuthenticatedHttpClient,
}

/// World Chain constants
const WORLDCHAIN_NETWORK: &str = "worldchain";

/// World Chain's chain ID
pub const WORLDCHAIN_CHAIN_ID: u32 = 480;

impl<'a> RpcClient<'a> {
    /// Creates a new RPC client for World Chain
    ///
    /// # Arguments
    /// * `http_client` - The authenticated HTTP client for making requests
    pub fn new(http_client: &'a dyn AuthenticatedHttpClient) -> Self {
        Self { http_client }
    }

    /// Constructs the RPC endpoint URL for World Chain
    fn rpc_endpoint() -> String {
        format!("/v1/rpc/{WORLDCHAIN_NETWORK}")
    }

    /// Makes a generic RPC call with typed parameters and result
    async fn rpc_call<P, R>(&self, method: &str, params: P) -> Result<R, RpcError>
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
            serde_json::to_vec(&request).map_err(|e| RpcError::JsonError {
                message: format!("Failed to serialize request: {e}"),
            })?;

        // Send the HTTP request
        let response_bytes = self
            .http_client
            .fetch_from_app_backend(
                Self::rpc_endpoint(),
                HttpMethod::Post,
                Some(request_body),
            )
            .await?;

        // Parse the response as a generic JSON value first to handle both success and error cases
        let json_response: Value =
            serde_json::from_slice(&response_bytes).map_err(|e| {
                RpcError::JsonError {
                    message: format!("Failed to parse response as JSON: {e}"),
                }
            })?;

        // Check if it's an error response
        if let Some(error) = json_response.get("error") {
            let error_payload: ErrorPayload = serde_json::from_value(error.clone())
                .map_err(|e| RpcError::JsonError {
                    message: format!("Failed to parse error payload: {e}"),
                })?;

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
                serde_json::from_value(result.clone()).map_err(|e| {
                    RpcError::JsonError {
                        message: format!("Failed to parse result: {e}"),
                    }
                })
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
    ///
    /// # Implementation Note
    ///
    /// This method requires the `wa_sponsorUserOperation` handler to be implemented in the app-backend.
    /// As of now, this handler is not yet implemented and will return a "method not found" error.
    pub async fn sponsor_user_operation(
        &self,
        user_operation: &UserOperation,
        self_sponsor_token: Option<Address>,
    ) -> Result<SponsorUserOperationResponse, RpcError> {
        let params = SponsorUserOperationParams(
            user_operation.into(),
            self_sponsor_token.map(|token| TokenInfo { token }),
        );

        self.rpc_call("wa_sponsorUserOperation", params).await
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
        user_operation: &UserOperation,
        entrypoint: Address,
    ) -> Result<FixedBytes<32>, RpcError> {
        let params = vec![
            serde_json::to_value(UserOperationJson::from(user_operation)).map_err(
                |e| RpcError::JsonError {
                    message: format!("Failed to serialize UserOperation: {e}"),
                },
            )?,
            serde_json::Value::String(format!("{entrypoint:?}")),
        ];

        let result: String = self.rpc_call("eth_sendUserOperation", params).await?;

        FixedBytes::from_hex(&result).map_err(|e| RpcError::InvalidResponse {
            message: format!("Invalid userOpHash format: {e}"),
        })
    }
}

/// Extension to merge paymaster data into a `UserOperation`
impl UserOperation {
    /// Merges paymaster data from sponsorship response into the `UserOperation`
    #[must_use]
    pub fn with_paymaster_data(
        mut self,
        sponsor_response: SponsorUserOperationResponse,
    ) -> Self {
        self.paymaster = sponsor_response.paymaster;
        self.paymaster_data = sponsor_response.paymaster_data;
        self.paymaster_verification_gas_limit = sponsor_response
            .paymaster_verification_gas_limit
            .try_into()
            .unwrap_or(0);
        self.paymaster_post_op_gas_limit = sponsor_response
            .paymaster_post_op_gas_limit
            .try_into()
            .unwrap_or(0);

        // Update gas fields if they were estimated by the RPC
        if self.pre_verification_gas.is_zero() {
            self.pre_verification_gas = sponsor_response.pre_verification_gas;
        }
        if self.verification_gas_limit == 0 {
            self.verification_gas_limit = sponsor_response
                .verification_gas_limit
                .try_into()
                .unwrap_or(0);
        }
        if self.call_gas_limit == 0 {
            self.call_gas_limit =
                sponsor_response.call_gas_limit.try_into().unwrap_or(0);
        }
        if self.max_fee_per_gas == 0 {
            self.max_fee_per_gas =
                sponsor_response.max_fee_per_gas.try_into().unwrap_or(0);
        }
        if self.max_priority_fee_per_gas == 0 {
            self.max_priority_fee_per_gas = sponsor_response
                .max_priority_fee_per_gas
                .try_into()
                .unwrap_or(0);
        }

        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::{address, bytes, U256};
    use serde_json::json;

    #[test]
    fn test_user_operation_json_serialization() {
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

        let json_op = UserOperationJson::from(&user_op);
        let serialized = serde_json::to_value(&json_op).unwrap();

        assert_eq!(
            serialized["sender"],
            "0x5a6b47f4131bf1feafa56a05573314bcf44c9149"
        );
        assert_eq!(
            serialized["nonce"],
            "0x845adb2c711129d4f3966735ed98a9f09fc4ce57"
        );
        assert_eq!(serialized["callData"], "0xe9ae5c53");
        assert_eq!(serialized["callGasLimit"], "0x13880");
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
}
