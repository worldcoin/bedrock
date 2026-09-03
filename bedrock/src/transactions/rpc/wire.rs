use alloy::primitives::{Address, Bytes, U128, U256};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;

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
    /// Request sponsorship for a `UserOperation` (V1)
    #[serde(rename = "wa_sponsorUserOperation")]
    SponsorUserOperation,
    /// Request sponsorship for a `UserOperation` (V2)
    #[serde(rename = "pm_sponsorUserOperation")]
    PmSponsorUserOperation,
    /// Queries the status of a `UserOperation`
    #[serde(rename = "wa_getUserOperationReceipt")]
    WaGetUserOperationReceipt,
    /// Relay a signed Safe `execTransaction` for the backend to submit on-chain
    #[serde(rename = "wa_relaySafeTransaction")]
    RelaySafeTransaction,
    /// Submit a signed `UserOperation` (V1)
    #[serde(rename = "eth_sendUserOperation")]
    SendUserOperation,
    /// Submit a signed `UserOperation` (V2)
    #[serde(rename = "eth_sendUserOperation")]
    SendUserOperationV2,
    /// Make a read call to a smart contract
    #[serde(rename = "eth_call")]
    EthCall,
    /// Read a single storage slot of a contract
    #[serde(rename = "eth_getStorageAt")]
    EthGetStorageAt,
    /// Query supported ERC-4337 entry points
    #[serde(rename = "eth_supportedEntryPoints")]
    SupportedEntryPoints,
}

/// 4337 provider selection to be passed by native apps
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RpcProviderName {
    /// Let TFH backend load balance between available providers
    Any,
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
            Self::Any => "any",
            Self::Alchemy => "alchemy",
            Self::Pimlico => "pimlico",
        }
    }
}

/// JSON-RPC request envelope, shared with [`crate::transactions::custom_bundler`].
#[derive(Debug, Serialize)]
pub struct JsonRpcRequest<T> {
    jsonrpc: &'static str,
    id: Id,
    method: RpcMethod,
    params: T,
}

impl<T> JsonRpcRequest<T> {
    pub(crate) const fn new(method: RpcMethod, id: Id, params: T) -> Self {
        Self {
            jsonrpc: "2.0",
            id,
            method,
            params,
        }
    }
}

/// JSON-RPC error response, shared with [`crate::transactions::custom_bundler`].
#[derive(Debug, Deserialize)]
pub struct JsonRpcError {
    pub code: i64,
    pub message: String,
    #[serde(default)]
    pub data: Option<Value>,
}

/// Structured details returned when protocol sponsorship is declined.
#[derive(Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SponsorshipDeclineDetails {
    /// ERC-20 token the user can use to pay the transaction fee.
    pub token: Address,
    /// Paymaster contract that accepts the fee token.
    pub paymaster_address: Address,
    /// Policy reason for declining protocol sponsorship.
    pub reason: SponsorshipDeclineReason,
}

/// Reason protocol sponsorship was declined.
#[derive(Debug, PartialEq, Eq)]
pub enum SponsorshipDeclineReason {
    /// The L2 base fee exceeded the sponsorship threshold.
    L2BaseFee,
    /// The L1 data fee exceeded the sponsorship threshold.
    L1DataFee,
    /// The user's transaction count exceeded the sponsorship threshold.
    TransactionCount,
    /// The estimated gas usage exceeded the sponsorship threshold.
    GasUsage,
    /// A reason introduced by a newer sponsorship service.
    Unknown(String),
}

impl<'de> Deserialize<'de> for SponsorshipDeclineReason {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Ok(match value.as_str() {
            "l2_base_fee" => Self::L2BaseFee,
            "l1_data_fee" => Self::L1DataFee,
            "tx_count" => Self::TransactionCount,
            "gas_usage" => Self::GasUsage,
            _ => Self::Unknown(value),
        })
    }
}

/// Response from `wa_sponsorUserOperation`
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SponsorUserOperationResponse {
    /// Paymaster address
    pub paymaster: Option<Address>,
    /// Paymaster data
    pub paymaster_data: Option<Bytes>,
    /// Pre-verification gas
    pub pre_verification_gas: U256,
    /// Verification gas limit
    pub verification_gas_limit: U128,
    /// Call gas limit
    pub call_gas_limit: U128,
    /// Paymaster verification gas limit
    pub paymaster_verification_gas_limit: Option<U128>,
    /// Paymaster post-op gas limit
    pub paymaster_post_op_gas_limit: Option<U128>,
    /// Max priority fee per gas
    pub max_priority_fee_per_gas: U128,
    /// Max fee per gas
    pub max_fee_per_gas: U128,
    /// provider name
    pub provider_name: RpcProviderName,
}

/// Response from `pm_sponsorUserOperation` (V2)
///
/// Paymaster fields (`paymaster`, `paymaster_data`,
/// `paymaster_verification_gas_limit`, `paymaster_post_op_gas_limit`) are
/// absent from the bundler-sponsored response shape and present on the
/// self-sponsored (token) response — see
/// `bedrock/src/transactions/transaction.md`. They are modelled as
/// `Option<T>` so both shapes deserialize.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PmSponsorUserOperationResponse {
    /// Call gas limit
    pub call_gas_limit: U128,
    /// Verification gas limit
    pub verification_gas_limit: U128,
    /// Pre-verification gas
    pub pre_verification_gas: U256,
    /// Max fee per gas
    pub max_fee_per_gas: U128,
    /// Max priority fee per gas
    pub max_priority_fee_per_gas: U128,
    /// Paymaster address (absent on the bundler-sponsored path)
    pub paymaster: Option<Address>,
    /// Paymaster verification gas limit (absent on the bundler-sponsored path)
    pub paymaster_verification_gas_limit: Option<U128>,
    /// Paymaster post-op gas limit (absent on the bundler-sponsored path)
    pub paymaster_post_op_gas_limit: Option<U128>,
    /// Paymaster data (absent on the bundler-sponsored path)
    pub paymaster_data: Option<Bytes>,
}

/// Context object passed as the third parameter of `pm_sponsorUserOperation`.
///
/// V2 sponsorship is a two-mode protocol: an initial protocol-sponsored
/// attempt with empty context, followed (on a structured decline) by a
/// self-sponsored retry that names the ERC-20 token paying for gas. See
/// `bedrock/src/transactions/transaction.md`.
#[derive(Debug, Clone)]
pub enum SponsorshipContext {
    /// Empty context — request protocol sponsorship (the wallet provider
    /// pays gas). Distinct from the ERC-4337 notion of bundler sponsorship,
    /// which implies a user-appointed bundler choosing to sponsor.
    Protocol,
    /// Self-sponsored mode with the given ERC-20 token paying for gas.
    SelfSponsoredToken(Address),
}

impl SponsorshipContext {
    pub(super) fn to_json_value(&self) -> serde_json::Value {
        match self {
            Self::Protocol => serde_json::json!({}),
            Self::SelfSponsoredToken(token) => {
                serde_json::json!({ "token": format!("{token:?}") })
            }
        }
    }
}

/// Response from `wa_getUserOperationReceipt`
#[derive(Debug, Deserialize, uniffi::Record, Clone)]
#[serde(rename_all = "camelCase")]
pub struct WaGetUserOperationReceiptResponse {
    /// User operation hash
    pub user_op_hash: String,
    /// Transaction hash, if the user operation has been included in a block
    pub transaction_hash: Option<String>,
    /// Sender address
    pub sender: String,
    /// Status (`pending`, `error`, `mined_success`, or `mined_revert`)
    pub status: String,
    /// Source (flexible field representing the transaction type or origin)
    pub source: String,
    /// Source ID, if available
    pub source_id: Option<String>,
    /// Self-sponsor token, if applicable
    pub self_sponsor_token: Option<String>,
    /// Self-sponsor amount, if applicable
    pub self_sponsor_amount: Option<String>,
    /// Block timestamp, if the user operation has been included in a block
    pub block_timestamp: Option<String>,
}

/// Single positional param for the `wa_relaySafeTransaction` JSON-RPC call.
///
/// Mirrors the arguments of the Safe `execTransaction` method plus the target
/// Safe. All numeric fields are `0x`-prefixed hex and addresses are
/// `0x`-prefixed; `signatures` is the packed owner signature(s).
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RelaySafeTransactionRequest {
    /// The Safe whose `execTransaction` is being called.
    pub safe_address: String,
    /// `to` argument of `execTransaction`.
    pub to: String,
    /// `value` argument.
    pub value: String,
    /// `data` argument.
    pub data: String,
    /// `operation` argument (`0` = call, `1` = delegatecall).
    pub operation: u8,
    /// `safeTxGas` argument.
    pub safe_tx_gas: String,
    /// `baseGas` argument.
    pub base_gas: String,
    /// `gasPrice` argument.
    pub gas_price: String,
    /// `gasToken` argument.
    pub gas_token: String,
    /// `refundReceiver` argument.
    pub refund_receiver: String,
    /// `nonce` argument.
    pub nonce: String,
    /// Packed owner signature(s).
    pub signatures: String,
}
