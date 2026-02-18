//! Test utilities for unit tests and E2E tests for mocking RPC responses either from Anvil or hard-coded for unit tests.
#![allow(clippy::all)]
use std::str::FromStr;

use alloy::{
    network::Ethereum,
    primitives::{keccak256, Address, FixedBytes, Log, U128, U256},
    providers::Provider,
    sol,
    sol_types::{SolEvent, SolValue},
};

use crate::{
    primitives::{
        http_client::{AuthenticatedHttpClient, HttpError, HttpHeader, HttpMethod},
        PrimitiveError,
    },
    smart_account::UserOperation,
    transactions::foreign::UnparsedUserOperation,
};

/// Represents a response from '`wa_sponsorUserOperation`' rpc method
#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct SponsorUserOperationResponseLite<'a> {
    paymaster: Option<&'a str>,
    paymaster_data: Option<&'a str>,
    pre_verification_gas: String,
    verification_gas_limit: String,
    call_gas_limit: String,
    paymaster_verification_gas_limit: String,
    paymaster_post_op_gas_limit: String,
    max_priority_fee_per_gas: String,
    max_fee_per_gas: String,
    provider_name: String,
}

sol! {
    /// Packed user operation for `EntryPoint`
    #[sol(rename_all = "camelCase")]
    struct PackedUserOperation {
        address sender;
        uint256 nonce;
        bytes init_code;
        bytes call_data;
        bytes32 account_gas_limits;
        uint256 pre_verification_gas;
        bytes32 gas_fees;
        bytes paymaster_and_data;
        bytes signature;
    }

    #[sol(rpc)]
    interface IEntryPoint {
        event UserOperationRevertReason(
            bytes32 indexed userOpHash,
            address indexed sender,
            uint256 nonce,
            bytes revertReason
        );

        event UserOperationEvent(
            bytes32 indexed userOpHash,
            address indexed sender,
            address indexed paymaster,
            uint256 nonce,
            bool success,
            uint256 actualGasCost,
            uint256 actualGasUsed
        );

        function depositTo(address account) external payable;
        function handleOps(PackedUserOperation[] calldata ops, address payable beneficiary) external;
    }

}

/// Pack two U128 in 32 bytes
#[must_use]
pub fn pack_pair(a: &U128, b: &U128) -> FixedBytes<32> {
    let mut out = [0u8; 32];
    out[..16].copy_from_slice(&a.to_be_bytes::<16>());
    out[16..].copy_from_slice(&b.to_be_bytes::<16>());
    out.into()
}

impl TryFrom<&UserOperation> for PackedUserOperation {
    type Error = PrimitiveError;

    fn try_from(user_op: &UserOperation) -> Result<Self, Self::Error> {
        Ok(Self {
            sender: user_op.sender,
            nonce: user_op.nonce,
            init_code: user_op.get_init_code(),
            call_data: user_op.call_data.clone(),
            account_gas_limits: pack_pair(
                &user_op.verification_gas_limit,
                &user_op.call_gas_limit,
            ),
            pre_verification_gas: user_op.pre_verification_gas,
            gas_fees: pack_pair(
                &user_op.max_priority_fee_per_gas,
                &user_op.max_fee_per_gas,
            ),
            paymaster_and_data: user_op.get_paymaster_and_data(),
            signature: user_op.signature.clone(),
        })
    }
}

use std::collections::HashMap;

/// Mock HTTP client for testing that can provide custom responses for `eth_call`
#[derive(Clone)]
pub struct AnvilBackedHttpClient<P>
where
    P: Provider<Ethereum> + Clone + Send + Sync + 'static,
{
    /// The underlying Ethereum provider
    pub provider: P,
    /// Custom responses for `eth_call` based on contract address only
    pub address_responses: HashMap<Address, String>,
    /// Custom responses for `eth_call` based on contract address AND call data
    pub address_data_responses: HashMap<(Address, String), String>,
}

impl<P> AnvilBackedHttpClient<P>
where
    P: Provider<Ethereum> + Clone + Send + Sync + 'static,
{
    /// Creates a new `AnvilBackedHttpClient` with no custom responses
    pub fn new(provider: P) -> Self {
        Self {
            provider,
            address_responses: HashMap::new(),
            address_data_responses: HashMap::new(),
        }
    }

    /// Sets a custom response for `eth_call` based on contract address only
    pub fn set_response_for_address(
        &mut self,
        to_address: Address,
        response_hex: String,
    ) {
        self.address_responses.insert(to_address, response_hex);
    }

    /// Sets a custom response for `eth_call` based on contract address AND call data
    pub fn set_response_for_address_and_data(
        &mut self,
        to_address: Address,
        call_data: String,
        response_hex: String,
    ) {
        self.address_data_responses
            .insert((to_address, call_data), response_hex);
    }
}

#[async_trait::async_trait]
impl<P> AuthenticatedHttpClient for AnvilBackedHttpClient<P>
where
    P: Provider<Ethereum> + Clone + Send + Sync + 'static,
{
    #[allow(clippy::too_many_lines, clippy::or_fun_call)]
    async fn fetch_from_app_backend(
        &self,
        url: String,
        method: HttpMethod,
        _headers: Vec<HttpHeader>,
        body: Option<Vec<u8>>,
    ) -> Result<Vec<u8>, HttpError> {
        if method != HttpMethod::Post {
            return Err(HttpError::Generic {
                error_message: "unsupported method".into(),
            });
        }

        let body = body.ok_or(HttpError::Generic {
            error_message: "missing body".into(),
        })?;

        let root: serde_json::Value =
            serde_json::from_slice(&body).map_err(|_| HttpError::Generic {
                error_message: "invalid json".into(),
            })?;

        let method =
            root.get("method")
                .and_then(|m| m.as_str())
                .ok_or(HttpError::Generic {
                    error_message: "invalid json".into(),
                })?;
        let id = root.get("id").cloned().unwrap_or(serde_json::Value::Null);
        let params = root
            .get("params")
            .cloned()
            .unwrap_or(serde_json::Value::Null);

        match method {
            // Respond with minimal, sane gas values and no paymaster
            "wa_sponsorUserOperation" => {
                let result = SponsorUserOperationResponseLite {
                    paymaster: None,
                    paymaster_data: None,
                    pre_verification_gas: "0x200000".into(), // 2M
                    verification_gas_limit: "0x200000".into(), // 2M
                    call_gas_limit: "0x200000".into(),       // 2M
                    paymaster_verification_gas_limit: "0x0".into(),
                    paymaster_post_op_gas_limit: "0x0".into(),
                    max_priority_fee_per_gas: "0x12A05F200".into(), // 5 gwei
                    max_fee_per_gas: "0x12A05F200".into(),          // 5 gwei
                    provider_name: "pimlico".into(),
                };
                let resp = serde_json::json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "result": result,
                });
                Ok(serde_json::to_vec(&resp).unwrap())
            }
            // Execute the inner call directly through the Safe 4337 Module (no sponsorship path)
            "eth_sendUserOperation" => {
                let params = params.as_array().ok_or(HttpError::Generic {
                    error_message: "invalid params".into(),
                })?;
                let user_op_val = params.first().ok_or(HttpError::Generic {
                    error_message: "missing userOp param".into(),
                })?;
                let entry_point_str = params.get(1).and_then(|v| v.as_str()).ok_or(
                    HttpError::Generic {
                        error_message: "missing entryPoint param".into(),
                    },
                )?;
                // Build UnparsedUserOperation from JSON (which uses hex strings), then convert
                let obj = user_op_val.as_object().ok_or(HttpError::Generic {
                    error_message: "userOp param must be an object".into(),
                })?;

                let get_opt = |k: &str| -> Option<String> {
                    obj.get(k)
                        .and_then(|v| v.as_str())
                        .map(std::string::ToString::to_string)
                };
                let get_or_zero = |k: &str| -> String {
                    get_opt(k).unwrap_or_else(|| "0x0".to_string())
                };
                let get_required = |k: &str| -> Result<String, HttpError> {
                    get_opt(k).ok_or(HttpError::Generic {
                        error_message: format!("missing or invalid {k}"),
                    })
                };

                let unparsed = UnparsedUserOperation {
                    sender: get_required("sender")?,
                    nonce: get_required("nonce")?,
                    call_data: get_required("callData")?,
                    call_gas_limit: get_or_zero("callGasLimit"),
                    verification_gas_limit: get_or_zero("verificationGasLimit"),
                    pre_verification_gas: get_or_zero("preVerificationGas"),
                    max_fee_per_gas: get_or_zero("maxFeePerGas"),
                    max_priority_fee_per_gas: get_or_zero("maxPriorityFeePerGas"),
                    paymaster: get_opt("paymaster"),
                    paymaster_verification_gas_limit: get_opt(
                        "paymasterVerificationGasLimit",
                    ),
                    paymaster_post_op_gas_limit: get_opt("paymasterPostOpGasLimit"),
                    paymaster_data: get_opt("paymasterData"),
                    signature: get_required("signature")?,
                    factory: get_opt("factory"),
                    factory_data: get_opt("factoryData"),
                };

                let user_op: UserOperation =
                    unparsed.try_into().map_err(|e| HttpError::Generic {
                        error_message: format!("invalid userOp: {e}"),
                    })?;

                // Convert to the packed format expected by EntryPoint
                let packed = PackedUserOperation::try_from(&user_op).map_err(|e| {
                    HttpError::Generic {
                        error_message: format!("pack userOp failed: {e}"),
                    }
                })?;

                // Compute the EntryPoint userOpHash per EIP-4337 spec
                let packed_for_hash =
                    PackedUserOperation::try_from(&user_op).map_err(|e| {
                        HttpError::Generic {
                            error_message: format!("pack userOp for hash failed: {e}"),
                        }
                    })?;
                let chain_id_u64 = self.provider.get_chain_id().await.map_err(|e| {
                    HttpError::Generic {
                        error_message: format!("getChainId failed: {e}"),
                    }
                })?;
                let inner_encoded = (
                    packed_for_hash.sender,
                    packed_for_hash.nonce,
                    keccak256(packed_for_hash.init_code.clone()),
                    keccak256(packed_for_hash.call_data.clone()),
                    packed_for_hash.account_gas_limits,
                    packed_for_hash.pre_verification_gas,
                    packed_for_hash.gas_fees,
                    keccak256(packed_for_hash.paymaster_and_data.clone()),
                )
                    .abi_encode();
                let inner_hash = keccak256(inner_encoded);

                // Execute via EntryPoint.handleOps on-chain
                let entry_point_addr =
                    Address::from_str(entry_point_str).map_err(|_| {
                        HttpError::Generic {
                            error_message: "invalid entryPoint".into(),
                        }
                    })?;
                let entry_point = IEntryPoint::new(entry_point_addr, &self.provider);
                let tx = entry_point
                    .handleOps(vec![packed], user_op.sender)
                    .send()
                    .await
                    .map_err(|e| HttpError::Generic {
                        error_message: format!("handleOps failed: {e}"),
                    })?;
                let receipt =
                    tx.get_receipt().await.map_err(|e| HttpError::Generic {
                        error_message: format!("handleOps receipt failed: {e}"),
                    })?;

                // Check for error events in the receipt
                for log in receipt.inner.logs() {
                    let raw_log = Log {
                        address: log.address(),
                        data: log.data().clone(),
                    };

                    // Check for UserOperationRevertReason event
                    if let Ok(revert_event) =
                        IEntryPoint::UserOperationRevertReason::decode_log(&raw_log)
                    {
                        let revert_reason = if revert_event.revertReason.is_empty() {
                            "Unknown revert reason".to_string()
                        } else {
                            String::from_utf8(revert_event.revertReason.to_vec())
                                .unwrap_or_else(|_| {
                                    format!(
                                        "0x{}",
                                        hex::encode(&revert_event.revertReason)
                                    )
                                })
                        };

                        return Err(HttpError::Generic {
                            error_message: format!(
                                "UserOperation reverted - sender: {}, nonce: {}, reason: {}",
                                revert_event.sender, revert_event.nonce, revert_reason
                            ),
                        });
                    }

                    // Log UserOperationEvent for debugging
                    if let Ok(event) =
                        IEntryPoint::UserOperationEvent::decode_log(&raw_log)
                    {
                        println!(
                            "UserOperationEvent - sender: {}, success: {}, actualGasCost: {}, actualGasUsed: {}",
                            event.sender, event.success, event.actualGasCost, event.actualGasUsed
                        );
                    }
                }

                // Return the chain userOpHash (EntryPoint-wrapped)
                let enc = (inner_hash, entry_point_addr, U256::from(chain_id_u64))
                    .abi_encode();
                let user_op_hash = keccak256(enc);

                let resp = serde_json::json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "result": format!("0x{}", hex::encode(user_op_hash)),
                });
                Ok(serde_json::to_vec(&resp).unwrap())
            }
            // Return a mocked wa_getUserOperationReceipt response with static values
            "wa_getUserOperationReceipt" => {
                let params = params.as_array().ok_or(HttpError::Generic {
                    error_message: "invalid params".into(),
                })?;
                let user_op_hash = params.first().and_then(|v| v.as_str()).ok_or(
                    HttpError::Generic {
                        error_message: "missing userOpHash param".into(),
                    },
                )?;

                // Extract the network from the URL path (e.g. "/v1/rpc/worldchain" -> "worldchain")
                let network_name = url.rsplit('/').next().unwrap_or_default();

                let result = serde_json::json!({
                    "network": network_name,
                    "userOpHash": user_op_hash,
                    "transactionHash":
                        "0x3a9b7d5e1f0a4c2e6b8d7f9a1c3e5f0b2d4a6c8e9f1b3d5c7a9e0f2c4b6d8a0",
                    "sender": "0x1234567890abcdef1234567890abcdef12345678",
                    "status": "mined_success",
                    "source": "campaign_gift_sponsor",
                    "sourceId": "0x1",
                    "selfSponsorToken": serde_json::Value::Null,
                    "selfSponsorAmount": serde_json::Value::Null,
                    "blockTimestamp": "2025-11-24T20:15:32.000Z",
                });

                let resp = serde_json::json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "result": result,
                });
                Ok(serde_json::to_vec(&resp).unwrap())
            }
            "eth_call" => {
                let params = params.as_array().ok_or(HttpError::Generic {
                    error_message: "invalid params".into(),
                })?;

                let call_params = params.first().ok_or(HttpError::Generic {
                    error_message: "missing call params".into(),
                })?;

                let call_obj = call_params.as_object().ok_or(HttpError::Generic {
                    error_message: "call params must be an object".into(),
                })?;

                // Extract the 'to' address from the call parameters
                let to_str = call_obj.get("to").and_then(|v| v.as_str()).ok_or(
                    HttpError::Generic {
                        error_message: "missing 'to' address in eth_call".into(),
                    },
                )?;

                let to_address =
                    Address::from_str(to_str).map_err(|_| HttpError::Generic {
                        error_message: "invalid 'to' address format".into(),
                    })?;

                // Extract call data
                let call_data = call_obj.get("data").and_then(|v| v.as_str()).ok_or(
                    HttpError::Generic {
                        error_message: "missing 'data' in eth_call".into(),
                    },
                )?;

                // First check if we have a custom response for this specific address + data combination
                if let Some(custom_response) = self
                    .address_data_responses
                    .get(&(to_address, call_data.to_string()))
                {
                    let resp = serde_json::json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "result": custom_response,
                    });
                    return Ok(serde_json::to_vec(&resp).unwrap());
                }

                // Then check if we have a custom response for this address only
                if let Some(custom_response) = self.address_responses.get(&to_address) {
                    let resp = serde_json::json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "result": custom_response,
                    });
                    return Ok(serde_json::to_vec(&resp).unwrap());
                }

                // If no custom response, forward to the actual provider

                // Forward to real provider using simpler call interface
                let result = self
                    .provider
                    .raw_request::<_, alloy::primitives::Bytes>(
                        "eth_call".into(),
                        [
                            serde_json::json!({
                                "to": format!("{to_address:?}"),
                                "data": call_data
                            }),
                            serde_json::json!("latest"),
                        ],
                    )
                    .await
                    .map_err(|e| HttpError::Generic {
                        error_message: format!("eth_call failed: {e}"),
                    })?;

                let resp = serde_json::json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "result": format!("0x{}", hex::encode(result)),
                });
                Ok(serde_json::to_vec(&resp).unwrap())
            }
            other => Err(HttpError::Generic {
                error_message: format!("unsupported method {other}"),
            }),
        }
    }
}

/// Starts a minimal HTTP server that simulates a 4337 bundler by routing
/// incoming JSON-RPC requests through the given [`AnvilBackedHttpClient`].
///
/// Returns the base URL (e.g. `http://127.0.0.1:12345`) the server is
/// listening on. The server runs in a background tokio task and handles
/// one request per connection (`Connection: close`).
///
/// # Panics
///
/// Panics if the TCP listener fails to bind to a local address.
pub async fn start_mock_bundler_server<P>(client: AnvilBackedHttpClient<P>) -> String
where
    P: Provider<Ethereum> + Clone + Send + Sync + 'static,
{
    use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("failed to bind mock bundler server");
    let url = format!("http://{}", listener.local_addr().unwrap());

    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                break;
            };
            let client = client.clone();
            tokio::spawn(async move {
                let (reader, mut writer) = stream.into_split();
                let mut reader = BufReader::new(reader);
                let mut line = String::new();

                // 1. Skip the request line (e.g. "POST / HTTP/1.1\r\n")
                let _ = reader.read_line(&mut line).await;

                // 2. Read headers line-by-line, extract Content-Length
                let mut content_length: usize = 0;
                loop {
                    line.clear();
                    let _ = reader.read_line(&mut line).await;
                    if line.trim().is_empty() {
                        break;
                    }
                    let lower = line.to_ascii_lowercase();
                    if let Some(val) = lower.strip_prefix("content-length:") {
                        content_length = val.trim().parse().unwrap_or(0);
                    }
                }

                // 3. Read exactly `content_length` bytes of body
                let mut body = vec![0u8; content_length];
                let _ = reader.read_exact(&mut body).await;

                // 4. Delegate to the Anvil-backed bundler simulation
                let (status, response_body) = match client
                    .fetch_from_app_backend(
                        String::new(),
                        HttpMethod::Post,
                        vec![],
                        Some(body),
                    )
                    .await
                {
                    Ok(b) => ("200 OK", b),
                    Err(e) => {
                        ("500 Internal Server Error", format!("{e}").into_bytes())
                    }
                };

                // 5. Write HTTP response
                let header = format!(
                    "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    response_body.len()
                );
                let _ = writer.write_all(header.as_bytes()).await;
                let _ = writer.write_all(&response_body).await;
            });
        }
    });

    url
}
