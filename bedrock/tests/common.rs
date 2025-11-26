#![allow(dead_code)]
use std::str::FromStr;

use alloy::{
    network::Ethereum,
    node_bindings::AnvilInstance,
    primitives::{address, keccak256, Address, FixedBytes, Log, U128, U256},
    providers::{ext::AnvilApi, Provider},
    sol,
    sol_types::{SolCall, SolEvent, SolValue},
};

use bedrock::{
    primitives::{
        config::{current_environment_or_default, BedrockEnvironment},
        http_client::{AuthenticatedHttpClient, HttpError, HttpHeader, HttpMethod},
        PrimitiveError,
    },
    smart_account::UserOperation,
    transactions::foreign::UnparsedUserOperation,
};

sol!(
    #[allow(missing_docs)]
    #[sol(rpc)]
    interface ISafeProxyFactory {
        event ProxyCreation(address indexed proxy, address singleton);

        function createProxyWithNonce(
            address _singleton,
            bytes memory initializer,
            uint256 saltNonce
        ) external returns (address proxy);
    }
);

// https://github.com/safe-global/safe-smart-account/blob/v1.5.0/contracts/interfaces/ISafe.sol
sol!(
    #[allow(clippy::too_many_arguments)]
    #[sol(rpc)]
    interface ISafe {
        function setup(
            address[] calldata _owners,
            uint256 _threshold,
            address to,
            bytes calldata data,
            address fallbackHandler,
            address paymentToken,
            uint256 payment,
            address payable paymentReceiver
        ) external;

        function enableModules(address[] memory modules) external;

        /// EIP-1271 validation
        function isValidSignature(bytes32 dataHash, bytes memory signature) external view returns (bytes4);

        /// Execute Safe transaction
        function execTransaction(
            address to,
            uint256 value,
            bytes calldata data,
            uint8 operation,
            uint256 safeTxGas,
            uint256 baseGas,
            uint256 gasPrice,
            address gasToken,
            address payable refundReceiver,
            bytes memory signatures
        ) external payable returns (bool success);
    }
);

sol! {
    /// Packed user operation for EntryPoint
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

    #[sol(rpc)]
    interface IERC20 {
        function transfer(address to, uint256 amount) external returns (bool);
        function balanceOf(address account) external view returns (uint256);
        function approve(address spender, uint256 amount) external returns (bool);
    }

    /// 4337 Module for Safe Smart Account
    #[sol(rpc)]
    interface ISafe4337Module {
        function executeUserOp(
            address to,
            uint256 value,
            bytes calldata data,
            uint8 operation
        ) external;
    }
}

// Safe contract addresses on Worldchain
pub const SAFE_PROXY_FACTORY_ADDRESS: Address =
    address!("4e1DCf7AD4e460CfD30791CCC4F9c8a4f820ec67");
pub const SAFE_L2_SINGLETON_ADDRESS: Address =
    address!("29fcB43b46531BcA003ddC8FCB67FFE91900C762");
pub const SAFE_4337_MODULE_ADDRESS: Address =
    address!("75cf11467937ce3F2f357CE24ffc3DBF8fD5c226");
pub const SAFE_MODULE_SETUP_ADDRESS: Address =
    address!("2dd68b007B46fBe91B9A7c3EDa5A7a1063cB5b47");

pub fn setup_anvil() -> AnvilInstance {
    dotenvy::dotenv().ok();
    let rpc_url = std::env::var("WORLDCHAIN_RPC_URL").unwrap_or_else(|_| {
        // Fallback to a public, no-key RPC if available.
        "https://worldchain-mainnet.g.alchemy.com/v2/demo".to_string()
    });

    alloy::node_bindings::Anvil::new().fork(rpc_url).spawn()
}

pub async fn deploy_safe<P>(
    provider: &P,
    owner: Address,
    deploy_nonce: U256,
) -> anyhow::Result<Address>
where
    P: Provider<Ethereum>,
{
    // Fund the owner to be able to execute transactions
    provider
        .anvil_set_balance(owner, U256::from(1e19 as u64))
        .await
        .unwrap();

    let proxy_factory = ISafeProxyFactory::new(SAFE_PROXY_FACTORY_ADDRESS, provider);

    // Encode the Safe setup call
    let setup_data = ISafe::setupCall {
        _owners: vec![owner],
        _threshold: U256::from(1),
        to: SAFE_MODULE_SETUP_ADDRESS,
        data: ISafe::enableModulesCall {
            modules: vec![SAFE_4337_MODULE_ADDRESS],
        }
        .abi_encode()
        .into(),
        fallbackHandler: SAFE_4337_MODULE_ADDRESS,
        paymentToken: Address::ZERO,
        payment: U256::ZERO,
        paymentReceiver: Address::ZERO,
    }
    .abi_encode();

    // Deploy Safe via proxy factory
    let deploy_tx = proxy_factory
        .createProxyWithNonce(
            SAFE_L2_SINGLETON_ADDRESS,
            setup_data.into(),
            deploy_nonce,
        )
        .from(owner)
        .send()
        .await
        .expect("Failed to send createProxyWithNonce transaction");

    let receipt = deploy_tx
        .get_receipt()
        .await
        .expect("Failed to get transaction receipt");

    // Get the Safe address from the ProxyCreation event
    let proxy_creation_event = receipt
        .inner
        .logs()
        .iter()
        .find_map(|log| {
            let raw_log = Log {
                address: log.address(),
                data: log.data().clone(),
            };
            ISafeProxyFactory::ProxyCreation::decode_log(&raw_log).ok()
        })
        .expect("ProxyCreation event not found");

    Ok(proxy_creation_event.proxy)
}

/// Pack two U128 in 32 bytes
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

/// Set an ERC-20 balance for a Safe by directly writing the storage slot
///
/// The underlying token must store balances as `mapping(address => uint256)` at slot `0`.
pub async fn set_erc20_balance_for_safe<P>(
    provider: &P,
    token: Address,
    safe: Address,
    balance: U256,
) -> anyhow::Result<()>
where
    P: Provider<Ethereum> + AnvilApi<Ethereum>,
{
    // Simulate balance by writing storage slot for mapping(address => uint) at slot 0
    let mut padded = [0u8; 64];
    padded[12..32].copy_from_slice(safe.as_slice());
    let slot_hash = alloy::primitives::keccak256(padded);
    let slot = U256::from_be_bytes(slot_hash.into());

    provider
        .anvil_set_storage_at(token, slot, balance.into())
        .await?;

    Ok(())
}

/// Returns the World ID Address Book contract address for the current Bedrock environment.
/// Reference <https://github.com/worldcoin/worldcoin-vault/blob/main/src/WorldIDAddressBook.sol>
fn address_book_address() -> Address {
    match current_environment_or_default() {
        BedrockEnvironment::Staging => {
            Address::from_str("0xfd5b7aefdd478f34ae61d8399a206a4879f0af0a")
                .expect("failed to decode staging address book address")
        }
        BedrockEnvironment::Production => {
            Address::from_str("0x57b930D551e677CC36e2fA036Ae2fe8FdaE0330D")
                .expect("failed to decode production address book address")
        }
    }
}

/// Mark an address as verified in the WorldIDAddressBook by overriding the `addressVerifiedUntil`
/// mapping via storage writes.
///
/// Storage layout (from `WorldIDAddressBook` + OpenZeppelin `Ownable2Step`):
/// - slot 0: `_owner`          (from `Ownable`)
/// - slot 1: `_pendingOwner`   (from `Ownable2Step`)
/// - slot 2: `worldIdRouter`
/// - slot 3: `groupId`
/// - (immutable) `externalNullifierHash` — not stored in a slot
/// - slot 4: `verificationLength`
/// - slot 5: `maxProofTime`
/// - slot 6: `nullifierHashes` mapping
/// - slot 7: `addressVerifiedUntil` mapping
pub async fn set_address_verified_until_for_account<P>(
    provider: &P,
    account: Address,
    verified_until: U256,
) -> anyhow::Result<()>
where
    P: Provider<Ethereum> + AnvilApi<Ethereum>,
{
    // Compute the storage slot for addressVerifiedUntil[account] where the mapping is at slot 7.
    let mut padded = [0u8; 64];
    // First 32 bytes: left-padded address
    padded[12..32].copy_from_slice(account.as_slice());
    // Second 32 bytes: mapping slot index (slot = 7 for `addressVerifiedUntil`).
    padded[63] = 7u8;
    let slot_hash = keccak256(padded);
    let slot = U256::from_be_bytes(slot_hash.into());

    provider
        .anvil_set_storage_at(address_book_address(), slot, verified_until.into())
        .await?;

    Ok(())
}

// ------------------ Shared Anvil-backed AuthenticatedHttpClient ------------------

/// Mock HTTP client that actually executes the user operation on Anvil and parses receipt logs
#[derive(Clone)]
pub struct AnvilBackedHttpClient<P>
where
    P: Provider<Ethereum> + Clone + Send + Sync + 'static,
{
    pub provider: P,
}

/// Represents a response from 'wa_sponsorUserOperation' rpc method
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

#[async_trait::async_trait]
impl<P> AuthenticatedHttpClient for AnvilBackedHttpClient<P>
where
    P: Provider<Ethereum> + Clone + Send + Sync + 'static,
{
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
                    obj.get(k).and_then(|v| v.as_str()).map(|s| s.to_string())
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
                    paymaster_verification_gas_limit: get_or_zero(
                        "paymasterVerificationGasLimit",
                    ),
                    paymaster_post_op_gas_limit: get_or_zero("paymasterPostOpGasLimit"),
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
                let user_op_hash = params.get(0).and_then(|v| v.as_str()).ok_or(
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
            other => Err(HttpError::Generic {
                error_message: format!("unsupported method {other}"),
            }),
        }
    }
}
