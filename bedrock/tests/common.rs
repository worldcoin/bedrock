use alloy::{
    network::Ethereum,
    node_bindings::AnvilInstance,
    primitives::{address, keccak256, Address, FixedBytes, Log, U256},
    providers::{ext::AnvilApi, Provider},
    sol,
    sol_types::{SolCall, SolEvent, SolValue},
};

use bedrock::{
    primitives::{
        http_client::{AuthenticatedHttpClient, HttpError, HttpHeader, HttpMethod},
        PrimitiveError,
    },
    transaction::{foreign::UnparsedUserOperation, UserOperation, ENTRYPOINT_4337},
};
use serde::Serialize;
use serde_json::json;

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

#[allow(dead_code)] // this is used across integration tests
pub fn setup_anvil() -> AnvilInstance {
    dotenvy::dotenv().ok();
    let rpc_url = std::env::var("WORLDCHAIN_RPC_URL").unwrap_or_else(|_| {
        // Fallback to a public, no-key RPC if available.
        "https://worldchain-mainnet.g.alchemy.com/v2/demo".to_string()
    });

    alloy::node_bindings::Anvil::new().fork(rpc_url).spawn()
}

#[allow(dead_code)] // this is used across integration tests
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
pub fn pack_pair(a: &u128, b: &u128) -> FixedBytes<32> {
    let mut out = [0u8; 32];
    out[..16].copy_from_slice(a.to_be_bytes().as_slice());
    out[16..].copy_from_slice(b.to_be_bytes().as_slice());
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

/// A mock HTTP client that intercepts 4337 RPC calls for testing.
/// - `wa_sponsorUserOperation`: Will mock a response with default gas values and no paymaster.
/// - `eth_sendUserOperation`: Executes the user operation on Anvil via the `EntryPoint` contract
#[derive(Clone)]
pub struct AnvilBackedHttpClient<P>
where
    P: Provider<Ethereum> + Clone + Send + Sync + 'static,
{
    pub provider: P,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SponsorUserOperationResponseLite<'a> {
    paymaster: &'a str,
    paymaster_data: &'a str,
    pre_verification_gas: String,
    verification_gas_limit: String,
    call_gas_limit: String,
    paymaster_verification_gas_limit: String,
    paymaster_post_op_gas_limit: String,
    max_priority_fee_per_gas: String,
    max_fee_per_gas: String,
}

#[async_trait::async_trait]
impl<P> AuthenticatedHttpClient for AnvilBackedHttpClient<P>
where
    P: Provider<Ethereum> + Clone + Send + Sync + 'static,
{
    async fn fetch_from_app_backend(
        &self,
        _url: String,
        method: HttpMethod,
        _headers: Vec<HttpHeader>,
        body: Option<Vec<u8>>,
    ) -> Result<Vec<u8>, HttpError> {
        if method != HttpMethod::Post {
            return Err(HttpError::Generic {
                message: "unsupported method".into(),
            });
        }

        let body = body.ok_or(HttpError::Generic {
            message: "missing body".into(),
        })?;

        let root: serde_json::Value =
            serde_json::from_slice(&body).map_err(|_| HttpError::Generic {
                message: "invalid json".into(),
            })?;

        let method =
            root.get("method")
                .and_then(|m| m.as_str())
                .ok_or(HttpError::Generic {
                    message: "invalid json".into(),
                })?;
        let id = root.get("id").cloned().unwrap_or(serde_json::Value::Null);
        let params = root
            .get("params")
            .cloned()
            .unwrap_or(serde_json::Value::Null);

        match method {
            // Intercept sponsor request and return minimal gas values with no paymaster
            "wa_sponsorUserOperation" => {
                let result = SponsorUserOperationResponseLite {
                    paymaster: "0x0000000000000000000000000000000000000000",
                    paymaster_data: "0x",
                    pre_verification_gas: "0x20000".into(),
                    verification_gas_limit: "0x20000".into(),
                    call_gas_limit: "0x20000".into(),
                    paymaster_verification_gas_limit: "0x0".into(),
                    paymaster_post_op_gas_limit: "0x0".into(),
                    max_priority_fee_per_gas: "0x3B9ACA00".into(), // 1 gwei
                    max_fee_per_gas: "0x3B9ACA00".into(),          // 1 gwei
                };

                let response = json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "result": result,
                });

                Ok(serde_json::to_vec(&response).unwrap())
            }
            // Execute the user operation on Anvil
            "eth_sendUserOperation" => {
                let params = params.as_array().ok_or(HttpError::Generic {
                    message: "invalid params".into(),
                })?;
                let user_op_val = params.first().ok_or(HttpError::Generic {
                    message: "missing userOp param".into(),
                })?;
                let _entry_point_str = params.get(1).and_then(|v| v.as_str()).ok_or(
                    HttpError::Generic {
                        message: "missing entryPoint param".into(),
                    },
                )?;

                // Build UnparsedUserOperation from JSON (which uses hex strings), then convert
                let obj = user_op_val.as_object().ok_or(HttpError::Generic {
                    message: "userOp param must be an object".into(),
                })?;

                let get_opt = |k: &str| -> Option<String> {
                    obj.get(k).and_then(|v| v.as_str()).map(|s| s.to_string())
                };
                let get_or_zero = |k: &str| -> String {
                    get_opt(k).unwrap_or_else(|| "0x0".to_string())
                };
                let get_required = |k: &str| -> Result<String, HttpError> {
                    get_opt(k).ok_or(HttpError::Generic {
                        message: format!("missing or invalid {k}"),
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

                let parsed_op: UserOperation =
                    unparsed.try_into().map_err(|e| HttpError::Generic {
                        message: format!("invalid userOp: {e}"),
                    })?;

                // Execute on Anvil via EntryPoint
                let entry_point_contract =
                    IEntryPoint::new(*ENTRYPOINT_4337, &self.provider);
                let packed_op =
                    PackedUserOperation::try_from(&parsed_op).map_err(|e| {
                        HttpError::Generic {
                            message: format!("failed to pack user operation: {e}"),
                        }
                    })?;
                let handle_ops = entry_point_contract
                    .handleOps(vec![packed_op], parsed_op.sender)
                    .gas(5_000_000)
                    .send()
                    .await
                    .map_err(|e| HttpError::Generic {
                        message: format!("failed to execute user operation: {e}"),
                    })?;

                let _receipt =
                    handle_ops
                        .get_receipt()
                        .await
                        .map_err(|e| HttpError::Generic {
                            message: format!("failed to get receipt: {e}"),
                        })?;

                // Create a user operation hash
                let user_op_hash = keccak256(parsed_op.abi_encode());

                let response = json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "result": format!("0x{}", hex::encode(user_op_hash)),
                });

                Ok(serde_json::to_vec(&response).unwrap())
            }
            _ => Err(HttpError::Generic {
                message: format!("unsupported method: {method}"),
            }),
        }
    }
}
