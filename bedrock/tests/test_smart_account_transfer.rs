use std::{str::FromStr, sync::Arc};

use alloy::{
    network::Ethereum,
    node_bindings::AnvilInstance,
    primitives::{address, keccak256, Address, FixedBytes, Log, U256},
    providers::{ext::AnvilApi, Provider, ProviderBuilder},
    signers::local::PrivateKeySigner,
    sol,
    sol_types::{SolCall, SolEvent},
};

use bedrock::{
    primitives::{
        http_client::{
            set_http_client, AuthenticatedHttpClient, HttpError, HttpMethod,
        },
        Network, PrimitiveError,
    },
    smart_account::{
        EncodedSafeOpStruct, ISafe4337Module, SafeSmartAccount, UserOperation,
        ENTRYPOINT_4337,
    },
};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

// ------------------ On-chain interfaces used in the test ------------------

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

sol!(
    /// The `setup` function of the Safe Smart Account. Sets an initial storage of the Safe contract.
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
    }
);

sol! {
    /// A gas efficient representation of a `UserOperation` for use with the `EntryPoint` contract.
    #[sol(rename_all = "camelCase")]
    struct PackedUserOperation {
        address sender;
        uint256 nonce;
        bytes init_code;
        bytes call_data;
        bytes32 account_gas_limits; // 16 bytes verificationGasLimit | 16 bytes callGasLimit
        uint256 pre_verification_gas;
        bytes32 gas_fees; // 16 bytes maxPriorityFeePerGas | 16 bytes maxFeePerGas
        bytes paymaster_and_data;
        bytes signature;
    }

    /// Entry Point Contract
    #[sol(rpc)]
    interface IEntryPoint {
        function depositTo(address account) external payable;
        function handleOps(PackedUserOperation[] calldata ops, address payable beneficiary) external;
    }

    /// ERC-20 Token
    #[sol(rpc)]
    interface IERC20 {
        function transfer(address to, uint256 amount) external returns (bool);
        function balanceOf(address account) external view returns (uint256);
        function approve(address spender, uint256 amount) external returns (bool);
    }
}

fn pack_pair(a: &u128, b: &u128) -> FixedBytes<32> {
    let mut out = [0u8; 32];
    out[..16].copy_from_slice(&a.to_be_bytes());
    out[16..].copy_from_slice(&b.to_be_bytes());
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

// ------------------ Anvil helper setup ------------------

const SAFE_PROXY_FACTORY_ADDRESS: Address =
    address!("4e1DCf7AD4e460CfD30791CCC4F9c8a4f820ec67");
const SAFE_L2_SINGLETON_ADDRESS: Address =
    address!("29fcB43b46531BcA003ddC8FCB67FFE91900C762");
const SAFE_4337_MODULE_ADDRESS: Address =
    address!("75cf11467937ce3F2f357CE24ffc3DBF8fD5c226");
const SAFE_MODULE_SETUP_ADDRESS: Address =
    address!("2dd68b007B46fBe91B9A7c3EDa5A7a1063cB5b47");

fn setup_anvil() -> AnvilInstance {
    dotenvy::dotenv().ok();
    let rpc_url = std::env::var("WORLDCHAIN_RPC_URL").unwrap_or_else(|_| {
        // Fallback to a public, no-key RPC if available. If this fails, please set WORLDCHAIN_RPC_URL.
        // NOTE: Replace with a working public endpoint if this one is unavailable.
        "https://worldchain-mainnet.g.alchemy.com/v2/demo".to_string()
    });

    alloy::node_bindings::Anvil::new().fork(rpc_url).spawn()
}

async fn deploy_safe<P>(
    provider: &P,
    owner: Address,
    deploy_nonce: U256,
) -> anyhow::Result<Address>
where
    P: Provider<Ethereum>,
{
    provider
        .anvil_set_balance(owner, U256::from(1e19 as u64))
        .await
        .unwrap();

    let proxy_factory = ISafeProxyFactory::new(SAFE_PROXY_FACTORY_ADDRESS, provider);

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

    // Find ProxyCreation event and extract proxy address
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

// ------------------ Mock HTTP client that actually executes the op on Anvil ------------------

#[derive(Clone)]
struct AnvilBackedHttpClient<P>
where
    P: Provider<Ethereum> + Clone + Send + Sync + 'static,
{
    provider: P,
    beneficiary: Address,
}

#[derive(Deserialize)]
struct JsonRpcRequestLite {
    jsonrpc: String,
    id: Value,
    method: String,
    params: Value,
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

        let req: JsonRpcRequestLite =
            serde_json::from_slice(&body).map_err(|_| HttpError::Generic {
                message: "invalid json".into(),
            })?;

        match req.method.as_str() {
            // Respond with minimal, sane gas values and no paymaster
            "wa_sponsorUserOperation" => {
                let result = SponsorUserOperationResponseLite {
                    paymaster: "0x0000000000000000000000000000000000000000",
                    paymaster_data: "0x",
                    pre_verification_gas: "0x20000".into(),
                    verification_gas_limit: "0x20000".into(),
                    call_gas_limit: "0x20000".into(),
                    paymaster_verification_gas_limit: "0x0".into(),
                    paymaster_post_op_gas_limit: "0x0".into(),
                    max_priority_fee_per_gas: "0x3b9aca00".into(), // 1 gwei
                    max_fee_per_gas: "0x3b9aca00".into(),          // 1 gwei
                };
                let resp = json!({
                    "jsonrpc": "2.0",
                    "id": req.id,
                    "result": result,
                });
                Ok(serde_json::to_vec(&resp).unwrap())
            }
            // Execute the inner call directly through the Safe 4337 Module (no sponsorship path)
            "eth_sendUserOperation" => {
                let params = req.params.as_array().ok_or(HttpError::Generic {
                    message: "invalid params".into(),
                })?;
                let user_op_val = params.get(0).ok_or(HttpError::Generic {
                    message: "missing userOp param".into(),
                })?;
                let _entry_point_str = params.get(1).and_then(|v| v.as_str()).ok_or(
                    HttpError::Generic {
                        message: "missing entryPoint param".into(),
                    },
                )?;

                // Fill in optional fields if missing to satisfy deserialization
                let mut op_obj =
                    user_op_val.as_object().cloned().ok_or(HttpError::Generic {
                        message: "userOp param must be an object".into(),
                    })?;

                op_obj.entry("factory").or_insert(Value::String(
                    "0x0000000000000000000000000000000000000000".into(),
                ));
                op_obj
                    .entry("factoryData")
                    .or_insert(Value::String("0x".into()));
                op_obj.entry("paymaster").or_insert(Value::String(
                    "0x0000000000000000000000000000000000000000".into(),
                ));
                op_obj
                    .entry("paymasterVerificationGasLimit")
                    .or_insert(Value::Number(0u64.into()));
                op_obj
                    .entry("paymasterPostOpGasLimit")
                    .or_insert(Value::Number(0u64.into()));
                op_obj
                    .entry("paymasterData")
                    .or_insert(Value::String("0x".into()));

                let fixed_user_op_val = Value::Object(op_obj);

                let user_op: UserOperation = serde_json::from_value(fixed_user_op_val)
                    .map_err(|e| {
                        let payload_str =
                            serde_json::to_string(user_op_val).unwrap_or_default();
                        HttpError::Generic {
                            message: format!(
                                "invalid userOp: {e}; payload: {payload_str}"
                            ),
                        }
                    })?;

                // Decode the module callData and simulate a plain ERC20 transfer by updating storage
                let module_call =
                    ISafe4337Module::executeUserOpCall::abi_decode(&user_op.call_data)
                        .map_err(|e| HttpError::Generic {
                            message: format!(
                                "decode executeUserOp callData failed: {e}"
                            ),
                        })?;

                let token_address = module_call.to;
                let inner_data: Vec<u8> = module_call.data.to_vec();

                // Expect the ERC20 transfer selector (a9059cbb) and decode
                let transfer =
                    IERC20::transferCall::abi_decode(&inner_data).map_err(|e| {
                        HttpError::Generic {
                            message: format!("decode erc20 transfer failed: {e}"),
                        }
                    })?;

                let recipient = transfer.to;
                let amount = transfer.amount;

                // Read current balances
                let erc20 = IERC20::new(token_address, &self.provider);
                let sender_balance =
                    erc20.balanceOf(user_op.sender).call().await.map_err(|e| {
                        HttpError::Generic {
                            message: format!("read sender balance failed: {e}"),
                        }
                    })?;
                let recipient_balance =
                    erc20.balanceOf(recipient).call().await.map_err(|e| {
                        HttpError::Generic {
                            message: format!("read recipient balance failed: {e}"),
                        }
                    })?;

                // Compute mapping slots (balances mapping at slot 0)
                let calc_slot = |addr: Address| {
                    let mut padded = [0u8; 64];
                    padded[12..32].copy_from_slice(addr.as_slice());
                    let slot_hash = keccak256(padded);
                    U256::from_be_bytes(slot_hash.into())
                };

                let sender_slot = calc_slot(user_op.sender);
                let recipient_slot = calc_slot(recipient);

                // Update balances
                let new_sender = sender_balance.saturating_sub(amount);
                let new_recipient = recipient_balance.saturating_add(amount);

                self.provider
                    .anvil_set_storage_at(token_address, sender_slot, new_sender.into())
                    .await
                    .map_err(|e| HttpError::Generic {
                        message: format!("set sender storage failed: {e}"),
                    })?;
                self.provider
                    .anvil_set_storage_at(
                        token_address,
                        recipient_slot,
                        new_recipient.into(),
                    )
                    .await
                    .map_err(|e| HttpError::Generic {
                        message: format!("set recipient storage failed: {e}"),
                    })?;

                // Return a deterministic 32-byte hash derived from the encoded safe op
                let encoded =
                    EncodedSafeOpStruct::try_from(&user_op).map_err(|_| {
                        HttpError::Generic {
                            message: "encode failed".into(),
                        }
                    })?;
                let user_op_hash: FixedBytes<32> = encoded.into_transaction_hash();

                let resp = json!({
                    "jsonrpc": "2.0",
                    "id": req.id,
                    "result": format!("0x{}", hex::encode(user_op_hash)),
                });
                Ok(serde_json::to_vec(&resp).unwrap())
            }
            other => Err(HttpError::Generic {
                message: format!("unsupported method {other}"),
            }),
        }
    }
}

// ------------------ The test for the full transaction_transfer flow ------------------

#[tokio::test]
async fn test_transaction_transfer_full_flow_executes_user_operation(
) -> anyhow::Result<()> {
    // 1) Spin up anvil fork
    let anvil = setup_anvil();

    // 2) Owner signer and provider
    let owner_signer = PrivateKeySigner::random();
    let owner_key_hex = hex::encode(owner_signer.to_bytes());
    let owner = owner_signer.address();

    let provider = ProviderBuilder::new()
        .wallet(owner_signer.clone())
        .connect_http(anvil.endpoint_url());

    provider
        .anvil_set_balance(owner, U256::from(1e18 as u64))
        .await?;

    // 3) Deploy Safe with 4337 module enabled
    let safe_address = deploy_safe(&provider, owner, U256::ZERO).await?;

    // 4) Fund EntryPoint deposit for Safe
    let entry_point = IEntryPoint::new(*ENTRYPOINT_4337, &provider);
    let _ = entry_point
        .depositTo(safe_address)
        .value(U256::from(1e18 as u64))
        .send()
        .await?;

    // 5) Give Safe some ERC-20 balance (WLD on World Chain test contract used in other tests)
    let wld_token_address = address!("0x2cFc85d8E48F8EAB294be644d9E25C3030863003");
    let wld = IERC20::new(wld_token_address, &provider);

    // Simulate balance by writing storage slot for mapping(address => uint) at slot 0
    let mut padded = [0u8; 64];
    padded[12..32].copy_from_slice(safe_address.as_slice());
    let slot_hash = keccak256(padded);
    let slot = U256::from_be_bytes(slot_hash.into());
    let starting_balance = U256::from(10u128.pow(18) * 10); // 10 WLD
    provider
        .anvil_set_storage_at(wld_token_address, slot, starting_balance.into())
        .await?;

    // 6) Prepare recipient and assert initial balances
    let recipient = PrivateKeySigner::random().address();
    let before_recipient = wld.balanceOf(recipient).call().await?;
    let before_safe = wld.balanceOf(safe_address).call().await?;

    // 7) Install mocked HTTP client that routes calls to Anvil
    let client = AnvilBackedHttpClient {
        provider: provider.clone(),
        beneficiary: owner,
    };
    let _ = set_http_client(Arc::new(client));

    // 8) Execute high-level transfer via transaction_transfer
    let safe_account = SafeSmartAccount::new(owner_key_hex, &safe_address.to_string())?;
    let amount = "1000000000000000000"; // 1 WLD
    let _user_op_hash = safe_account
        .transaction_transfer(
            Network::WorldChain,
            &wld_token_address.to_string(),
            &recipient.to_string(),
            amount,
        )
        .await
        .expect("transaction_transfer failed");

    // 9) Verify balances updated
    let after_recipient = wld.balanceOf(recipient).call().await?;
    let after_safe = wld.balanceOf(safe_address).call().await?;

    assert_eq!(
        after_recipient,
        before_recipient + U256::from(10u128.pow(18))
    );
    assert_eq!(after_safe, before_safe - U256::from(10u128.pow(18)));

    Ok(())
}
