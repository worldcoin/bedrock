use alloy::{
    dyn_abi::TypedData,
    network::Ethereum,
    node_bindings::AnvilInstance,
    primitives::{address, keccak256, Address, Bytes, FixedBytes, U256},
    providers::{ext::AnvilApi, Provider, ProviderBuilder},
    signers::local::PrivateKeySigner,
    sol,
    sol_types::{SolCall, SolEvent},
};
use bedrock::{
    primitives::{Network, PrimitiveError},
    smart_account::{
        EncodedSafeOpStruct, SafeOperation, SafeSmartAccount, SafeSmartAccountSigner,
        SafeTransaction, UnparsedPermitTransferFrom, UnparsedTokenPermissions,
        UserOperation, ENTRYPOINT_4337, GNOSIS_SAFE_4337_MODULE, PERMIT2_ADDRESS,
    },
    transaction::foreign::UnparsedUserOperation,
};
use chrono::Utc;
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

sol!(
    /// The `setup` function of the Safe Smart Account. Sets an initial storage of the Safe contract.
    ///
    /// Reference: <https://github.com/safe-global/safe-smart-account/blob/v1.4.1/contracts/Safe.sol#L95>
    #[allow(clippy::too_many_arguments)] // this is how the function is defined in the Safe contract
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

        /// Verifies a signature is valid for a digest message following EIP-1271.
        /// Reference: <https://github.com/safe-global/safe-smart-account/blob/v1.4.1/contracts/handler/CompatibilityFallbackHandler.sol#L73>
        function isValidSignature(bytes32 dataHash, bytes memory signature) external view returns (bytes4);


        /// Executes a transaction.
        /// Reference: <https://github.com/safe-global/safe-smart-account/blob/v1.4.1/contracts/Safe.sol#L115>
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
        ) external payable override returns (bool success);
    }
);

sol! {
    /// A gas efficient representation of a `UserOperation` for use with the `EntryPoint` contract.
    ///
    /// Submitting transactions through the `EntryPoint` requires a `PackedUserOperation`,
    /// see `handleOps` in the `EntryPoint` contract. Reference: <https://github.com/eth-infinitism/account-abstraction/blob/v0.7.0/contracts/core/EntryPoint.sol#L174>
    ///
    ///
    /// Reference: <https://github.com/eth-infinitism/account-abstraction/blob/v0.7.0/contracts/interfaces/PackedUserOperation.sol#L18>
    #[sol(rename_all = "camelCase")]
    struct PackedUserOperation {
        /// The address of the smart contract account to be called.
        address sender;
        /// Anti-replay nonce for the userOp.
        uint256 nonce;
        /// Optional initialization code for deploying the account if it doesn't exist.
        bytes init_code;
        /// Calldata for the actual execution to be performed by the account.
        bytes call_data;
        /// Packed gas limits: first 16 bytes = `verificationGasLimit`, next 16 bytes = `callGasLimit`.
        bytes32 account_gas_limits;
        /// The fixed gas to be paid before the verification step (covers calldata costs, etc.).
        uint256 pre_verification_gas;
        /// Packed fee fields: first 16 bytes = `maxPriorityFeePerGas`, next 16 bytes = `maxFeePerGas`.
        bytes32 gas_fees;
        /// Data and address for an optional paymaster sponsoring the transaction.
        bytes paymaster_and_data;
        /// Signature over the operation (account-specific validation logic).
        bytes signature;
    }

    /// Entry Point Contract
    #[sol(rpc)]
    interface IEntryPoint {
        function depositTo(address account) external payable;
        function handleOps(PackedUserOperation[] calldata ops, address payable beneficiary) external;
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

    /// ERC-20 Token
    #[sol(rpc)]
    interface IERC20 {
        function transfer(address to, uint256 amount) external returns (bool);
        function balanceOf(address account) external view returns (uint256);
        function approve(address spender, uint256 amount) external returns (bool);
    }
}

/// Pack two U128 in 32 bytes
fn pack_pair(a: &u128, b: &u128) -> FixedBytes<32> {
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

// Safe contract addresses on Worldchain
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
    let rpc_url = std::env::var("WORLDCHAIN_RPC_URL")
        .expect("WORLDCHAIN_RPC_URL not set. Copy .env.example to .env and add your Alchemy API key");

    println!("Starting Anvil for Safe integration test...");
    let anvil = alloy::node_bindings::Anvil::new().fork(rpc_url).spawn();
    println!("✓ Anvil started at: {}", anvil.endpoint());
    anvil
}

async fn deploy_safe<P>(
    provider: &P,
    owner: Address,
    deploy_nonce: U256,
) -> anyhow::Result<Address>
where
    P: Provider<Ethereum>,
{
    // Fund the owner to be able to execute transactions
    provider
        .anvil_set_balance(owner, U256::from(1e19))
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
    println!("\nDeploying Safe-{deploy_nonce}");
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
            let raw_log = alloy::primitives::Log {
                address: log.address(),
                data: log.data().clone(),
            };
            ISafeProxyFactory::ProxyCreation::decode_log(&raw_log).ok()
        })
        .expect("ProxyCreation event not found");

    let safe_address = proxy_creation_event.proxy;

    Ok(safe_address)
}

#[tokio::test]
async fn test_integration_personal_sign() {
    let anvil = setup_anvil();
    let owner_signer = PrivateKeySigner::random();

    let owner_key_hex = hex::encode(owner_signer.to_bytes());

    let owner = owner_signer.address();

    let provider = ProviderBuilder::new()
        .wallet(owner_signer)
        .connect_http(anvil.endpoint_url());

    provider
        .anvil_set_balance(owner, U256::from(1e18))
        .await
        .expect("Failed to set balance");

    println!("✓ Using owner address: {owner}");

    // Deploy a Safe
    let safe_address = deploy_safe(&provider, owner, U256::ZERO)
        .await
        .expect("Failed to deploy Safe");

    let safe_contract = ISafe::new(safe_address, &provider);

    let message = "Hello from Safe integration test!";
    let chain_id = Network::WorldChain as u32;

    let safe_account = SafeSmartAccount::new(owner_key_hex, &safe_address.to_string())
        .expect("Failed to create SafeSmartAccount");

    let signature = safe_account
        .personal_sign(chain_id, message.to_string())
        .expect("Failed to sign message");

    println!("✓ Message signed successfully");
    println!("  Message:   '{message}'");
    println!("  Signature: {signature}");

    let signature = signature.as_str();

    assert_eq!(signature.len(), 132, "Invalid signature length");
    assert!(
        signature.starts_with("0x"),
        "Signature should start with 0x"
    );

    let sig_bytes = hex::decode(&signature[2..]).expect("Failed to decode signature");
    assert_eq!(sig_bytes.len(), 65, "Signature should be 65 bytes");

    let message_hash = keccak256(
        format!("\x19Ethereum Signed Message:\n{}{}", message.len(), message)
            .as_bytes(),
    );

    println!("Message hash: 0x{}", hex::encode(message_hash));
    println!("Signature bytes: 0x{}", hex::encode(&sig_bytes));

    let is_valid_result = safe_contract
        .isValidSignature(message_hash, Bytes::from(sig_bytes))
        .call()
        .await
        .expect("Failed to call isValidSignature");

    const EIP1271_MAGIC_VALUE: [u8; 4] = [0x16, 0x26, 0xba, 0x7e];
    let expected_signature =
        alloy::primitives::FixedBytes::<4>::from(EIP1271_MAGIC_VALUE);

    println!(
        "✓ On-chain signature verification result: 0x{}",
        hex::encode(is_valid_result)
    );
    assert_eq!(
        is_valid_result, expected_signature,
        "Signature verification failed on-chain"
    );

    println!("✓ Signature validation passed");
    println!("✓ Safe integration test completed successfully!");
}

/// Ensures signature verification fails if the message wasn't signed for the correct chain
#[tokio::test]
async fn test_integration_personal_sign_failure_on_incorrect_chain_id() {
    let anvil = setup_anvil();
    let owner_signer = PrivateKeySigner::random();

    let owner_key_hex = hex::encode(owner_signer.to_bytes());

    let owner = owner_signer.address();

    let provider = ProviderBuilder::new()
        .wallet(owner_signer)
        .connect_http(anvil.endpoint_url());

    provider
        .anvil_set_balance(owner, U256::from(1e18))
        .await
        .unwrap();

    let safe_address = deploy_safe(&provider, owner, U256::ZERO)
        .await
        .expect("Failed to deploy Safe");

    let safe_contract = ISafe::new(safe_address, &provider);

    let message = "Hello from Safe integration test!";
    let chain_id = 10; // Note: This is not World Chain, verification will fail

    let safe_account = SafeSmartAccount::new(owner_key_hex, &safe_address.to_string())
        .expect("Failed to create SafeSmartAccount");

    let signature = safe_account
        .personal_sign(chain_id, message.to_string())
        .expect("Failed to sign message")
        .to_hex_string();

    let sig_bytes = hex::decode(&signature[2..]).expect("Failed to decode signature");

    let message_hash = keccak256(
        format!("\x19Ethereum Signed Message:\n{}{}", message.len(), message)
            .as_bytes(),
    );

    let is_valid_result = safe_contract
        .isValidSignature(message_hash, Bytes::from(sig_bytes))
        .call()
        .await
        .unwrap_err();

    match is_valid_result {
        alloy::contract::Error::TransportError(e) => {
            // https://github.com/safe-global/safe-smart-account/blob/v1.4.1/docs/error_codes.md?plain=1#L21
            assert_eq!(
                e.as_error_resp().unwrap().message,
                "execution reverted: GS026"
            );
        }
        _ => panic!("Expected TransportError error, got {is_valid_result:?}"),
    }
}

/// Ensures signature verification fails if the message wasn't signed for the correct EIP-191 prefix
#[tokio::test]
async fn test_integration_personal_sign_failure_on_incorrect_eip_191_prefix() {
    let anvil = setup_anvil();
    let owner_signer = PrivateKeySigner::random();

    let owner_key_hex = hex::encode(owner_signer.to_bytes());

    let owner = owner_signer.address();

    let provider = ProviderBuilder::new()
        .wallet(owner_signer)
        .connect_http(anvil.endpoint_url());

    provider
        .anvil_set_balance(owner, U256::from(1e18))
        .await
        .expect("Failed to set balance");

    let safe_address = deploy_safe(&provider, owner, U256::ZERO)
        .await
        .expect("Failed to deploy Safe");

    let safe_contract = ISafe::new(safe_address, &provider);

    let message = "Hello from Safe integration test!";
    let chain_id = Network::WorldChain as u32;

    let safe_account = SafeSmartAccount::new(owner_key_hex, &safe_address.to_string())
        .expect("Failed to create SafeSmartAccount");

    let signature = safe_account
        .personal_sign(chain_id, message.to_string())
        .expect("Failed to sign message")
        .to_hex_string();

    let sig_bytes = hex::decode(&signature[2..]).expect("Failed to decode signature");

    // Note the omission of the EIP-191 prefix
    let message_hash = keccak256(message.as_bytes());

    let is_valid_result = safe_contract
        .isValidSignature(message_hash, Bytes::from(sig_bytes))
        .call()
        .await
        .unwrap_err();

    match is_valid_result {
        alloy::contract::Error::TransportError(e) => {
            // https://github.com/safe-global/safe-smart-account/blob/v1.4.1/docs/error_codes.md?plain=1#L21
            assert_eq!(
                e.as_error_resp().unwrap().message,
                "execution reverted: GS026"
            );
        }
        _ => panic!("Expected TransportError error, got {is_valid_result:?}"),
    }
}

/// Integration test for the encoding, signing and execution of a 4337 transaction.
///
/// This test deploys two Safe Smart Accounts, and transfers 1 ETH from Safe 1 to Safe 2 using a 4337 transaction.
#[tokio::test]
async fn test_integration_erc4337_transaction_execution() -> anyhow::Result<()> {
    let anvil = setup_anvil();
    let owner_signer = PrivateKeySigner::random();

    let owner_key_hex = hex::encode(owner_signer.to_bytes());

    let owner = owner_signer.address();
    println!("✓ Using owner address: {owner}");

    let provider = ProviderBuilder::new()
        .wallet(owner_signer.clone())
        .connect_http(anvil.endpoint_url());

    // Deploy Safes
    let safe_address = deploy_safe(&provider, owner, U256::ZERO).await?;
    let safe_address2 = deploy_safe(&provider, owner, U256::from(1)).await?;

    // Fund the Safe, to be able to test the balance transfer
    provider
        .anvil_set_balance(safe_address, U256::from(1e18))
        .await
        .unwrap();

    let before_balance = provider.get_balance(safe_address2).await?;

    // Fund EntryPoint deposit for the Safe
    let entry_point = IEntryPoint::new(*ENTRYPOINT_4337, &provider);
    let _ = entry_point
        .depositTo(safe_address)
        .value(U256::from(1e18))
        .send()
        .await?;

    // Transfer 1 ETH from Safe 1 to Safe 2
    let eth_amount = U256::from(1e18);
    let call_data = ISafe4337Module::executeUserOpCall {
        to: safe_address2,
        value: eth_amount,
        data: Bytes::new(),
        operation: 0, // CALL
    }
    .abi_encode();

    // Build the userOp
    let valid_after = &0u64.to_be_bytes()[2..]; // validAfter = 0  (immediately valid)
    let valid_until = &u64::MAX.to_be_bytes()[2..]; // validUntil = 0xFFFF_FFFF_FFFF (≈ forever)
    let user_op = UnparsedUserOperation {
        sender: safe_address.to_string(),
        nonce: "0x0".to_string(),
        call_data: format!("0x{}", hex::encode(&call_data)),
        call_gas_limit: "0x20000".to_string(),
        verification_gas_limit: "0x20000".to_string(),
        pre_verification_gas: "0x20000".to_string(),
        max_fee_per_gas: "0x3b9aca00".to_string(), // 1 gwei
        max_priority_fee_per_gas: "0x3b9aca00".to_string(), // 1 gwei
        paymaster: None,
        paymaster_verification_gas_limit: "0x0".to_string(),
        paymaster_post_op_gas_limit: "0x0".to_string(),
        paymaster_data: None,
        signature: {
            let mut buf = Vec::with_capacity(77);
            buf.extend_from_slice(valid_after);
            buf.extend_from_slice(valid_until);
            buf.extend_from_slice(&[0u8; 65]);
            format!("0x{}", hex::encode(&buf))
        },
        factory: None,
        factory_data: None,
    };

    let mut user_op: UserOperation = user_op.try_into().unwrap();

    // Sign the userOp and prepend validity timestamps
    let safe_account = SafeSmartAccount::new(owner_key_hex, &safe_address.to_string())
        .expect("Failed to create SafeSmartAccount");
    let op_hash = EncodedSafeOpStruct::try_from(&user_op)?.into_transaction_hash();

    let worldchain_chain_id = Network::WorldChain as u32;
    let sig = safe_account
        .sign_digest(op_hash, worldchain_chain_id, Some(*GNOSIS_SAFE_4337_MODULE))?
        .as_bytes();
    let mut sig_with_timestamps = Vec::with_capacity(77);
    sig_with_timestamps.extend_from_slice(valid_after);
    sig_with_timestamps.extend_from_slice(valid_until);
    sig_with_timestamps.extend_from_slice(&sig);
    user_op.signature = sig_with_timestamps.into();

    // Submit through the 4337 EntryPoint
    let _ = entry_point
        .handleOps(vec![PackedUserOperation::try_from(&user_op)?], owner)
        .from(owner)
        .send()
        .await?;

    // Assert the transfer has succeeded
    let after_balance = provider.get_balance(safe_address2).await?;
    assert_eq!(
        after_balance,
        before_balance + U256::from(1e18),
        "Native ETH transfer did not succeed"
    );
    Ok(())
}

#[tokio::test]
async fn test_integration_sign_typed_data() {
    let anvil = setup_anvil();
    let owner_signer = PrivateKeySigner::random();

    let owner_key_hex = hex::encode(owner_signer.to_bytes());

    let owner = owner_signer.address();

    let provider = ProviderBuilder::new()
        .wallet(owner_signer)
        .connect_http(anvil.endpoint_url());

    provider
        .anvil_set_balance(owner, U256::from(10).pow(U256::from(18)))
        .await
        .expect("Failed to set balance");

    println!("✓ Using owner address: {owner}");

    // Deploy a Safe
    let safe_address = deploy_safe(&provider, owner, U256::ZERO)
        .await
        .expect("Failed to deploy Safe");

    let safe_contract = ISafe::new(safe_address, &provider);

    // Example from specs: https://eips.ethereum.org/EIPS/eip-712#specification-of-the-eth_signtypeddata-json-rpc
    let typed_data = json!({
         "types":{
            "EIP712Domain":[
               {
                  "name":"name",
                  "type":"string"
               },
               {
                  "name":"version",
                  "type":"string"
               },
               {
                  "name":"chainId",
                  "type":"uint256"
               },
               {
                  "name":"verifyingContract",
                  "type":"address"
               }
            ],
            "Person":[
               {
                  "name":"name",
                  "type":"string"
               },
               {
                  "name":"wallet",
                  "type":"address"
               }
            ],
            "Mail":[
               {
                  "name":"from",
                  "type":"Person"
               },
               {
                  "name":"to",
                  "type":"Person"
               },
               {
                  "name":"contents",
                  "type":"string"
               }
            ]
         },
         "primaryType":"Mail",
         "domain":{
            "name":"Ether Mail",
            "version":"1",
            "chainId":1,
            "verifyingContract":"0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC"
         },
         "message":{
            "from":{
               "name":"Cow",
               "wallet":"0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826"
            },
            "to":{
               "name":"Bob",
               "wallet":"0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB"
            },
            "contents":"Hello, Bob!"
         }
    });

    let chain_id = Network::WorldChain as u32;

    let safe_account = SafeSmartAccount::new(owner_key_hex, &safe_address.to_string())
        .expect("Failed to create SafeSmartAccount");

    let signature = safe_account
        .sign_typed_data(chain_id, &typed_data.to_string())
        .expect("Failed to sign message");

    let signature = signature.as_str();

    assert_eq!(signature.len(), 132, "Invalid signature length");
    assert!(
        signature.starts_with("0x"),
        "Signature should start with 0x"
    );

    let sig_bytes = hex::decode(&signature[2..]).expect("Failed to decode signature");
    assert_eq!(sig_bytes.len(), 65, "Signature should be 65 bytes");

    let message: TypedData = serde_json::from_str(&typed_data.to_string())
        .expect("Failed to parse typed data");
    let message_hash = message
        .eip712_signing_hash()
        .expect("Failed to calculate EIP-712 signing hash");

    let is_valid_result = safe_contract
        .isValidSignature(message_hash, Bytes::from(sig_bytes))
        .call()
        .await
        .expect("Failed to call isValidSignature");

    const EIP1271_MAGIC_VALUE: [u8; 4] = [0x16, 0x26, 0xba, 0x7e];
    let expected_signature =
        alloy::primitives::FixedBytes::<4>::from(EIP1271_MAGIC_VALUE);

    assert_eq!(
        is_valid_result, expected_signature,
        "Signature verification failed on-chain"
    );

    println!("✓ Signature validation for EIP-712 typed data passed");
}

sol!(
    // NOTE: This is defined in the `permit2` module, but it cannot be easily re-used here.
    struct TokenPermissions {
        address token;
        uint256 amount;
    }

    /// The signed permit message for a single token transfer.
    struct PermitTransferFrom {
        TokenPermissions permitted;
        uint256 nonce;
        uint256 deadline;
    }

    /// Transfer details for permitTransferFrom
    struct SignatureTransferDetails {
        address to;
        uint256 requestedAmount;
    }

    /// Reference: <https://github.com/Uniswap/permit2/blob/cc56ad0f3439c502c246fc5cfcc3db92bb8b7219/src/interfaces/ISignatureTransfer.sol#L9>
    #[sol(rpc)]
    interface ISignatureTransfer {
        function permitTransferFrom(
            PermitTransferFrom memory permit,
            SignatureTransferDetails calldata transferDetails,
            address owner,
            bytes calldata signature
        ) external;
    }
);

/// This integration test encompasses multiple key functionality of the `SafeSmartAccount`.
/// In particular it tests both `sign_transaction` & `sign_permit2_transfer`.
///
/// The high level flow is as follows:
/// 1. General set-up
/// 2. Deploy a Safe (World App User)
/// 3. Give the Safe some simulated WLD balance
/// 4. Approve the Permit2 contract to transfer WLD tokens from the Safe on the ERC-20 WLD contract (this tests `sign_transaction` works properly on-chain).
/// 5. Initialize a "Mini App" Wallet which will get approved to transfer WLD tokens on behalf of the user
/// 6. Execute a `permitTransferFrom` call on the Permit2 contract to transfer WLD tokens from the Safe to the Mini App
/// 7. Verify the tokens were transferred
#[tokio::test]
async fn test_integration_permit2_transfer() -> anyhow::Result<()> {
    // Step 1: Initial setup
    let anvil = setup_anvil();
    let owner_signer = PrivateKeySigner::random();
    let owner_key_hex = hex::encode(owner_signer.to_bytes());
    let owner = owner_signer.address();

    let provider = ProviderBuilder::new()
        .wallet(owner_signer.clone())
        .connect_http(anvil.endpoint_url());

    provider.anvil_set_balance(owner, U256::from(1e18)).await?;

    // Step 2: Deploy a Safe (World App User)
    let safe_address = deploy_safe(&provider, owner, U256::ZERO).await?;
    let chain_id = Network::WorldChain as u32;
    let safe_account = SafeSmartAccount::new(owner_key_hex, &safe_address.to_string())?;

    // Step 3: Give the Safe some simulated WLD balance
    let wld_token_address = address!("0x2cFc85d8E48F8EAB294be644d9E25C3030863003");
    let wld_contract = IERC20::new(wld_token_address, &provider);

    // the simulated balance is provided by updating the storage slot of the contract
    let mut padded = [0u8; 64];
    padded[12..32].copy_from_slice(safe_address.as_slice());
    let slot_hash = keccak256(padded);
    let slot = U256::from_be_bytes(slot_hash.into());
    let balance = U256::from(10e18); // 10 WLD

    provider
        .anvil_set_storage_at(wld_token_address, slot, balance.into())
        .await?;

    assert_eq!(wld_contract.balanceOf(safe_address).call().await?, balance,);

    // Step 4: Approve the Permit2 contract to transfer WLD tokens from the Safe
    // This uses the `sign_transaction` method to approve the Permit2 contract to transfer WLD tokens from the Safe on the ERC-20 WLD contract.
    let calldata = IERC20::approveCall {
        spender: PERMIT2_ADDRESS,
        amount: U256::MAX,
    }
    .abi_encode();

    let tx = SafeTransaction {
        to: wld_token_address.to_string(),
        value: "0".to_string(),
        data: format!("0x{}", hex::encode(&calldata)),
        operation: SafeOperation::Call,
        safe_tx_gas: "33000".to_string(),
        base_gas: "30000".to_string(),
        gas_price: "0".to_string(),
        gas_token: "0x0000000000000000000000000000000000000000".to_string(),
        refund_receiver: "0x0000000000000000000000000000000000000000".to_string(),
        nonce: "0".to_string(),
    };
    let signature = safe_account.sign_transaction(chain_id, tx)?;

    let safe_contract = ISafe::new(safe_address, &provider);
    let approve_result = safe_contract
        .execTransaction(
            wld_token_address,
            U256::ZERO, // value
            calldata.into(),
            0u8, // `Call`
            U256::from(33_000u64),
            U256::from(30_000u64), // base_gas
            U256::ZERO,            // gas_price (no refund)
            Address::ZERO,         // ETH token
            Address::ZERO,         // refund_receiver
            signature.to_vec()?.into(),
        )
        .from(owner)
        .send()
        .await?;

    approve_result.get_receipt().await?; // important to get the receipt to ensure the transaction was executed

    // Step 5: Initialize a "Mini App" Wallet which will get approved to transfer WLD tokens on behalf of the user
    let mini_app_signer = PrivateKeySigner::random();
    let mini_app_provider = ProviderBuilder::new()
        .wallet(mini_app_signer.clone())
        .connect_http(anvil.endpoint_url());

    mini_app_provider
        .anvil_set_balance(mini_app_signer.address(), U256::from(1e18))
        .await?;

    // Step 6: Execute a `permitTransferFrom` call on the Permit2 contract
    let permitted = UnparsedTokenPermissions {
        token: wld_token_address.to_string(),
        amount: "1000000000000000000".to_string(), // 1 WLD
    };

    let deadline = Utc::now().timestamp() + 180; // 3 minutes from now

    let transfer_from = UnparsedPermitTransferFrom {
        permitted,
        spender: mini_app_signer.address().to_string(),
        nonce: "0".to_string(),
        deadline: deadline.to_string(),
    };

    let signature = safe_account
        .sign_permit2_transfer(chain_id, transfer_from)
        .expect("Failed to sign permit2 transfer");

    let permit_struct = PermitTransferFrom {
        permitted: TokenPermissions {
            token: wld_token_address,
            amount: U256::from(1e18), // 1 WLD
        },
        nonce: U256::from(0),
        deadline: U256::from(deadline),
    };

    let signature_transfer = SignatureTransferDetails {
        to: mini_app_signer.address(),
        requestedAmount: U256::from(1e18), // 1 WLD
    };

    let signature = signature.to_vec()?;

    let permit2_contract = ISignatureTransfer::new(PERMIT2_ADDRESS, &mini_app_provider);
    let result = permit2_contract
        .permitTransferFrom(
            permit_struct,
            signature_transfer,
            safe_address,
            signature.into(),
        )
        .from(mini_app_signer.address())
        .gas(500_000)
        .send()
        .await?;

    result.get_receipt().await?;

    // Step 7: Verify the tokens were indeed transferred
    let mini_app_balance = wld_contract
        .balanceOf(mini_app_signer.address())
        .call()
        .await?;
    let safe_balance_after = wld_contract.balanceOf(safe_address).call().await?;

    assert_eq!(mini_app_balance, U256::from(1e18));
    assert_eq!(safe_balance_after, U256::from(9e18));

    Ok(())
}
