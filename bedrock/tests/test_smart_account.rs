use alloy::{
    network::Ethereum,
    node_bindings::AnvilInstance,
    primitives::{address, keccak256, Address, Bytes, U256},
    providers::{ext::AnvilApi, Provider, ProviderBuilder},
    signers::local::PrivateKeySigner,
    sol,
    sol_types::{SolCall, SolEvent},
};
use bedrock::smart_account::{
    EncodedSafeOpStruct, PackedUserOperation, SafeSmartAccount, SafeSmartAccountSigner,
    UserOperation, ENTRYPOINT_4337, GNOSIS_SAFE_4337_MODULE,
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
    }
);

sol! {
    struct PackedUserOperationStruct {
    address sender;
    uint256 nonce;
    bytes initCode;
    bytes callData;
    bytes32 accountGasLimits;
    uint256 preVerificationGas;
    bytes32 gasFees;
    bytes paymasterAndData;
    bytes signature;
    }

    #[sol(rpc)]
    interface IEntryPoint {
        function depositTo(address account) external payable;
        function handleOps(PackedUserOperationStruct[] calldata ops, address payable beneficiary) external;
    }

    #[sol(rpc)]
    interface IERC20 {
        function transfer(address to, uint256 amount) external returns (bool);
        function balanceOf(address account) external view returns (uint256);
    }

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

impl From<PackedUserOperation> for PackedUserOperationStruct {
    fn from(packed: PackedUserOperation) -> Self {
        PackedUserOperationStruct {
            sender: packed.sender,
            nonce: packed.nonce,
            initCode: packed.init_code,
            callData: packed.call_data,
            accountGasLimits: packed.account_gas_limits.into(),
            preVerificationGas: packed.pre_verification_gas,
            gasFees: packed.gas_fees.into(),
            paymasterAndData: packed.paymaster_and_data,
            signature: packed.signature,
        }
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
    println!("\nDeploying Safe-{}", deploy_nonce);
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

    println!("Deploy transaction hash: {}", receipt.transaction_hash);

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

    println!(
        "✓ Safe deployed at: {}\nFunding Safe with 10 ETH",
        safe_address
    );

    provider
        .anvil_set_balance(safe_address, U256::from(1e19))
        .await
        .expect("Failed to set Safe balance");

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
        .anvil_set_balance(owner, U256::from(10).pow(U256::from(18)))
        .await
        .expect("Failed to set balance");

    println!("✓ Using owner address: {}", owner);

    // Deploy a Safe
    let safe_address = deploy_safe(&provider, owner, U256::ZERO)
        .await
        .expect("Failed to deploy Safe");

    let safe_contract = ISafe::new(safe_address, &provider);

    let message = "Hello from Safe integration test!";
    let chain_id = 480;

    let safe_account = SafeSmartAccount::new(owner_key_hex, &safe_address.to_string())
        .expect("Failed to create SafeSmartAccount");

    let signature = safe_account
        .personal_sign(chain_id, message.to_string())
        .expect("Failed to sign message");

    println!("✓ Message signed successfully");
    println!("  Message:   '{}'", message);
    println!("  Signature: {}", signature);

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

#[tokio::test]
async fn test_execute_erc4337_tx() -> anyhow::Result<()> {
    let anvil = setup_anvil();
    let owner_signer = PrivateKeySigner::random();

    let owner_key_hex = hex::encode(owner_signer.to_bytes());

    let owner = owner_signer.address();
    println!("✓ Using owner address: {}", owner);

    let provider = ProviderBuilder::new()
        .wallet(owner_signer.clone())
        .connect_http(anvil.endpoint_url());

    // Fund owner
    provider.anvil_set_balance(owner, U256::from(1e19)).await?;

    // Deploy Safes
    let safe_address = deploy_safe(&provider, owner, U256::ZERO).await?;
    let safe_address2 = deploy_safe(&provider, owner, U256::from(1)).await?;

    let before_balance = provider.get_balance(safe_address2).await?;

    // Fund EntryPoint deposit for the Safe
    let entry_point = IEntryPoint::new(*ENTRYPOINT_4337, &provider);
    let _ = entry_point
        .depositTo(safe_address)
        .value(U256::from(1e18))
        .send()
        .await?;

    // Let's transfer 1 ETH from Safe 1 to Safe 2
    let eth_amount = U256::from(1e18);
    let call_data = ISafe4337Module::executeUserOpCall {
        to: safe_address2,
        value: eth_amount,
        data: Bytes::new(),
        operation: 0, // CALL
    }
    .abi_encode();

    // Build UserOperation
    let valid_after = &0u64.to_be_bytes()[2..]; // validAfter = 0  (immediately valid)
    let valid_until = &u64::MAX.to_be_bytes()[2..]; // validUntil = 0xFFFF_FFFF_FFFF (≈ forever)
    let mut user_op = UserOperation {
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

    // Sign UserOp and prepend validity timestamps
    let safe_account = SafeSmartAccount::new(owner_key_hex, &safe_address.to_string())
        .expect("Failed to create SafeSmartAccount");
    let op_hash = EncodedSafeOpStruct::try_from(&user_op)?.into_transaction_hash();

    let worldchain_chain_id = 480;
    let sig = safe_account
        .sign_digest(op_hash, worldchain_chain_id, Some(*GNOSIS_SAFE_4337_MODULE))?
        .as_bytes();
    let mut sig_with_timestamps = Vec::with_capacity(77);
    sig_with_timestamps.extend_from_slice(valid_after);
    sig_with_timestamps.extend_from_slice(valid_until);
    sig_with_timestamps.extend_from_slice(&sig);
    user_op.signature = format!("0x{}", hex::encode(sig_with_timestamps));

    // Submit through EntryPoint
    let _ = entry_point
        .handleOps(vec![PackedUserOperation::try_from(&user_op)?.into()], owner)
        .from(owner)
        .send()
        .await?;

    //  Assert transfer succeeded
    let after_balance = provider.get_balance(safe_address2).await?;
    assert_eq!(
        after_balance,
        before_balance + U256::from(1e18),
        "Native ETH transfer did not succeed"
    );
    Ok(())
}
