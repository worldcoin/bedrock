#[cfg(feature = "anvil-integration-tests")]
#[tokio::test]
async fn test_personal_sign() {
    use alloy::{
        node_bindings::Anvil,
        primitives::{address, keccak256, Address, Bytes, U256},
        providers::{ext::AnvilApi, ProviderBuilder},
        signers::local::PrivateKeySigner,
        sol,
        sol_types::{SolCall, SolEvent},
    };
    use bedrock::smart_account::{SafeSmartAccount, SafeSmartAccountSigner};

    dotenv::dotenv().ok();

    let rpc_url = std::env::var("WORLDCHAIN_RPC_URL")
        .expect("WORLDCHAIN_RPC_URL not set. Copy .env.example to .env and add your Alchemy API key");

    println!("Starting Safe integration test...");

    let anvil = Anvil::new().fork(rpc_url).spawn();

    println!("✓ Anvil started at: {}", anvil.endpoint());

    let owner_signer: PrivateKeySigner = anvil.keys()[0].clone().into();

    let owner_signer = PrivateKeySigner::random();
    let owner = owner_signer.address();
    let owner_key_hex = hex::encode(owner_signer.to_bytes());

    let provider = ProviderBuilder::new()
        .wallet(owner_signer)
        .connect_http(anvil.endpoint_url());

    provider
        .anvil_set_balance(owner, U256::from(10).pow(U256::from(18)))
        .await
        .expect("Failed to set balance");

    println!("✓ Using owner address: {}", owner);

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

    // Safe contract addresses on Worldchain
    const SAFE_PROXY_FACTORY_ADDRESS: Address =
        address!("4e1DCf7AD4e460CfD30791CCC4F9c8a4f820ec67");
    const SAFE_L2_SINGLETON_ADDRESS: Address =
        address!("29fcB43b46531BcA003ddC8FCB67FFE91900C762");
    const SAFE_4337_MODULE_ADDRESS: Address =
        address!("75cf11467937ce3F2f357CE24ffc3DBF8fD5c226");
    const SAFE_MODULE_SETUP_ADDRESS: Address =
        address!("2dd68b007B46fBe91B9A7c3EDa5A7a1063cB5b47");

    let proxy_factory = ISafeProxyFactory::new(SAFE_PROXY_FACTORY_ADDRESS, &provider);

    // Setup modules array
    let modules = vec![SAFE_4337_MODULE_ADDRESS];

    // Setup owners array
    let owners = vec![owner];

    // Encode the Safe setup call
    let setup_data = ISafe::setupCall {
        _owners: owners,
        _threshold: U256::from(1),
        to: SAFE_MODULE_SETUP_ADDRESS,
        data: ISafe::enableModulesCall { modules }.abi_encode().into(),
        fallbackHandler: SAFE_4337_MODULE_ADDRESS,
        paymentToken: Address::ZERO,
        payment: U256::ZERO,
        paymentReceiver: Address::ZERO,
    }
    .abi_encode();

    // Deploy Safe via proxy factory
    let deploy_tx = proxy_factory
        .createProxyWithNonce(SAFE_L2_SINGLETON_ADDRESS, setup_data.into(), U256::ZERO)
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

    println!("\n✓ Safe deployed at: {}", safe_address);

    sol!(
        #[allow(missing_docs)]
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

            function isValidSignature(bytes32 dataHash, bytes memory signature) external view returns (bytes4);
        }
    );

    let safe_contract = ISafe::new(safe_address, &provider);

    let safe_account = SafeSmartAccount::new(owner_key_hex, &safe_address.to_string())
        .expect("Failed to create SafeSmartAccount");

    let message = "Hello from Safe integration test!";
    let chain_id = 480;

    let signature = safe_account
        .personal_sign(chain_id, message.to_string())
        .expect("Failed to sign message");

    println!("✓ Message signed successfully");
    println!("  Message:   '{}'", message);
    println!("  Signature: {}", signature);

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
        .isValidSignature(message_hash.into(), Bytes::from(sig_bytes))
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
