use alloy::{
    primitives::{Bytes, U256},
    providers::{ext::AnvilApi, Provider, ProviderBuilder},
    signers::local::PrivateKeySigner,
    sol_types::SolCall,
};
use bedrock::test_utils::PackedUserOperation;
use bedrock::{
    primitives::Network,
    smart_account::{
        EncodedSafeOpStruct, SafeSmartAccount, SafeSmartAccountSigner, UserOperation,
        ENTRYPOINT_4337, GNOSIS_SAFE_4337_MODULE,
    },
    test_utils::IEntryPoint,
    transactions::foreign::UnparsedUserOperation,
};
mod common;
use common::{deploy_safe, setup_anvil, ISafe4337Module};

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
        paymaster_verification_gas_limit: Some("0x0".to_string()),
        paymaster_post_op_gas_limit: Some("0x0".to_string()),
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
    let (va, vu) = user_op.extract_validity_timestamps()?;
    let op_hash = EncodedSafeOpStruct::from_user_op_with_validity(&user_op, va, vu)
        .unwrap()
        .into_transaction_hash();

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
