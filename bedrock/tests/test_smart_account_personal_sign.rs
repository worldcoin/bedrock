use alloy::{
    primitives::{keccak256, Bytes, U256},
    providers::{ext::AnvilApi, ProviderBuilder},
    signers::local::PrivateKeySigner,
};
use bedrock::{primitives::Network, smart_account::SafeSmartAccount};

mod common;
use common::{deploy_safe, setup_anvil, ISafe};

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
                "execution reverted: revert: GS026"
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
                "execution reverted: revert: GS026"
            );
        }
        _ => panic!("Expected TransportError error, got {is_valid_result:?}"),
    }
}
