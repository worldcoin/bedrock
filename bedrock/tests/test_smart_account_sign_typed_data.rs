use alloy::{
    dyn_abi::TypedData,
    primitives::{Bytes, U256},
    providers::{ext::AnvilApi, ProviderBuilder},
    signers::local::PrivateKeySigner,
};
use bedrock::{primitives::Network, smart_account::SafeSmartAccount};
use serde_json::json;

mod common;
use common::{deploy_safe, setup_anvil, ISafe};

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
