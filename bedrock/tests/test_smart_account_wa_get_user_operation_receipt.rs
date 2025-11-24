use std::sync::Arc;

mod common;
use alloy::{providers::ProviderBuilder, signers::local::PrivateKeySigner};
use common::{setup_anvil, AnvilBackedHttpClient};

use bedrock::{
    primitives::{http_client::set_http_client, Network},
    smart_account::SafeSmartAccount,
};

#[tokio::test]
async fn test_wa_get_user_operation_receipt_uses_mocked_response() -> anyhow::Result<()>
{
    // Spin up a minimal Anvil-backed provider required by AnvilBackedHttpClient
    let anvil = setup_anvil();

    let owner_signer = PrivateKeySigner::random();
    let owner_key_hex = hex::encode(owner_signer.to_bytes());
    let owner_address = owner_signer.address();

    let provider = ProviderBuilder::new()
        .wallet(owner_signer.clone())
        .connect_http(anvil.endpoint_url());

    // Install the shared Anvil-backed HTTP client which now also mocks wa_getUserOperationReceipt
    let client = AnvilBackedHttpClient {
        provider: provider.clone(),
    };
    set_http_client(Arc::new(client));

    // Construct a SafeSmartAccount; the on-chain state is irrelevant for this test
    let safe_account =
        SafeSmartAccount::new(owner_key_hex, &owner_address.to_string())?;

    let user_op_hash =
        "0x3a9b7d5e1f0a4c2e6b8d7f9a1c3e5f0b2d4a6c8e9f1b3d5c7a9e0f2c4b6d8a0";

    let receipt = safe_account
        .wa_get_user_operation_receipt(Network::WorldChain, user_op_hash)
        .await?;

    assert_eq!(receipt.user_op_hash, user_op_hash);
    assert_eq!(
        receipt.transaction_hash,
        "0x3a9b7d5e1f0a4c2e6b8d7f9a1c3e5f0b2d4a6c8e9f1b3d5c7a9e0f2c4b6d8a0"
    );
    assert_eq!(receipt.sender, "0x1234567890abcdef1234567890abcdef12345678");
    assert_eq!(receipt.success, "true");
    assert_eq!(receipt.source, "campaign_gift_sponsor");
    assert_eq!(receipt.source_id.as_deref(), Some("0x1"));
    assert!(receipt.self_sponsor_token.is_none());
    assert!(receipt.self_sponsor_amount.is_none());
    assert_eq!(receipt.block_timestamp, "2025-11-24T20:15:32.000Z");

    Ok(())
}
