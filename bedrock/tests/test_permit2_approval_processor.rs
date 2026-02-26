use std::sync::Arc;

mod common;
use alloy::{
    primitives::U256,
    providers::{ext::AnvilApi, ProviderBuilder},
    signers::local::PrivateKeySigner,
};
use common::{deploy_safe, setup_anvil, IERC20};

use bedrock::{
    migration::{
        processors::permit2_approval_processor::Permit2ApprovalProcessor, MigrationProcessor,
        ProcessorResult,
    },
    primitives::http_client::set_http_client,
    smart_account::{SafeSmartAccount, ENTRYPOINT_4337, PERMIT2_ADDRESS},
    test_utils::{AnvilBackedHttpClient, IEntryPoint},
    transactions::contracts::permit2::WORLDCHAIN_PERMIT2_TOKENS,
};

#[tokio::test]
async fn test_permit2_approval_processor_full_flow() -> anyhow::Result<()> {
    // 1) Spin up anvil fork of WorldChain
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
    let deposit_tx = entry_point
        .depositTo(safe_address)
        .value(U256::from(1e18 as u64))
        .send()
        .await?;
    let _ = deposit_tx.get_receipt().await?;

    // 5) Install mocked HTTP client that routes RPC calls to Anvil
    let client = AnvilBackedHttpClient::new(provider.clone());
    set_http_client(Arc::new(client));

    // 6) Create the processor
    let safe_account = Arc::new(
        SafeSmartAccount::new(owner_key_hex, &safe_address.to_string())?,
    );
    let processor = Permit2ApprovalProcessor::new(safe_account.clone());

    // 7) Verify migration ID
    assert_eq!(processor.migration_id(), "wallet.permit2.approval");

    // 8) Verify is_applicable returns true (no approvals yet)
    assert!(
        processor.is_applicable().await?,
        "Processor should be applicable before approvals"
    );

    // 9) Execute the migration (batched MultiSend approve)
    let result = processor.execute().await?;
    assert!(
        matches!(result, ProcessorResult::Success),
        "Expected ProcessorResult::Success"
    );

    // 10) Verify on-chain: all tokens should now have max allowance to Permit2
    for (token_address, token_name) in &WORLDCHAIN_PERMIT2_TOKENS {
        let token = IERC20::new(*token_address, &provider);
        let allowance = token
            .allowance(safe_address, PERMIT2_ADDRESS)
            .call()
            .await?;

        assert_eq!(
            allowance, U256::MAX,
            "Token {} should have max allowance to Permit2 after migration",
            token_name
        );
    }

    // 11) Verify is_applicable returns false
    assert!(
        !processor.is_applicable().await?,
        "Processor should not be applicable after approvals"
    );


    Ok(())
}
