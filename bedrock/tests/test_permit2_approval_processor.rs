use std::sync::Arc;

mod common;
use alloy::{
    primitives::U256,
    providers::{
        ext::AnvilApi,
        fillers::{BlobGasFiller, ChainIdFiller, GasFiller},
        Provider, ProviderBuilder,
    },
    signers::local::PrivateKeySigner,
};
use common::{deploy_safe, setup_anvil, IERC20};

use bedrock::{
    migration::{
        processors::permit2_approval_processor::Permit2ApprovalProcessor,
        MigrationController, MigrationProcessor, MigrationStatus, ProcessorResult,
    },
    primitives::{
        http_client::set_http_client, key_value_store::InMemoryDeviceKeyValueStore,
    },
    smart_account::{SafeSmartAccount, ENTRYPOINT_4337, PERMIT2_ADDRESS},
    test_utils::{AnvilBackedHttpClient, IEntryPoint},
    transactions::contracts::worldchain::{
        USDC_ADDRESS, WBTC_ADDRESS, WETH_ADDRESS, WLD_ADDRESS,
    },
};

#[tokio::test]
async fn test_permit2_approval_processor_full_flow() -> anyhow::Result<()> {
    // 1) Spin up anvil fork of WorldChain
    let anvil = setup_anvil();

    // 2) Owner signer and provider
    let owner_signer = PrivateKeySigner::random();
    let owner_key_hex = hex::encode(owner_signer.to_bytes());
    let owner = owner_signer.address();

    // Use simple (uncached) nonce management: this test rolls the chain
    // backwards with evm_revert, and a cached nonce manager would submit
    // future-nonce transactions that anvil queues forever.
    let provider = ProviderBuilder::default()
        .filler(GasFiller::default())
        .filler(BlobGasFiller::default())
        .with_simple_nonce_management()
        .filler(ChainIdFiller::default())
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
    let safe_account = Arc::new(SafeSmartAccount::from_private_key_hex(
        owner_key_hex,
        &safe_address.to_string(),
    )?);
    let processor = Permit2ApprovalProcessor::new(safe_account.clone());

    // 7) Verify migration ID
    assert_eq!(processor.migration_id(), "wallet.permit2.approval");

    // 8) Verify is_applicable returns true (no approvals yet)
    assert!(
        processor.is_applicable().await?,
        "Processor should be applicable before approvals"
    );

    // 8b) Snapshot the pre-approval chain state so the controller-driven
    //     lifecycle below can start from scratch.
    let pre_approval_snapshot: U256 =
        provider.raw_request("evm_snapshot".into(), ()).await?;

    // 9) Execute the migration (batched MultiSend approve, fire-and-forget)
    let result = processor.execute().await?;
    let user_op_hash = match result {
        ProcessorResult::Pending { user_op_hash } => {
            user_op_hash.expect("Pending must carry the submitted userOp hash")
        }
        other => panic!("Expected ProcessorResult::Pending, got {other:?}"),
    };

    // 9b) The hash is only an artifact of the submission; whether the work landed
    // is proven by the on-chain allowance assertions below, not by a receipt.
    assert!(!user_op_hash.is_empty(), "Pending must carry a userOp hash");

    // 10) Verify on-chain: all tokens should now have max allowance to Permit2
    let tokens: [(alloy::primitives::Address, &str); 4] = [
        (USDC_ADDRESS, "usdc"),
        (WETH_ADDRESS, "weth"),
        (WBTC_ADDRESS, "wbtc"),
        (WLD_ADDRESS, "wld"),
    ];
    for (token_address, token_name) in &tokens {
        let token = IERC20::new(*token_address, &provider);
        let allowance = token
            .allowance(safe_address, PERMIT2_ADDRESS)
            .call()
            .await?;

        assert_eq!(
            allowance,
            U256::MAX,
            "Token {token_name} should have max allowance to Permit2 after migration",
        );
    }

    // 11) Verify is_applicable returns false
    assert!(
        !processor.is_applicable().await?,
        "Processor should not be applicable after approvals"
    );

    // --- Fire-and-forget lifecycle with a dropped transaction (controller) ---

    // 12) Roll the chain back to the pre-approval state so the migration is
    //     needed again, and drive it through the full controller this time.
    let reverted: bool = provider
        .raw_request("evm_revert".into(), (pre_approval_snapshot,))
        .await?;
    assert!(reverted, "evm_revert should succeed");
    // After moving the chain backwards, mine filler blocks past the pre-revert
    // height so the provider's block watcher (which tracks height monotonically)
    // sees subsequent transactions; otherwise get_receipt() hangs forever.
    let _: serde_json::Value = provider
        .raw_request("anvil_mine".into(), (U256::from(5), U256::ZERO))
        .await?;

    let kv_store = Arc::new(InMemoryDeviceKeyValueStore::new());
    let controller = MigrationController::with_processors(
        kv_store,
        vec![Arc::new(Permit2ApprovalProcessor::new(
            safe_account.clone(),
        ))],
    );

    // 13) Snapshot right before submitting so we can simulate the submitted
    //     transaction being dropped (chain moves backwards, tx never lands).
    let pre_submit_snapshot: U256 =
        provider.raw_request("evm_snapshot".into(), ()).await?;

    // 14) First controller run: submits fire-and-forget and stays InProgress
    //     with the userOp hash persisted on the record.
    let summary = controller.run_migrations().await?;
    assert_eq!(
        summary.pending, 1,
        "first run should submit and stay pending"
    );
    let record = &controller.list_all_records()?[0];
    assert!(matches!(record.status, MigrationStatus::InProgress));
    assert!(
        record.pending_user_op_hash.is_some(),
        "userOp hash must be persisted on the record"
    );

    // 15) Drop the submitted transaction by moving the chain backwards.
    let reverted: bool = provider
        .raw_request("evm_revert".into(), (pre_submit_snapshot,))
        .await?;
    assert!(reverted, "evm_revert should succeed");
    // Same watcher workaround as above: advance the head past its pre-revert height.
    let _: serde_json::Value = provider
        .raw_request("anvil_mine".into(), (U256::from(5), U256::ZERO))
        .await?;
    let usdc = IERC20::new(USDC_ADDRESS, &provider);
    assert_eq!(
        usdc.allowance(safe_address, PERMIT2_ADDRESS).call().await?,
        U256::ZERO,
        "the dropped transaction's approvals must be gone after the rollback"
    );

    // 16) Second controller run: the receipt reports mined but the on-chain end
    //     state does not hold, so the migration re-executes (new submission).
    let summary = controller.run_migrations().await?;
    assert_eq!(summary.pending, 1, "second run should re-submit");
    let record = &controller.list_all_records()?[0];
    assert!(matches!(record.status, MigrationStatus::InProgress));
    assert_eq!(record.attempts, 2, "re-execution is a second attempt");

    // 17) Third controller run: the resubmitted approvals landed, so the
    //     migration is promoted to Succeeded via the is_applicable recheck.
    let summary = controller.run_migrations().await?;
    assert_eq!(
        summary.succeeded, 1,
        "third run should promote to Succeeded"
    );
    let record = &controller.list_all_records()?[0];
    assert!(matches!(record.status, MigrationStatus::Succeeded));
    assert!(record.pending_user_op_hash.is_none());

    // 18) Final on-chain check: all allowances are max again.
    for (token_address, token_name) in &tokens {
        let token = IERC20::new(*token_address, &provider);
        let allowance = token
            .allowance(safe_address, PERMIT2_ADDRESS)
            .call()
            .await?;
        assert_eq!(
            allowance,
            U256::MAX,
            "Token {token_name} should have max allowance after re-execution",
        );
    }

    Ok(())
}
