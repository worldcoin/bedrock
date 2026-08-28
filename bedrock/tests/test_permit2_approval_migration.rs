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
        wallet::permit2_approval::Permit2ApprovalMigration, MigrationStatus,
        Reconciled, WalletMigration, WalletMigrationController, WalletMigrationRecord,
    },
    primitives::{
        http_client::set_http_client,
        key_value_store::{DeviceKeyValueStore, InMemoryDeviceKeyValueStore},
    },
    smart_account::{SafeSmartAccount, ENTRYPOINT_4337, PERMIT2_ADDRESS},
    test_utils::{AnvilBackedHttpClient, IEntryPoint},
    transactions::contracts::worldchain::{
        USDC_ADDRESS, WBTC_ADDRESS, WETH_ADDRESS, WLD_ADDRESS,
    },
};

/// Rewinds the record's last-attempt time so the resubmit cooldown has elapsed,
/// standing in for the next cold start an hour later.
fn skip_resubmit_cooldown(kv: &InMemoryDeviceKeyValueStore, migration_id: &str) {
    let key = format!("migration:wallet:{migration_id}");
    let mut record: WalletMigrationRecord =
        serde_json::from_str(&kv.get(key.clone()).unwrap()).unwrap();
    record.last_attempted_at = record
        .last_attempted_at
        .map(|t| t - chrono::Duration::hours(2));
    kv.set(key, serde_json::to_string(&record).unwrap())
        .unwrap();
}

#[tokio::test]
async fn test_permit2_approval_migration_full_flow() -> anyhow::Result<()> {
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

    // 6) Create the migration
    let safe_account = Arc::new(SafeSmartAccount::from_private_key_hex(
        owner_key_hex,
        &safe_address.to_string(),
    )?);
    let migration = Permit2ApprovalMigration::new(safe_account.clone());

    // 7) Verify migration ID
    assert_eq!(migration.migration_id(), "wallet.permit2.approval");

    // 7b) Snapshot the pre-approval chain state so the controller-driven
    //     lifecycle below can start from scratch.
    let pre_approval_snapshot: U256 =
        provider.raw_request("evm_snapshot".into(), ()).await?;

    // 8) Pass 1: observes missing allowances and submits the batched MultiSend
    //    approve, fire-and-forget. The reference is only an artifact of the
    //    submission; whether the work landed is proven by the on-chain allowance
    //    assertions below, never by a receipt.
    assert!(!migration.end_state_holds().await?);
    let reference = match migration.reconcile().await? {
        Reconciled::Submitted { reference } => {
            reference.expect("submission must carry the userOp hash")
        }
        other => panic!("Expected Reconciled::Submitted, got {other:?}"),
    };
    assert!(!reference.is_empty(), "submission must carry a userOp hash");

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

    // 9) Pass 2: the end state now holds.
    assert!(
        migration.end_state_holds().await?,
        "the end state should hold once the approvals are in place"
    );

    // --- Fire-and-forget lifecycle with a dropped transaction (controller) ---

    // 10) Roll the chain back to the pre-approval state so the migration is
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
    let controller = WalletMigrationController::with_migrations(
        kv_store.clone(),
        vec![Arc::new(Permit2ApprovalMigration::new(
            safe_account.clone(),
        ))],
    );

    // 11) Snapshot right before submitting so we can simulate the submitted
    //     transaction being dropped (chain moves backwards, tx never lands).
    let pre_submit_snapshot: U256 =
        provider.raw_request("evm_snapshot".into(), ()).await?;

    // 12) First controller pass: submits fire-and-forget and stays in flight.
    let summary = controller.run().await;
    assert_eq!(
        summary.pending, 1,
        "first pass should submit and stay pending"
    );
    let record = &controller.list_records()?[0];
    assert!(matches!(record.status, MigrationStatus::InProgress));
    assert_eq!(record.attempts, 1);

    // 13) Drop the submitted transaction by moving the chain backwards.
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

    // 14) Second controller pass, an hour later: the gap is open again, so it
    //     re-submits. Nothing about the dropped submission is consulted.
    skip_resubmit_cooldown(&kv_store, "wallet.permit2.approval");
    let summary = controller.run().await;
    assert_eq!(summary.pending, 1, "second pass should re-submit");
    let record = &controller.list_records()?[0];
    assert!(matches!(record.status, MigrationStatus::InProgress));
    assert_eq!(record.attempts, 2, "re-submission is a second attempt");

    // 15) Third controller pass: the resubmitted approvals landed, so the
    //     observation converges and the migration is recorded complete.
    skip_resubmit_cooldown(&kv_store, "wallet.permit2.approval");
    let summary = controller.run().await;
    assert_eq!(
        summary.succeeded, 1,
        "third pass should converge to Succeeded"
    );
    let record = &controller.list_records()?[0];
    assert!(matches!(record.status, MigrationStatus::Succeeded));

    // 16) Final on-chain check: all allowances are max again.
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
