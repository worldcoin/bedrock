//! End-to-end coverage for [`WalletMigrationController`] against a real chain.
//!
//! Proves the ordering rule that unit tests can only assert with doubles: on a
//! Safe missing the ERC-4337 module, the repair runs alone on the first launch
//! and everything else waits, because a userOp cannot validate until it lands.

use std::sync::Arc;

mod common;
use alloy::{
    primitives::{Address, B256, U256},
    providers::{ext::AnvilApi, Provider, ProviderBuilder},
    signers::local::PrivateKeySigner,
};
use common::{
    deploy_safe_without_4337_module, setup_anvil, ISafe, IERC20,
    SAFE_4337_MODULE_ADDRESS,
};

use bedrock::{
    migration::{
        MigrationRecordEntry, MigrationStatus,
        TestWalletMigrationController as WalletMigrationController,
    },
    primitives::{
        http_client::set_http_client, key_value_store::InMemoryDeviceKeyValueStore,
    },
    smart_account::{SafeSmartAccount, ENTRYPOINT_4337, PERMIT2_ADDRESS},
    test_utils::{AnvilBackedHttpClient, IEntryPoint},
    transactions::contracts::{
        safe_module::SAFE_FALLBACK_HANDLER_SLOT, worldchain::USDC_ADDRESS,
    },
};

const REPAIR: &str = "wallet.safe.enable_4337_module.v1";
const PERMIT2: &str = "wallet.permit2.approval";

fn record<'a>(
    records: &'a [MigrationRecordEntry],
    id: &str,
) -> &'a MigrationRecordEntry {
    records
        .iter()
        .find(|r| r.migration_id == id)
        .unwrap_or_else(|| panic!("no record for {id}"))
}

/// Reads the Safe's fallback handler address from its storage slot.
async fn fallback_handler<P>(provider: &P, safe: Address) -> anyhow::Result<Address>
where
    P: Provider<alloy::network::Ethereum>,
{
    let slot = U256::from_be_bytes(SAFE_FALLBACK_HANDLER_SLOT.0);
    let word = provider.get_storage_at(safe, slot).await?;
    Ok(Address::from_word(B256::from(word.to_be_bytes::<32>())))
}

#[tokio::test]
async fn test_repair_runs_alone_then_unblocks_the_rest() -> anyhow::Result<()> {
    // 1) Anvil fork of WorldChain, funded owner, Safe deployed *without* the
    //    4337 module — the state this ordering rule exists for.
    let anvil = setup_anvil();
    let owner_signer = PrivateKeySigner::random();
    let owner_key_hex = hex::encode(owner_signer.to_bytes());
    let owner = owner_signer.address();

    let provider = ProviderBuilder::new()
        .wallet(owner_signer.clone())
        .connect_http(anvil.endpoint_url());
    provider
        .anvil_set_balance(owner, U256::from(1e18 as u64))
        .await?;

    let safe_address =
        deploy_safe_without_4337_module(&provider, owner, U256::ZERO).await?;
    let safe = ISafe::new(safe_address, &provider);
    let usdc = IERC20::new(USDC_ADDRESS, &provider);

    // The Permit2 approvals go out as a userOp, so the Safe needs a deposit.
    let entry_point = IEntryPoint::new(*ENTRYPOINT_4337, &provider);
    entry_point
        .depositTo(safe_address)
        .value(U256::from(1e18 as u64))
        .send()
        .await?
        .get_receipt()
        .await?;

    set_http_client(Arc::new(AnvilBackedHttpClient::new(provider.clone())));

    let safe_account = Arc::new(SafeSmartAccount::from_private_key_hex(
        owner_key_hex,
        &safe_address.to_string(),
    )?);
    let kv_store = Arc::new(InMemoryDeviceKeyValueStore::new());
    let controller =
        WalletMigrationController::new(kv_store, Some(safe_account.clone()));

    // 2) Pre-state: no module, no fallback handler, no approvals.
    assert!(
        !safe
            .isModuleEnabled(SAFE_4337_MODULE_ADDRESS)
            .call()
            .await?
    );
    assert_eq!(
        usdc.allowance(safe_address, PERMIT2_ADDRESS).call().await?,
        U256::ZERO
    );

    // 3) Launch 1: the repair is relayed, and everything else is held back.
    //    A userOp could not validate yet, so submitting one would be waste.
    let summary = controller.run().await;
    assert_eq!(summary.total, 2);
    assert_eq!(summary.pending, 1, "the repair was submitted");
    assert_eq!(summary.skipped, 1, "the dependent was held back");

    let records = controller.list_records()?;
    assert!(
        matches!(record(&records, REPAIR).status, MigrationStatus::InProgress),
        "the repair is in flight, not yet proven"
    );
    let permit2 = record(&records, PERMIT2);
    assert!(
        matches!(permit2.status, MigrationStatus::NotStarted),
        "the dependent must not have run on this launch"
    );
    assert_eq!(permit2.attempts, 0, "and must not have submitted anything");
    assert_eq!(
        usdc.allowance(safe_address, PERMIT2_ADDRESS).call().await?,
        U256::ZERO,
        "no approvals can have gone out before the repair converged"
    );

    // The relay itself did land — being held back is a decision about the
    // *record*, not about the chain.
    assert!(
        safe.isModuleEnabled(SAFE_4337_MODULE_ADDRESS)
            .call()
            .await?,
        "the relayed repair should be on chain already"
    );
    assert_eq!(
        fallback_handler(&provider, safe_address).await?,
        SAFE_4337_MODULE_ADDRESS
    );

    // 4) Launch 2: the repair is observed in place, which converges it and
    //    unblocks the dependent in the same pass.
    let summary = controller.run().await;
    assert_eq!(summary.succeeded, 1, "the repair converged");
    assert_eq!(summary.pending, 1, "and the dependent submitted");

    let records = controller.list_records()?;
    assert!(matches!(
        record(&records, REPAIR).status,
        MigrationStatus::Succeeded
    ));
    assert!(matches!(
        record(&records, PERMIT2).status,
        MigrationStatus::InProgress
    ));
    assert_eq!(
        usdc.allowance(safe_address, PERMIT2_ADDRESS).call().await?,
        U256::MAX,
        "the approvals landed once the Safe could validate a userOp"
    );

    // 5) Launch 3: both observe their end state and settle. Nothing is
    //    submitted, and the repair reports skipped rather than a fresh success.
    let summary = controller.run().await;
    assert_eq!(summary.succeeded, 1, "the approvals are proven landed");
    assert_eq!(summary.skipped, 1, "the repair was already done");
    assert_eq!(summary.pending, 0);

    let records = controller.list_records()?;
    for id in [REPAIR, PERMIT2] {
        assert!(
            matches!(record(&records, id).status, MigrationStatus::Succeeded),
            "{id} should be converged"
        );
    }

    Ok(())
}
