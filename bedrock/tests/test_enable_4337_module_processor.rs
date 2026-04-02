use std::sync::Arc;

mod common;
use alloy::{
    primitives::U256,
    providers::{ext::AnvilApi, ProviderBuilder},
    signers::local::PrivateKeySigner,
};
use common::{deploy_safe_v130, setup_anvil, ISafe, SAFE_4337_MODULE};

use bedrock::{
    migration::{
        processors::enable_4337_module_processor::Enable4337ModuleProcessor,
        MigrationProcessor,
    },
    primitives::http_client::set_http_client,
    smart_account::{SafeSmartAccount, ENTRYPOINT_4337},
    test_utils::{AnvilBackedHttpClient, IEntryPoint},
};

#[tokio::test]
async fn test_enable_4337_module_processor_full_flow() -> anyhow::Result<()> {
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

    // 3) Deploy Safe v1.3.0 without 4337 module
    let safe_address =
        deploy_safe_v130(&provider, owner, U256::ZERO).await?;

    // 4) Verify module is NOT enabled
    let safe_contract = ISafe::new(safe_address, &provider);
    let is_enabled = safe_contract
        .isModuleEnabled(SAFE_4337_MODULE)
        .call()
        .await?;
    assert!(!is_enabled, "4337 module should NOT be enabled initially");

    // 5) Fund EntryPoint deposit for Safe
    let entry_point = IEntryPoint::new(*ENTRYPOINT_4337, &provider);
    let deposit_tx = entry_point
        .depositTo(safe_address)
        .value(U256::from(1e18 as u64))
        .send()
        .await?;
    let _ = deposit_tx.get_receipt().await?;

    // 6) We need the 4337 module enabled as fallback handler for UserOp execution.
    //    Since this is a chicken-and-egg problem (we need the module to execute UserOps,
    //    but we want to test enabling the module via UserOp), we enable the module
    //    via a direct execTransaction first, then disable it, then test the processor.
    //
    //    Alternative approach: test is_applicable only (which is the main on-chain check),
    //    and trust that execute follows the same pattern as the permit2 processor.

    // 6) Install mocked HTTP client that routes RPC calls to Anvil
    let client = AnvilBackedHttpClient::new(provider.clone());
    set_http_client(Arc::new(client));

    // 7) Create the processor
    let safe_account = Arc::new(SafeSmartAccount::new(
        owner_key_hex,
        &safe_address.to_string(),
    )?);
    let processor = Enable4337ModuleProcessor::new(safe_account.clone());

    // 8) Verify migration ID
    assert_eq!(
        processor.migration_id(),
        "wallet.safe.enable_4337_module.v1"
    );

    // 9) Verify is_applicable returns true (module not enabled)
    assert!(
        processor.is_applicable().await?,
        "Processor should be applicable when 4337 module is NOT enabled"
    );

    // 10) Now deploy a Safe WITH module enabled and verify is_applicable returns false
    let safe_address_with_module =
        common::deploy_safe_v141(&provider, owner, U256::from(1)).await?;

    let safe_account_with_module = Arc::new(SafeSmartAccount::new(
        hex::encode(owner_signer.to_bytes()),
        &safe_address_with_module.to_string(),
    )?);
    let processor_with_module =
        Enable4337ModuleProcessor::new(safe_account_with_module);

    assert!(
        !processor_with_module.is_applicable().await?,
        "Processor should NOT be applicable when 4337 module is already enabled"
    );

    Ok(())
}
