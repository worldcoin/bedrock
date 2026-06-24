use std::sync::Arc;

mod common;
use alloy::{
    primitives::{Address, B256, U256},
    providers::{ext::AnvilApi, Provider, ProviderBuilder},
    signers::local::PrivateKeySigner,
};
use common::{
    deploy_safe_without_4337_module, setup_anvil, ISafe, SAFE_4337_MODULE_ADDRESS,
};

use bedrock::{
    migration::{MigrationProcessor, ProcessorResult, Safe4337ModuleProcessor},
    primitives::http_client::set_http_client,
    smart_account::SafeSmartAccount,
    test_utils::AnvilBackedHttpClient,
    transactions::contracts::safe_module::SAFE_FALLBACK_HANDLER_SLOT,
};

/// Reads the Safe's fallback handler address from its storage slot.
async fn fallback_handler<P>(provider: &P, safe: Address) -> anyhow::Result<Address>
where
    P: Provider<alloy::network::Ethereum>,
{
    let slot = U256::from_be_bytes(SAFE_FALLBACK_HANDLER_SLOT.0);
    let word = provider.get_storage_at(safe, slot).await?;
    Ok(Address::from_word(B256::from(word.to_be_bytes::<32>())))
}

/// End-to-end: a Safe deployed without the ERC-4337 module is detected by the
/// migration, repaired via a relayed `execTransaction`, and ends up with the
/// module enabled AND set as the fallback handler.
#[tokio::test]
async fn test_safe_4337_module_processor_full_flow() -> anyhow::Result<()> {
    // 1) Anvil fork of WorldChain + funded owner signer.
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

    // Pre-state: neither condition is satisfied.
    assert!(
        !safe
            .isModuleEnabled(SAFE_4337_MODULE_ADDRESS)
            .call()
            .await?,
        "module should be absent before repair"
    );
    assert_ne!(
        fallback_handler(&provider, safe_address).await?,
        SAFE_4337_MODULE_ADDRESS,
        "fallback handler should not be the module before repair"
    );

    // 3) Route Bedrock's backend RPC through the Anvil-backed mock.
    let client = AnvilBackedHttpClient::new(provider.clone());
    set_http_client(Arc::new(client));

    // 4) Build the processor for this Safe.
    let safe_account = Arc::new(SafeSmartAccount::from_private_key_hex(
        owner_key_hex,
        &safe_address.to_string(),
    )?);
    let processor = Safe4337ModuleProcessor::new(safe_account);

    assert_eq!(
        processor.migration_id(),
        "wallet.safe.enable_4337_module.v1"
    );

    // 5) Applicable while the module/handler are missing.
    assert!(
        processor.is_applicable().await?,
        "processor should be applicable before repair"
    );

    // 6) Execute the repair (signed execTransaction relayed on-chain).
    let result = processor.execute().await?;
    assert!(
        matches!(result, ProcessorResult::Success),
        "expected ProcessorResult::Success"
    );

    // 7) Post-state: module enabled AND fallback handler == module.
    assert!(
        safe.isModuleEnabled(SAFE_4337_MODULE_ADDRESS)
            .call()
            .await?,
        "module should be enabled after repair"
    );
    assert_eq!(
        fallback_handler(&provider, safe_address).await?,
        SAFE_4337_MODULE_ADDRESS,
        "fallback handler should be the module after repair"
    );

    // 8) No longer applicable once repaired.
    assert!(
        !processor.is_applicable().await?,
        "processor should not be applicable after repair"
    );

    Ok(())
}
