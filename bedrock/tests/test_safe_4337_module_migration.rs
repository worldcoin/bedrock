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
    migration::{
        wallet::safe_4337_module::Safe4337ModuleMigration, WalletMigration,
        WalletMigrationResult,
    },
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
async fn test_safe_4337_module_migration_full_flow() -> anyhow::Result<()> {
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

    // 4) Build the migration for this Safe.
    let safe_account = Arc::new(SafeSmartAccount::from_private_key_hex(
        owner_key_hex,
        &safe_address.to_string(),
    )?);
    let migration = Safe4337ModuleMigration::new(safe_account);

    assert_eq!(
        migration.migration_id(),
        "wallet.safe.enable_4337_module.v1"
    );

    // 5) Pass 1: the end state does not hold, so the repair is relayed and
    //    reported as Submitted with the relayed transaction id. Nothing is
    //    confirmed yet — a later observation is what proves it landed.
    assert!(!migration.end_state_holds().await?);
    assert!(
        matches!(
            migration.reconcile().await?,
            WalletMigrationResult::Submitted { reference: Some(_) }
        ),
        "first pass should relay and report submitted with a transaction id"
    );

    // The relayed execTransaction has landed: module enabled AND handler set.
    assert!(
        safe.isModuleEnabled(SAFE_4337_MODULE_ADDRESS)
            .call()
            .await?,
        "module should be enabled after the relayed repair"
    );
    assert_eq!(
        fallback_handler(&provider, safe_address).await?,
        SAFE_4337_MODULE_ADDRESS,
        "fallback handler should be the module after the relayed repair"
    );

    // 6) Pass 2: the end state now holds. This observation — not the relay's
    //    own return value — is what marks the migration complete.
    assert!(
        migration.end_state_holds().await?,
        "the end state should hold once the repair is in place"
    );

    Ok(())
}
