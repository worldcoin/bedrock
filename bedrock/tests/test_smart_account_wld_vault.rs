//! E2E test for migrating from WLDVault to ERC4626 vault using Morpho as example.
use std::sync::Arc;

mod common;
use alloy::{
    primitives::{
        utils::{parse_ether, parse_units},
        Address, U256,
    },
    providers::{ext::AnvilApi, ProviderBuilder},
    signers::local::PrivateKeySigner,
    sol,
};
use common::{deploy_safe, set_erc20_balance_for_safe, setup_anvil, IERC20};

use std::str::FromStr;

use bedrock::{
    primitives::http_client::set_http_client, smart_account::SafeSmartAccount,
    test_utils::AnvilBackedHttpClient,
};

use crate::common::set_address_verified_until_for_account;

sol! {
   #[sol(rpc)]
    interface WLDVault {
        function balanceOf(address account) external view returns (uint256);
        function deposit(uint256 amount) external;
    }
}

#[tokio::test]
async fn test_wld_vault_migration() -> anyhow::Result<()> {
    let wld_address =
        Address::from_str("0x2cFc85d8E48F8EAB294be644d9E25C3030863003").unwrap();
    let wld_vault_address =
        Address::from_str("0x14a028cC500108307947dca4a1Aa35029FB66CE0").unwrap();
    let morpho_vault_address =
        Address::from_str("0x348831b46876d3dF2Db98BdEc5E3B4083329Ab9f").unwrap();

    let owner_signer = PrivateKeySigner::random();
    let owner_key_hex = hex::encode(owner_signer.to_bytes());
    let owner = owner_signer.address();

    let anvil = setup_anvil();
    let provider = ProviderBuilder::new()
        .wallet(owner_signer.clone())
        .connect_http(anvil.endpoint_url());

    let wld = IERC20::new(wld_address, &provider);
    let wld_vault = WLDVault::new(wld_vault_address, &provider);
    let morpho_vault = IERC20::new(morpho_vault_address, &provider);

    let safe_address = deploy_safe(&provider, owner, U256::ZERO).await?;
    println!("✓ Deployed Safe at: {safe_address}");

    provider
        .anvil_set_balance(safe_address, parse_ether("1").unwrap())
        .await?;
    println!("✓ Funded Safe for userOp gas");

    set_address_verified_until_for_account(
        &provider,
        safe_address,
        U256::from(2_000_000_000u64),
    )
    .await?;
    println!("✓ Set Safe as verified until far future");

    let amount: U256 = parse_units("1", 18).unwrap().into();
    set_erc20_balance_for_safe(&provider, wld_address, safe_address, amount).await?;

    let balance_before = wld.balanceOf(safe_address).call().await?;
    println!("WLD balance before deposit: {balance_before}");

    let vault_before = wld_vault.balanceOf(safe_address).call().await?;
    println!("WLDVault balance before deposit: {vault_before}");

    provider.anvil_impersonate_account(safe_address).await?;

    // Approve WLDVault to spend WLD from Safe
    let request = wld
        .approve(wld_vault_address, amount)
        .into_transaction_request()
        .from(safe_address);
    provider
        .anvil_send_impersonated_transaction(request)
        .await?;
    provider.anvil_mine(Some(1), None).await?;

    // Deposit WLDVault
    let request = wld_vault
        .deposit(amount)
        .into_transaction_request()
        .from(safe_address)
        .to(wld_vault_address);
    provider
        .anvil_send_impersonated_transaction(request)
        .await?;
    provider.anvil_mine(Some(1), None).await?;

    provider
        .anvil_stop_impersonating_account(safe_address)
        .await?;
    println!("✓ Deposited WLD into WLDVault");

    let balance_after = wld.balanceOf(safe_address).call().await?;
    println!("WLD balance after deposit: {balance_after}");

    let vault_after = wld_vault.balanceOf(safe_address).call().await?;
    println!("WLDVault balance after deposit: {vault_after}");

    assert!(
        balance_after < balance_before,
        "WLD balance did not decrease after deposit"
    );
    assert!(
        vault_after > vault_before,
        "WLDVault balance did not increase after deposit"
    );

    let shares_before = morpho_vault.balanceOf(safe_address).call().await?;
    println!("MorphoVault balance before migration: {shares_before}");

    let client = AnvilBackedHttpClient::new(provider.clone());
    set_http_client(Arc::new(client));

    let safe_account = SafeSmartAccount::new(owner_key_hex, &safe_address.to_string())?;
    safe_account
        .transaction_wld_legacy_vault_migrate(
            &wld_vault_address.to_string(),
            &morpho_vault_address.to_string(),
        )
        .await
        .expect("WLDVault migration failed");
    println!("✓ Migrated WLDVault to MorphoVault");

    let balance_after = wld.balanceOf(safe_address).call().await?;
    println!("WLD balance after migration: {balance_after}");

    let vault_after = wld_vault.balanceOf(safe_address).call().await?;
    println!("WLDVault balance after migration: {vault_after}");

    let shares_after = morpho_vault.balanceOf(safe_address).call().await?;
    println!("MorphoVault balance after migration: {shares_after}");

    assert!(
        vault_after == U256::ZERO,
        "WLDVault balance not zero after migration"
    );
    assert!(
        shares_before < shares_after,
        "MorphoVault shares did not increase after migration"
    );

    Ok(())
}
