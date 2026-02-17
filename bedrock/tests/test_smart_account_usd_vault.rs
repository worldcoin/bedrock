///! E2E test for migrating from USDVault to ERC4626 vault using Morpho as example.
use std::sync::Arc;

mod common;
use alloy::{
    primitives::{
        utils::{parse_ether, parse_units},
        Address, U256,
    },
    providers::{ext::AnvilApi, ProviderBuilder},
    signers::local::PrivateKeySigner,
};
use common::{deploy_safe, set_erc20_balance_for_safe, setup_anvil, IERC20};

use std::str::FromStr;

use bedrock::{
    primitives::http_client::set_http_client, smart_account::SafeSmartAccount,
    test_utils::AnvilBackedHttpClient,
};

use crate::common::{
    set_address_verified_until_for_account, set_erc20_balance_with_slot,
};

#[tokio::test]
async fn test_usd_vault_migration() -> anyhow::Result<()> {
    let usdc_address =
        Address::from_str("0x79A02482A880bCE3F13e09Da970dC34db4CD24d1").unwrap();
    let sdai_address =
        Address::from_str("0x859DBE24b90C9f2f7742083d3cf59cA41f55Be5d").unwrap();
    let usd_vault_address =
        Address::from_str("0x6F1D98034D3055684F989f3Ac9832eC37B3F22EC").unwrap();
    let morpho_vault_address =
        Address::from_str("0xb1E80387EbE53Ff75a89736097D34dC8D9E9045B").unwrap();

    let owner_signer = PrivateKeySigner::random();
    let owner_key_hex = hex::encode(owner_signer.to_bytes());
    let owner = owner_signer.address();

    let anvil = setup_anvil();
    let provider = ProviderBuilder::new()
        .wallet(owner_signer.clone())
        .connect_http(anvil.endpoint_url());

    let usdc = IERC20::new(usdc_address, &provider);
    let sdai = IERC20::new(sdai_address, &provider);
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

    set_erc20_balance_with_slot(
        &provider,
        usdc_address,
        usd_vault_address,
        parse_units("10000", 6).unwrap().into(),
        U256::from(9), // USDC balance is at slot 9
    )
    .await?;
    set_erc20_balance_with_slot(
        &provider,
        sdai_address,
        usd_vault_address,
        parse_units("10000", 18).unwrap().into(),
        U256::from(0), // sDAI balance is at slot 0
    )
    .await?;
    println!("✓ Added liquidity to USDVault");

    let vault_usdc_balance = usdc.balanceOf(usd_vault_address).call().await?;
    let vault_sdai_balance = sdai.balanceOf(usd_vault_address).call().await?;
    println!("USDVault USDC balance: {vault_usdc_balance}");
    println!("USDVault sDAI balance: {vault_sdai_balance}");

    let sdai_amount: U256 = parse_units("10", 18).unwrap().into();
    set_erc20_balance_for_safe(&provider, sdai_address, safe_address, sdai_amount)
        .await?;

    let client = AnvilBackedHttpClient::new(provider.clone());
    set_http_client(Arc::new(client));

    let safe_account = SafeSmartAccount::new(owner_key_hex, &safe_address.to_string())?;
    let sdai_balance_before = sdai.balanceOf(safe_address).call().await?;
    println!("sDAI balance before migration: {sdai_balance_before}");

    let morpho_shares_before = morpho_vault.balanceOf(safe_address).call().await?;
    println!("MorphoVault shares before migration: {morpho_shares_before}");

    safe_account
        .transaction_usd_vault_migrate(
            &usd_vault_address.to_string(),
            &morpho_vault_address.to_string(),
        )
        .await
        .expect("USDVault migration failed");
    println!("✓ Migrated USDVault to MorphoVault");

    let sdai_balance_after = sdai.balanceOf(safe_address).call().await?;
    println!("sDAI balance after migration: {sdai_balance_after}");

    let morpho_shares_after = morpho_vault.balanceOf(safe_address).call().await?;
    println!("MorphoVault shares after migration: {morpho_shares_after}");

    assert!(
        sdai_balance_after == U256::ZERO,
        "sDAI balance was not fully redeemed during migration"
    );
    assert!(
        morpho_shares_after > morpho_shares_before,
        "MorphoVault shares did not increase after migration"
    );

    Ok(())
}
