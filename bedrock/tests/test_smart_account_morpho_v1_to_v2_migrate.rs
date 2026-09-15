//! E2E fork test for ERC-4626 vault-to-vault migrate (Morpho Re7 WARS V1 → V2).
//!
//! Mirrors `test_smart_account_wld_vault`: fork World Chain, deploy a Safe, move funds,
//! then call `transaction_erc4626_migrate`.

use std::{str::FromStr, sync::Arc};

use alloy::{
    primitives::{
        utils::{parse_ether, parse_units},
        Address, U256,
    },
    providers::{ext::AnvilApi, ProviderBuilder},
    signers::local::PrivateKeySigner,
    sol,
};

mod common;
use common::{deploy_safe, setup_anvil, IERC20};

use bedrock::{
    primitives::http_client::set_http_client,
    smart_account::{SafeSmartAccount, ENTRYPOINT_4337},
    test_utils::{AnvilBackedHttpClient, IEntryPoint},
};

sol! {
    #[sol(rpc)]
    interface IERC4626Vault {
        function balanceOf(address account) external view returns (uint256);
        function asset() external view returns (address);
        function deposit(uint256 assets, address receiver) external returns (uint256 shares);
        function approve(address spender, uint256 amount) external returns (bool);
    }
}

/// Morpho Re7 WARS (World Chain).
const WARS_TOKEN: &str = "0x0DC4F92879B7670e5f4e4e6e3c801D229129D90D";
const WARS_V1_VAULT: &str = "0x1C94c7A2c71ECF13104c31F49d5138EDb099D25D";
const WARS_V2_VAULT: &str = "0x4047dB25Fd6EcD07d72CA44adf3a2A44dE6DE084";
/// Known wARS holder used to fund the Safe via impersonated transfer.
const WARS_FUNDER: &str = "0x0D0c99daF35DaF2CFC50cF6a437E1c49fDf4F167";
/// Morpho WLD vault — different underlying asset, for mismatch check.
const WLD_MORPHO_VAULT: &str = "0x348831b46876d3dF2Db98BdEc5E3B4083329Ab9f";

#[tokio::test]
async fn test_morpho_wars_v1_to_v2_migration() -> anyhow::Result<()> {
    let wars_token = Address::from_str(WARS_TOKEN)?;
    let wars_v1 = Address::from_str(WARS_V1_VAULT)?;
    let wars_v2 = Address::from_str(WARS_V2_VAULT)?;
    let wars_funder = Address::from_str(WARS_FUNDER)?;
    let bad_dest_vault = Address::from_str(WLD_MORPHO_VAULT)?;

    let owner_signer = PrivateKeySigner::random();
    let owner_key_hex = hex::encode(owner_signer.to_bytes());
    let owner = owner_signer.address();

    let anvil = setup_anvil();
    let provider = ProviderBuilder::new()
        .wallet(owner_signer.clone())
        .connect_http(anvil.endpoint_url());

    let client = AnvilBackedHttpClient::new(provider.clone());
    set_http_client(Arc::new(client));

    let wars = IERC20::new(wars_token, &provider);
    let v1_vault = IERC4626Vault::new(wars_v1, &provider);
    let v2_vault = IERC4626Vault::new(wars_v2, &provider);

    let safe_address = deploy_safe(&provider, owner, U256::ZERO).await?;
    println!("✓ Deployed Safe at: {safe_address}");

    let safe_account = SafeSmartAccount::from_private_key_hex(
        owner_key_hex,
        &safe_address.to_string(),
    )?;

    // Gas for UserOps via EntryPoint deposit (same pattern as Morpho ERC-4626 e2e).
    provider
        .anvil_set_balance(owner, parse_ether("20")?)
        .await?;
    let entry_point = IEntryPoint::new(*ENTRYPOINT_4337, &provider);
    let deposit_tx = entry_point
        .depositTo(safe_address)
        .value(parse_ether("1")?)
        .send()
        .await?;
    let _ = deposit_tx.get_receipt().await?;
    println!("✓ Funded EntryPoint deposit for Safe");

    // Zero shares — migrate must fail before building the bundle.
    let zero_result = safe_account
        .transaction_erc4626_migrate(
            &wars_v1.to_string(),
            &wars_v2.to_string(),
            &U256::from(10u128.pow(18)).to_string(),
        )
        .await;
    assert!(
        zero_result.is_err(),
        "Expected migrate to fail with zero V1 shares"
    );
    let zero_err = zero_result.unwrap_err().to_string();
    assert!(
        zero_err.contains("Cannot migrate zero amount"),
        "Unexpected zero-share error: {zero_err}"
    );
    println!("✓ Migrate correctly failed with zero shares");

    // Fund Safe with wARS via impersonated transfer (storage layout is non-standard).
    let mut deposit_amount: U256 = parse_units("10", 18)?.into();
    let funder_balance = wars.balanceOf(wars_funder).call().await?;
    assert!(
        !funder_balance.is_zero(),
        "Expected wARS funder {wars_funder} to hold tokens on the fork"
    );
    if funder_balance < deposit_amount {
        deposit_amount = funder_balance / U256::from(2);
    }

    provider
        .anvil_set_balance(wars_funder, parse_ether("1")?)
        .await?;
    provider.anvil_impersonate_account(wars_funder).await?;
    let fund_tx = wars
        .transfer(safe_address, deposit_amount)
        .into_transaction_request()
        .from(wars_funder);
    provider
        .anvil_send_impersonated_transaction(fund_tx)
        .await?;
    provider.anvil_mine(Some(1), None).await?;
    provider
        .anvil_stop_impersonating_account(wars_funder)
        .await?;

    let safe_wars = wars.balanceOf(safe_address).call().await?;
    assert_eq!(safe_wars, deposit_amount, "Safe wARS funding failed");
    println!("✓ Funded Safe with {deposit_amount} wARS");

    // Deposit into Morpho V1 so the Safe holds V1 shares.
    provider
        .anvil_set_balance(safe_address, parse_ether("1")?)
        .await?;
    provider.anvil_impersonate_account(safe_address).await?;
    let approve_tx = wars
        .approve(wars_v1, deposit_amount)
        .into_transaction_request()
        .from(safe_address);
    provider
        .anvil_send_impersonated_transaction(approve_tx)
        .await?;
    provider.anvil_mine(Some(1), None).await?;

    let deposit_tx = v1_vault
        .deposit(deposit_amount, safe_address)
        .into_transaction_request()
        .from(safe_address);
    provider
        .anvil_send_impersonated_transaction(deposit_tx)
        .await?;
    provider.anvil_mine(Some(1), None).await?;
    provider
        .anvil_stop_impersonating_account(safe_address)
        .await?;

    let v1_shares_before = v1_vault.balanceOf(safe_address).call().await?;
    let v2_shares_before = v2_vault.balanceOf(safe_address).call().await?;
    assert!(
        !v1_shares_before.is_zero(),
        "Expected V1 shares after deposit"
    );
    println!("✓ Deposited into V1; shares={v1_shares_before}");

    // Asset mismatch — destination has a different underlying.
    let mismatch = safe_account
        .transaction_erc4626_migrate(
            &wars_v1.to_string(),
            &bad_dest_vault.to_string(),
            &v1_shares_before.to_string(),
        )
        .await;
    assert!(
        mismatch.is_err(),
        "Expected migrate to fail on asset mismatch"
    );
    let mismatch_err = mismatch.unwrap_err().to_string();
    assert!(
        mismatch_err.contains("Asset address mismatch"),
        "Unexpected mismatch error: {mismatch_err}"
    );
    println!("✓ Migrate correctly failed on asset mismatch");

    // Happy path: migrate all V1 shares into V2.
    safe_account
        .transaction_erc4626_migrate(
            &wars_v1.to_string(),
            &wars_v2.to_string(),
            &v1_shares_before.to_string(),
        )
        .await
        .expect("ERC-4626 migrate failed");
    println!("✓ Migrated V1 → V2");

    let v1_shares_after = v1_vault.balanceOf(safe_address).call().await?;
    let v2_shares_after = v2_vault.balanceOf(safe_address).call().await?;
    println!("V1 shares after: {v1_shares_after}");
    println!("V2 shares after: {v2_shares_after}");

    assert_eq!(
        v1_shares_after,
        U256::ZERO,
        "V1 shares should be zero after full migrate"
    );
    assert!(
        v2_shares_after > v2_shares_before,
        "V2 shares should increase after migrate"
    );

    Ok(())
}
