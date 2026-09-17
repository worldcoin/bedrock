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
        function previewRedeem(uint256 shares) external view returns (uint256 assets);
        function previewDeposit(uint256 assets) external view returns (uint256 shares);
        function maxRedeem(address owner) external view returns (uint256 maxShares);
    }
}

/// Morpho Re7 WARS (World Chain).
const WARS_TOKEN: &str = "0x0DC4F92879B7670e5f4e4e6e3c801D229129D90D";
const WARS_V1_VAULT: &str = "0x1C94c7A2c71ECF13104c31F49d5138EDb099D25D";
const WARS_V2_VAULT: &str = "0x4047dB25Fd6EcD07d72CA44adf3a2A44dE6DE084";
/// Morpho WLD vault — different underlying asset, for mismatch check.
const WLD_MORPHO_VAULT: &str = "0x348831b46876d3dF2Db98BdEc5E3B4083329Ab9f";
/// Candidate wARS holders for impersonated funding (first with enough balance wins).
const WARS_FUNDER_CANDIDATES: &[&str] = &[
    // Morpho / Re7-related holder that historically funded this canary
    "0x0D0c99daF35DaF2CFC50cF6a437E1c49fDf4F167",
    // V1 vault itself (sometimes holds idle underlying)
    "0x1C94c7A2c71ECF13104c31F49d5138EDb099D25D",
    // V2 vault idle assets
    "0x4047dB25Fd6EcD07d72CA44adf3a2A44dE6DE084",
];

#[tokio::test]
async fn test_morpho_wars_v1_to_v2_migration() -> anyhow::Result<()> {
    let wars_token = Address::from_str(WARS_TOKEN)?;
    let wars_v1 = Address::from_str(WARS_V1_VAULT)?;
    let wars_v2 = Address::from_str(WARS_V2_VAULT)?;
    let bad_dest_vault = Address::from_str(WLD_MORPHO_VAULT)?;

    let owner_signer = PrivateKeySigner::random();
    let owner_key_hex = hex::encode(owner_signer.to_bytes());
    let owner = owner_signer.address();

    // Tip fork (same as other World Chain e2e). Pinning a historical block made CI RPCs
    // return `invalid block range` on Safe deploy (`createProxyWithNonce`).
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
        .transaction_erc4626_migrate(&wars_v1.to_string(), &wars_v2.to_string())
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
    let requested_amount: U256 = parse_units("10", 18)?.into();
    let min_funder_balance: U256 = parse_units("1", 18)?.into();
    let mut wars_funder = None;
    let mut funder_balance = U256::ZERO;
    for candidate in WARS_FUNDER_CANDIDATES {
        let address = Address::from_str(candidate)?;
        let balance = wars.balanceOf(address).call().await?;
        if balance >= min_funder_balance {
            wars_funder = Some(address);
            funder_balance = balance;
            break;
        }
    }
    let wars_funder = wars_funder.ok_or_else(|| {
        anyhow::anyhow!(
            "No wARS funder candidate held >= {min_funder_balance} on the fork tip"
        )
    })?;
    let deposit_amount = requested_amount.min(funder_balance / U256::from(2));
    assert!(
        !deposit_amount.is_zero(),
        "Resolved funder {wars_funder} balance too small to migrate"
    );
    println!("✓ Using wARS funder {wars_funder} (balance={funder_balance})");

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
        .transaction_erc4626_migrate(&wars_v1.to_string(), &bad_dest_vault.to_string())
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

    // Expected post-migrate balances from the same build-time formulas as `migrate`
    // (`shares = min(balanceOf, maxRedeem)`). Morpho V1 may report maxRedeem < balance.
    let max_redeem = v1_vault.maxRedeem(safe_address).call().await?;
    let redeemable_shares = v1_shares_before.min(max_redeem);
    assert!(
        !redeemable_shares.is_zero(),
        "expected non-zero redeemable V1 shares (balance={v1_shares_before}, maxRedeem={max_redeem})"
    );
    println!(
        "✓ Redeemable V1 shares={redeemable_shares} (balance={v1_shares_before}, maxRedeem={max_redeem})"
    );

    let preview_assets = v1_vault.previewRedeem(redeemable_shares).call().await?;
    let haircut_factor =
        U256::from(1_000_000_000_000_000_000u64) - U256::from(300_000_000_000_000u64);
    let deposit_assets = preview_assets
        .checked_mul(haircut_factor)
        .and_then(|v| v.checked_div(U256::from(1_000_000_000_000_000_000u64)))
        .expect("deposit haircut overflow");
    let expected_v2_shares = v2_vault.previewDeposit(deposit_assets).call().await?;
    let expected_wars_dust = preview_assets.saturating_sub(deposit_assets);
    let expected_v1_remaining = v1_shares_before.saturating_sub(redeemable_shares);
    let wars_before_migrate = wars.balanceOf(safe_address).call().await?;
    assert!(
        !expected_v2_shares.is_zero(),
        "destination previewDeposit should be non-zero before migrate"
    );

    // Happy path: migrate redeemable V1 shares into V2.
    safe_account
        .transaction_erc4626_migrate(&wars_v1.to_string(), &wars_v2.to_string())
        .await
        .expect("ERC-4626 migrate failed");
    println!("✓ Migrated V1 → V2");

    let v1_shares_after = v1_vault.balanceOf(safe_address).call().await?;
    let v2_shares_after = v2_vault.balanceOf(safe_address).call().await?;
    let wars_after_migrate = wars.balanceOf(safe_address).call().await?;
    let v2_shares_received = v2_shares_after.saturating_sub(v2_shares_before);
    let wars_dust_received = wars_after_migrate.saturating_sub(wars_before_migrate);
    println!("V1 shares after: {v1_shares_after} (expected remaining={expected_v1_remaining})");
    println!("V2 shares after: {v2_shares_after} (received={v2_shares_received})");
    println!(
        "Safe wARS after: {wars_after_migrate} (dust received={wars_dust_received}, expected≈{expected_wars_dust})"
    );

    assert_eq!(
        v1_shares_after, expected_v1_remaining,
        "V1 remaining shares should be balance - min(balance, maxRedeem)"
    );
    assert_eq!(
        v2_shares_received, expected_v2_shares,
        "V2 shares received should match destination previewDeposit(deposit_assets)"
    );
    // Haircut leaves non-deposited redeem proceeds on the Safe. Live redeem can yield
    // slightly more than build-time previewRedeem, so dust is at least the haircut remainder.
    assert!(
        wars_dust_received >= expected_wars_dust,
        "redeemed wARS not deposited should remain in the Safe (got {wars_dust_received}, expected at least {expected_wars_dust})"
    );

    Ok(())
}
