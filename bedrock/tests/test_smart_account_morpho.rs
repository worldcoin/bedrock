//! E2E tests for Morpho vault deposit and withdraw operations.

use std::sync::Arc;

mod common;
use alloy::{
    primitives::U256,
    providers::{ext::AnvilApi, ProviderBuilder},
    signers::local::PrivateKeySigner,
    sol,
};
use common::{
    deploy_safe, set_erc20_balance_for_safe, setup_anvil, AnvilBackedHttpClient,
    IEntryPoint, IERC20,
};

use bedrock::{
    primitives::http_client::set_http_client,
    smart_account::{SafeSmartAccount, ENTRYPOINT_4337},
    transactions::contracts::{
        constants::{MORPHO_VAULT_WLD_TOKEN_ADDRESS, WLD_TOKEN_ADDRESS},
        morpho::MorphoToken,
    },
};

sol! {
    /// Morpho vault interface for checking balances
    #[sol(rpc)]
    interface IMorphoVault {
        function balanceOf(address account) external view returns (uint256);
    }
}

#[tokio::test]
async fn test_morpho_deposit_and_withdraw_wld() -> anyhow::Result<()> {
    // 1) Spin up anvil fork of World Chain mainnet
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

    // 3) Deploy Safe with 4337 module enabled
    let safe_address = deploy_safe(&provider, owner, U256::ZERO).await?;
    println!("✓ Deployed Safe at: {safe_address}");

    // 4) Fund EntryPoint deposit for Safe (for gas)
    let entry_point = IEntryPoint::new(*ENTRYPOINT_4337, &provider);
    let deposit_tx = entry_point
        .depositTo(safe_address)
        .value(U256::from(1e18 as u64))
        .send()
        .await?;
    let _ = deposit_tx.get_receipt().await?;
    println!("✓ Funded EntryPoint deposit for Safe");

    // 5) Give Safe some WLD balance to deposit
    let deposit_amount = U256::from(10u128.pow(18)); // 1 WLD
    let starting_balance = deposit_amount * U256::from(10u8); // 10 WLD
    set_erc20_balance_for_safe(
        &provider,
        WLD_TOKEN_ADDRESS,
        safe_address,
        starting_balance,
    )
    .await?;

    let wld = IERC20::new(WLD_TOKEN_ADDRESS, &provider);
    let before_safe_wld = wld.balanceOf(safe_address).call().await?;
    println!("✓ Safe WLD balance before deposit: {before_safe_wld}");
    assert_eq!(before_safe_wld, starting_balance);

    // 6) Check Morpho vault share balance before deposit
    let morpho_vault = IMorphoVault::new(MORPHO_VAULT_WLD_TOKEN_ADDRESS, &provider);
    let before_vault_shares = morpho_vault.balanceOf(safe_address).call().await?;
    println!("✓ Safe Morpho vault shares before deposit: {before_vault_shares}");

    // 7) Install mocked HTTP client that routes calls to Anvil
    let client = AnvilBackedHttpClient {
        provider: provider.clone(),
    };
    set_http_client(Arc::new(client));

    // 8) Create and execute Morpho deposit
    let safe_account = SafeSmartAccount::new(owner_key_hex, &safe_address.to_string())?;

    let _user_op_hash = safe_account
        .transaction_morpho_deposit(MorphoToken::WLD, &deposit_amount.to_string())
        .await
        .expect("Morpho deposit failed");

    println!("✓ Morpho deposit executed");

    // 9) Verify balances after deposit
    let after_deposit_wld = wld.balanceOf(safe_address).call().await?;
    let after_deposit_shares = morpho_vault.balanceOf(safe_address).call().await?;

    println!("✓ Safe WLD balance after deposit: {after_deposit_wld}");
    println!("✓ Safe Morpho vault shares after deposit: {after_deposit_shares}");

    // WLD balance should have decreased by deposit amount
    assert_eq!(
        after_deposit_wld,
        before_safe_wld - deposit_amount,
        "WLD balance did not decrease by deposit amount"
    );

    // Vault shares should have increased (exact amount depends on exchange rate)
    assert!(
        after_deposit_shares > before_vault_shares,
        "Morpho vault shares did not increase after deposit"
    );

    // ==========================================================================
    // WITHDRAW
    // ==========================================================================

    // 10) Withdraw half the deposited amount
    let withdraw_amount = deposit_amount / U256::from(2u8); // 0.5 WLD

    let _user_op_hash = safe_account
        .transaction_morpho_withdraw(MorphoToken::WLD, &withdraw_amount.to_string())
        .await
        .expect("Morpho withdraw failed");

    println!("✓ Morpho withdraw executed");

    // 11) Verify balances after withdraw
    let after_withdraw_wld = wld.balanceOf(safe_address).call().await?;
    let after_withdraw_shares = morpho_vault.balanceOf(safe_address).call().await?;

    println!("✓ Safe WLD balance after withdraw: {after_withdraw_wld}");
    println!("✓ Safe Morpho vault shares after withdraw: {after_withdraw_shares}");

    // WLD balance should have increased after withdraw
    assert!(
        after_withdraw_wld > after_deposit_wld,
        "WLD balance should have increased after withdraw"
    );

    // Vault shares should have decreased after withdraw
    assert!(
        after_withdraw_shares < after_deposit_shares,
        "Vault shares should have decreased after withdraw"
    );

    Ok(())
}
