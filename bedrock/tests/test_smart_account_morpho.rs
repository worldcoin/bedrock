//! E2E tests for ERC4626 vault deposit operations using Morpho as example.

use std::sync::Arc;

mod common;
use alloy::{
    primitives::U256,
    providers::{ext::AnvilApi, ProviderBuilder},
    signers::local::PrivateKeySigner,
    sol,
};
use common::{deploy_safe, set_erc20_balance_for_safe, setup_anvil, IERC20};

use bedrock::{
    primitives::{http_client::set_http_client, Network},
    smart_account::{SafeSmartAccount, ENTRYPOINT_4337},
    test_utils::{AnvilBackedHttpClient, IEntryPoint},
    transactions::contracts::{
        constants::{MORPHO_VAULT_WLD_TOKEN_ADDRESS, WLD_TOKEN_ADDRESS},
        erc4626::Erc4626Vault,
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
async fn test_erc4626_deposit_wld() -> anyhow::Result<()> {
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

    // 7) Install HTTP client that routes calls to Anvil (no mocking needed)
    let client = AnvilBackedHttpClient::new(provider.clone());
    set_http_client(Arc::new(client));

    // 8) Create and execute ERC4626 deposit using the generic implementation
    let safe_account = SafeSmartAccount::new(owner_key_hex, &safe_address.to_string())?;

    // First create the transaction to log call data for unit tests
    let rpc_client = bedrock::transactions::rpc::get_rpc_client().unwrap();
    let erc4626_deposit = Erc4626Vault::deposit(
        rpc_client,
        Network::WorldChain,
        MORPHO_VAULT_WLD_TOKEN_ADDRESS,
        deposit_amount,
        safe_address,
        [0u8; 10], // metadata
    )
    .await
    .expect("Failed to create ERC4626 deposit");

    // Log the call data for hardcoding in unit tests
    println!("🔍 ERC4626 Deposit Call Data for Unit Tests:");
    println!(
        "🔍   Call Data: 0x{}",
        hex::encode(&erc4626_deposit.call_data)
    );
    println!("🔍   User wallet address: 0x{}", safe_address);

    // Now execute using the high-level API
    let _user_op_hash = safe_account
        .transaction_erc4626_deposit(
            &MORPHO_VAULT_WLD_TOKEN_ADDRESS.to_string(),
            &deposit_amount.to_string(),
        )
        .await
        .expect("ERC4626 deposit failed");

    println!("✓ ERC4626 deposit executed");

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

    Ok(())
}
