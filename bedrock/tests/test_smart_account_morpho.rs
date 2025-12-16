//! E2E tests for ERC4626 vault deposit operations using Morpho as example.

use std::sync::Arc;

mod common;
use alloy::{
    primitives::{Address, U256},
    providers::{ext::AnvilApi, ProviderBuilder},
    signers::local::PrivateKeySigner,
    sol,
};
use common::{deploy_safe, set_erc20_balance_for_safe, setup_anvil, IERC20};
use std::str::FromStr;

use bedrock::{
    primitives::{http_client::set_http_client, Network},
    smart_account::{Is4337Encodable, SafeSmartAccount, ENTRYPOINT_4337},
    test_utils::{AnvilBackedHttpClient, IEntryPoint},
    transactions::contracts::erc4626::Erc4626Vault,
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
    // Define addresses for the test
    let wld_token_address =
        Address::from_str("0x2cfc85d8e48f8eab294be644d9e25c3030863003").unwrap();
    let morpho_vault_wld_token_address =
        Address::from_str("0x348831b46876d3dF2Db98BdEc5E3B4083329Ab9f").unwrap();

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
        wld_token_address,
        safe_address,
        starting_balance,
    )
    .await?;

    let wld = IERC20::new(wld_token_address, &provider);
    let before_safe_wld = wld.balanceOf(safe_address).call().await?;
    println!("✓ Safe WLD balance before deposit: {before_safe_wld}");
    assert_eq!(before_safe_wld, starting_balance);

    // 6) Check Morpho vault share balance before deposit
    let morpho_vault = IMorphoVault::new(morpho_vault_wld_token_address, &provider);
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
        morpho_vault_wld_token_address,
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
            &morpho_vault_wld_token_address.to_string(),
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

    // 10) Test withdraw operation
    println!("\n--- Testing ERC4626 Withdraw ---");

    // Calculate a partial withdrawal amount (half of what we deposited)
    let withdraw_asset_amount = deposit_amount / U256::from(2u8); // 0.5 WLD

    // First create the transaction to log call data for unit tests
    let erc4626_withdraw = Erc4626Vault::withdraw(
        rpc_client,
        Network::WorldChain,
        morpho_vault_wld_token_address,
        withdraw_asset_amount,
        safe_address, // user_address (both receiver and owner)
        [0u8; 10],    // metadata
    )
    .await
    .expect("Failed to create ERC4626 withdraw");

    // Log the call data for hardcoding in unit tests
    println!("🔍 ERC4626 Withdraw Call Data for Unit Tests:");
    println!(
        "🔍   Call Data: 0x{}",
        hex::encode(&erc4626_withdraw.call_data)
    );
    println!("🔍   Withdraw Asset Amount: {}", withdraw_asset_amount);

    // Execute the withdraw transaction directly using the struct
    let _user_op_hash_withdraw = erc4626_withdraw
        .sign_and_execute(
            &safe_account,
            Network::WorldChain,
            None,
            None,
            bedrock::transactions::RpcProviderName::Any,
        )
        .await
        .expect("ERC4626 withdraw failed");

    println!("✓ ERC4626 withdraw executed");

    // 11) Verify balances after withdraw
    let after_withdraw_wld = wld.balanceOf(safe_address).call().await?;
    let after_withdraw_shares = morpho_vault.balanceOf(safe_address).call().await?;

    println!("✓ Safe WLD balance after withdraw: {after_withdraw_wld}");
    println!("✓ Safe Morpho vault shares after withdraw: {after_withdraw_shares}");

    // WLD balance should have increased from withdrawal
    assert!(
        after_withdraw_wld > after_deposit_wld,
        "WLD balance did not increase after withdrawal"
    );

    // Vault shares should have decreased
    assert!(
        after_withdraw_shares < after_deposit_shares,
        "Morpho vault shares did not decrease after withdrawal"
    );

    // 12) Test redeem operation (redeem a small portion of remaining shares)
    println!("\n--- Testing ERC4626 Redeem ---");

    // Calculate a small portion of remaining shares to redeem (25% of current shares)
    let redeem_share_amount = after_withdraw_shares / U256::from(4u8); // 25% of remaining shares

    // First create the transaction to log call data for unit tests
    let erc4626_redeem = Erc4626Vault::redeem(
        rpc_client,
        Network::WorldChain,
        morpho_vault_wld_token_address,
        redeem_share_amount,
        safe_address, // user_address (both receiver and owner)
        [0u8; 10],    // metadata
    )
    .await
    .expect("Failed to create ERC4626 redeem");

    // Log the call data for hardcoding in unit tests
    println!("🔍 ERC4626 Redeem Call Data for Unit Tests:");
    println!(
        "🔍   Call Data: 0x{}",
        hex::encode(&erc4626_redeem.call_data)
    );
    println!("🔍   Redeem Share Amount: {}", redeem_share_amount);

    // Execute the redeem transaction directly using the struct
    let _user_op_hash_redeem = erc4626_redeem
        .sign_and_execute(
            &safe_account,
            Network::WorldChain,
            None,
            None,
            bedrock::transactions::RpcProviderName::Any,
        )
        .await
        .expect("ERC4626 redeem failed");

    println!("✓ ERC4626 redeem executed");

    // 13) Verify balances after redeem
    let after_redeem_wld = wld.balanceOf(safe_address).call().await?;
    let after_redeem_shares = morpho_vault.balanceOf(safe_address).call().await?;

    println!("✓ Safe WLD balance after redeem: {after_redeem_wld}");
    println!("✓ Safe Morpho vault shares after redeem: {after_redeem_shares}");

    // WLD balance should have increased from redeem
    assert!(
        after_redeem_wld > after_withdraw_wld,
        "WLD balance did not increase after redeem"
    );

    // Vault shares should have decreased
    assert!(
        after_redeem_shares < after_withdraw_shares,
        "Morpho vault shares did not decrease after redeem"
    );

    // 14) Test withdraw with share-limited scenario (should switch to redeem internally)
    println!("\n--- Testing ERC4626 Withdraw (Share-Limited) ---");

    // Request more assets than we have shares for - this should trigger the share-limited path
    // and cause withdraw to internally use redeem
    let remaining_shares = after_redeem_shares;
    let large_withdraw_amount = deposit_amount * U256::from(10u8); // Request way more than we have

    // Create the withdraw transaction - this should detect share limitation and switch to redeem
    let erc4626_withdraw_limited = Erc4626Vault::withdraw(
        rpc_client,
        Network::WorldChain,
        morpho_vault_wld_token_address,
        large_withdraw_amount, // Request more than available
        safe_address,
        [0u8; 10], // metadata
    )
    .await
    .expect("Failed to create ERC4626 withdraw (share-limited)");

    // Verify that the call data uses redeem function selector (proving the logic switch worked)
    // redeem(uint256,address,address) selector: 0xba087652
    // withdraw(uint256,address,address) selector: 0xb460af94
    let call_data_hex = hex::encode(&erc4626_withdraw_limited.call_data);
    assert!(
        call_data_hex.starts_with("ba087652"),
        "Withdraw should have switched to redeem when share-limited. Call data starts with: {}",
        &call_data_hex[..8]
    );
    println!("✓ Withdraw correctly switched to redeem (share-limited logic verified)");

    // Log the call data
    println!("🔍 ERC4626 Withdraw (Share-Limited) Call Data:");
    println!(
        "🔍   Call Data: 0x{}",
        hex::encode(&erc4626_withdraw_limited.call_data)
    );
    println!("🔍   Requested Asset Amount: {}", large_withdraw_amount);
    println!("🔍   Available Shares: {}", remaining_shares);

    // Execute the withdraw transaction (which internally uses redeem)
    let _user_op_hash_withdraw_limited = erc4626_withdraw_limited
        .sign_and_execute(
            &safe_account,
            Network::WorldChain,
            None,
            None,
            bedrock::transactions::RpcProviderName::Any,
        )
        .await
        .expect("ERC4626 withdraw (share-limited) failed");

    println!("✓ ERC4626 withdraw (share-limited) executed");

    // 15) Verify all assets have been withdrawn
    let final_wld = wld.balanceOf(safe_address).call().await?;
    let final_shares = morpho_vault.balanceOf(safe_address).call().await?;

    println!("✓ Final Safe WLD balance: {}", final_wld);
    println!("✓ Final Safe Morpho vault shares: {}", final_shares);

    // All vault shares should be withdrawn (may have small rounding remainder, but should be near zero)
    assert!(
        final_shares < U256::from(1000u64), // Allow for small rounding remainders
        "Not all vault shares were withdrawn. Remaining: {}",
        final_shares
    );

    // WLD balance should have increased from the final withdrawal
    assert!(
        final_wld > after_redeem_wld,
        "WLD balance did not increase after final withdrawal"
    );

    println!("\n--- Final Summary ---");
    println!("Initial WLD balance: {}", starting_balance);
    println!("After deposit WLD balance: {}", after_deposit_wld);
    println!("After withdraw WLD balance: {}", after_withdraw_wld);
    println!("After redeem WLD balance: {}", after_redeem_wld);
    println!("Final WLD balance: {}", final_wld);
    println!("Final vault shares: {} (should be 0)", final_shares);

    Ok(())
}
