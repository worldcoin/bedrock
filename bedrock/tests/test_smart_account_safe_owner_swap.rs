use std::sync::Arc;

use alloy::{
    primitives::U256,
    providers::{ext::AnvilApi, ProviderBuilder},
    signers::local::PrivateKeySigner,
    sol,
};
use bedrock::{
    primitives::http_client::set_http_client,
    smart_account::{SafeSmartAccount, ENTRYPOINT_4337},
};

mod common;
use common::{deploy_safe, setup_anvil, AnvilBackedHttpClient, IEntryPoint};

sol! {
    /// Safe owner management interface
    #[sol(rpc)]
    interface IOwnerManager {
        function getOwners() external view returns (address[] memory);
        function isOwner(address owner) external view returns (bool);
        function swapOwner(address prevOwner, address oldOwner, address newOwner) external;
    }
}

/// End-to-end integration test for swapping Safe owners using tx_swap_safe_owner.
///
/// This test:
/// 1. Deploys a Safe with an initial owner
/// 2. Sets up a custom RPC client that intercepts sponsor requests
/// 3. Executes the owner swap using tx_swap_safe_owner
/// 4. Verifies the swap was executed successfully on-chain
#[tokio::test]
async fn test_safe_owner_swap_e2e() -> anyhow::Result<()> {
    let anvil = setup_anvil();

    // Setup initial and new owners
    let initial_owner_signer = PrivateKeySigner::random();
    let initial_owner = initial_owner_signer.address();
    let initial_owner_key_hex = hex::encode(initial_owner_signer.to_bytes());

    let new_owner_signer = PrivateKeySigner::random();
    let new_owner = new_owner_signer.address();

    println!("✓ Initial owner address: {initial_owner}");
    println!("✓ New owner address: {new_owner}");

    let provider = ProviderBuilder::new()
        .wallet(initial_owner_signer.clone())
        .connect_http(anvil.endpoint_url());

    // Deploy Safe with initial owner
    let safe_address = deploy_safe(&provider, initial_owner, U256::ZERO).await?;
    println!("✓ Deployed Safe at: {safe_address}");

    // Fund the Safe for gas
    provider
        .anvil_set_balance(safe_address, U256::from(1e18))
        .await?;

    // Fund EntryPoint deposit for the Safe
    let entry_point = IEntryPoint::new(*ENTRYPOINT_4337, &provider);
    let _deposit_tx = entry_point
        .depositTo(safe_address)
        .value(U256::from(1e18))
        .send()
        .await?;
    println!("✓ Funded Safe and EntryPoint deposit");

    // Verify initial owner
    let safe_contract = IOwnerManager::new(safe_address, &provider);
    let initial_owners = safe_contract.getOwners().call().await?;
    assert_eq!(initial_owners.len(), 1);
    assert_eq!(initial_owners[0], initial_owner);
    assert!(safe_contract.isOwner(initial_owner).call().await?);
    assert!(!safe_contract.isOwner(new_owner).call().await?);
    println!("✓ Verified initial owner");

    // Set up custom HTTP client that intercepts sponsor requests and executes on Anvil
    let anvil_http_client = AnvilBackedHttpClient {
        provider: provider.clone(),
    };
    set_http_client(Arc::new(anvil_http_client));

    // Create SafeSmartAccount instance
    let safe_account =
        SafeSmartAccount::new(initial_owner_key_hex, &safe_address.to_string())
            .expect("Failed to create SafeSmartAccount");

    // Execute the owner swap using tx_swap_safe_owner
    println!("→ Executing tx_swap_safe_owner to swap owners...");
    let tx_hash = safe_account
        .tx_swap_safe_owner(&initial_owner.to_string(), &new_owner.to_string())
        .await?;

    println!(
        "✓ Executed owner swap transaction: {}",
        tx_hash.to_hex_string()
    );

    // Verify the owner swap was successful
    let final_owners = safe_contract.getOwners().call().await?;
    assert_eq!(final_owners.len(), 1, "Should still have exactly 1 owner");
    assert_eq!(final_owners[0], new_owner, "Owner should be the new owner");

    // Verify ownership status
    assert!(
        !safe_contract.isOwner(initial_owner).call().await?,
        "Initial owner should no longer be an owner"
    );
    assert!(
        safe_contract.isOwner(new_owner).call().await?,
        "New owner should be an owner"
    );

    println!("✅ Successfully swapped Safe owner from {initial_owner} to {new_owner}");

    Ok(())
}
