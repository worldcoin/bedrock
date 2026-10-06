//! E2E test for migrating from USDVault to ERC4626 vault using Morpho as example.
use std::sync::Arc;

mod common;
use alloy::{
    network::Ethereum,
    primitives::{
        keccak256,
        utils::{parse_ether, parse_units},
        Address, U256,
    },
    providers::{ext::AnvilApi, Provider, ProviderBuilder},
    signers::local::PrivateKeySigner,
    sol,
};
use common::{deploy_safe, set_erc20_balance_for_safe, setup_anvil, IERC20};

use std::str::FromStr;

use bedrock::{
    primitives::http_client::set_http_client, primitives::HexEncodedData,
    smart_account::SafeSmartAccount, test_utils::AnvilBackedHttpClient,
    transactions::contracts::usd_legacy_vault::USD_LEGACY_VAULT_ADDRESSES,
    transactions::TransactionError,
};

use crate::common::{
    set_address_verified_until_for_account, set_erc20_balance_with_slot,
};

sol! {
    #[sol(rpc)]
    interface UsdVaultLimits {
        function LIMIT_WITHDRAWALS_TO_DEPOSITS() external view returns (bool);
    }
}

/// Storage slot of the `sDAIBalances` mapping in the legacy USD vaults.
const SDAI_BALANCES_SLOT: u64 = 1;

/// Sets `mapping(address => uint256)` entry `account` at `mapping_slot` in `contract`.
async fn set_mapping_balance<P>(
    provider: &P,
    contract: Address,
    account: Address,
    mapping_slot: u64,
    value: U256,
) -> anyhow::Result<()>
where
    P: Provider + AnvilApi<Ethereum>,
{
    let mut padded = [0u8; 64];
    padded[12..32].copy_from_slice(account.as_slice());
    padded[32..64].copy_from_slice(&U256::from(mapping_slot).to_be_bytes::<32>());
    let slot = U256::from_be_bytes(keccak256(padded).into());
    provider
        .anvil_set_storage_at(contract, slot, value.into())
        .await?;
    Ok(())
}

/// Runs the migration through either the unified `transaction_erc4626_migrate` entry point or
/// the deprecated `transaction_usd_legacy_vault_migrate` wrapper.
async fn migrate(
    account: &SafeSmartAccount,
    use_unified_entry_point: bool,
    from_vault: &str,
    to_vault: &str,
) -> Result<HexEncodedData, TransactionError> {
    if use_unified_entry_point {
        account
            .transaction_erc4626_migrate(from_vault, to_vault)
            .await
    } else {
        account
            .transaction_usd_legacy_vault_migrate(from_vault, to_vault)
            .await
    }
}

#[tokio::test]
async fn test_usd_vault_migration() -> anyhow::Result<()> {
    let usdc_address =
        Address::from_str("0x79A02482A880bCE3F13e09Da970dC34db4CD24d1").unwrap();
    let sdai_address =
        Address::from_str("0x859DBE24b90C9f2f7742083d3cf59cA41f55Be5d").unwrap();
    let morpho_vault_address =
        Address::from_str("0xb1E80387EbE53Ff75a89736097D34dC8D9E9045B").unwrap();
    let bad_morpho_vault_address =
        Address::from_str("0x348831b46876d3dF2Db98BdEc5E3B4083329Ab9f").unwrap();

    let owner_signer = PrivateKeySigner::random();
    let owner_key_hex = hex::encode(owner_signer.to_bytes());
    let owner = owner_signer.address();

    let anvil = setup_anvil();
    let provider = ProviderBuilder::new()
        .wallet(owner_signer.clone())
        .connect_http(anvil.endpoint_url());
    let client = AnvilBackedHttpClient::new(provider.clone());
    set_http_client(Arc::new(client));

    // Exercise every legacy USD vault deployment through the deprecated wrapper first, then the
    // unified entry point, against the same fork (the global HTTP client can only be set once
    // per process).
    for (deploy_nonce, (usd_vault_address, use_unified_entry_point)) in
        USD_LEGACY_VAULT_ADDRESSES
            .into_iter()
            .flat_map(|vault| [(vault, false), (vault, true)])
            .enumerate()
    {
        let usdc = IERC20::new(usdc_address, &provider);
        let sdai = IERC20::new(sdai_address, &provider);
        let morpho_vault = IERC20::new(morpho_vault_address, &provider);

        let safe_address =
            deploy_safe(&provider, owner, U256::from(deploy_nonce)).await?;
        println!("✓ Deployed Safe at: {safe_address}");

        let safe_account = SafeSmartAccount::from_private_key_hex(
            owner_key_hex.clone(),
            &safe_address.to_string(),
        )?;

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

        // Test migration with zero sDAI balance - should fail
        let result = migrate(
            &safe_account,
            use_unified_entry_point,
            &usd_vault_address.to_string(),
            &morpho_vault_address.to_string(),
        )
        .await;

        assert!(
            result.is_err(),
            "Expected migration to fail with zero sDAI balance"
        );
        let error_message = result.unwrap_err().to_string();
        assert!(
            error_message.contains("Cannot migrate with zero sDAI balance"),
            "Expected error message to contain 'Cannot migrate with zero sDAI balance', got: {}",
            error_message
        );
        println!("✓ Migration correctly failed with zero sDAI balance error");

        // Now set up sDAI balance for actual migration test
        set_erc20_balance_for_safe(&provider, sdai_address, safe_address, sdai_amount)
            .await?;

        // Some deployments only let a user redeem what they deposited through the vault, tracked
        // in `sDAIBalances`. Credit the Safe as if it had deposited the sDAI itself.
        if UsdVaultLimits::new(usd_vault_address, &provider)
            .LIMIT_WITHDRAWALS_TO_DEPOSITS()
            .call()
            .await?
        {
            set_mapping_balance(
                &provider,
                usd_vault_address,
                safe_address,
                SDAI_BALANCES_SLOT,
                sdai_amount,
            )
            .await?;
        }

        let sdai_balance_before = sdai.balanceOf(safe_address).call().await?;
        println!("sDAI balance before migration: {sdai_balance_before}");

        let morpho_shares_before = morpho_vault.balanceOf(safe_address).call().await?;
        println!("MorphoVault shares before migration: {morpho_shares_before}");

        // Test migration with bad vault address - should fail
        let result = migrate(
            &safe_account,
            use_unified_entry_point,
            &usd_vault_address.to_string(),
            &bad_morpho_vault_address.to_string(),
        )
        .await;

        assert!(
            result.is_err(),
            "Expected migration to fail with bad vault address"
        );
        let error_message = result.unwrap_err().to_string();
        assert!(
            error_message.contains("Asset address mismatch between USDVault and ERC-4626 Vault"),
            "Expected error message to contain 'Asset address mismatch between USDVault and ERC-4626 Vault', got: {}",
            error_message
        );
        println!("✓ Migration correctly failed with asset address mismatch error");

        // Now perform successful migration
        migrate(
            &safe_account,
            use_unified_entry_point,
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
    }

    Ok(())
}
