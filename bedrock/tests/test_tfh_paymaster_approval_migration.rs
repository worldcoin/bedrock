//! End-to-end coverage for [`TfhPaymasterApprovalMigration`] against a real chain.
//!
//! Proves the two conditions that gate a top-up — the Safe holds the token, and
//! its allowance has fallen below half the target — and that the paymaster
//! draining the allowance is what brings the migration back.

use std::sync::Arc;

mod common;
use alloy::{
    primitives::{Address, U256},
    providers::{ext::AnvilApi, Provider, ProviderBuilder},
    signers::local::PrivateKeySigner,
};
use common::{deploy_safe, set_erc20_balance_with_slot, setup_anvil, IERC20};

use bedrock::{
    migration::wallet::tfh_paymaster_approval::TfhPaymasterApprovalMigration,
    migration::{WalletMigration, WalletMigrationResult},
    primitives::{
        config::{set_config, BedrockEnvironment, Os},
        http_client::set_http_client,
    },
    smart_account::{SafeSmartAccount, ENTRYPOINT_4337},
    test_utils::{AnvilBackedHttpClient, IEntryPoint},
    transactions::contracts::worldchain::{
        TFH_PAYMASTER_ADDRESS, USDC_ADDRESS, WLD_ADDRESS,
    },
};

/// 100 WLD, the target allowance.
fn wld_target() -> U256 {
    U256::from(100u64) * U256::from(10u64).pow(U256::from(18))
}

/// 30 USDC, the target allowance.
fn usdc_target() -> U256 {
    U256::from(30_000_000u64)
}

/// Storage slot of WLD's balances mapping.
const WLD_BALANCES_SLOT: u64 = 0;

/// Storage slot of USDC's balances mapping. USDC on World Chain is Circle's
/// `FiatToken`, which keeps them at slot 9 rather than 0.
const USDC_BALANCES_SLOT: u64 = 9;

/// Funds `token` for the Safe and proves the write landed.
///
/// Asserting the readback turns a wrong storage layout into a clear failure
/// rather than a confusing one downstream.
async fn fund<P>(
    provider: &P,
    token: Address,
    safe: Address,
    amount: U256,
    balances_slot: u64,
) -> anyhow::Result<()>
where
    P: Provider<alloy::network::Ethereum> + AnvilApi<alloy::network::Ethereum>,
{
    set_erc20_balance_with_slot(
        provider,
        token,
        safe,
        amount,
        U256::from(balances_slot),
    )
    .await?;
    let observed = IERC20::new(token, provider).balanceOf(safe).call().await?;
    assert_eq!(
        observed, amount,
        "balance write did not land for {token}; its balances mapping is not at \
         slot {balances_slot}"
    );
    Ok(())
}

/// Has the paymaster pull `amount` out of the Safe, draining its allowance the
/// way it does in production.
async fn paymaster_spends(
    endpoint: &reqwest::Url,
    token: Address,
    safe: Address,
    amount: U256,
) -> anyhow::Result<()> {
    // No wallet filler: an impersonated sender must go out unsigned, or the
    // provider tries to find a signing credential for the paymaster.
    let provider = ProviderBuilder::new().connect_http(endpoint.clone());

    provider
        .anvil_set_balance(TFH_PAYMASTER_ADDRESS, U256::from(1e18 as u64))
        .await?;
    provider
        .anvil_impersonate_account(TFH_PAYMASTER_ADDRESS)
        .await?;

    let receipt = IERC20::new(token, &provider)
        .transferFrom(safe, TFH_PAYMASTER_ADDRESS, amount)
        .from(TFH_PAYMASTER_ADDRESS)
        .send()
        .await?
        .get_receipt()
        .await?;
    assert!(
        receipt.status(),
        "the paymaster's transferFrom should succeed"
    );

    provider
        .anvil_stop_impersonating_account(TFH_PAYMASTER_ADDRESS)
        .await?;
    Ok(())
}

#[tokio::test]
async fn test_tfh_paymaster_approval_migration_full_flow() -> anyhow::Result<()> {
    // 1) Staging: `WalletMigrationController` only registers this off
    //    production, and `set_erc20_balance_with_slot` needs a config anyway.
    let root = std::env::temp_dir()
        .join(format!("bedrock-tfh-paymaster-it-{}", std::process::id()));
    set_config(
        BedrockEnvironment::Staging,
        Os::Ios,
        root.to_string_lossy().into_owned(),
    )?;

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

    // 2) A Safe with the 4337 module, funded at the EntryPoint so its userOps
    //    can be executed.
    let safe_address = deploy_safe(&provider, owner, U256::ZERO).await?;
    let entry_point = IEntryPoint::new(*ENTRYPOINT_4337, &provider);
    entry_point
        .depositTo(safe_address)
        .value(U256::from(1e18 as u64))
        .send()
        .await?
        .get_receipt()
        .await?;

    set_http_client(Arc::new(AnvilBackedHttpClient::new(provider.clone())));

    let safe_account = Arc::new(SafeSmartAccount::from_private_key_hex(
        owner_key_hex,
        &safe_address.to_string(),
    )?);
    let migration = TfhPaymasterApprovalMigration::new(safe_account);
    assert_eq!(migration.migration_id(), "wallet.tfh_paymaster.approval.v1");

    let wld = IERC20::new(WLD_ADDRESS, &provider);
    let usdc = IERC20::new(USDC_ADDRESS, &provider);

    // 3) No balances: nothing to approve, even though both allowances are zero.
    //    A wallet with no tokens never needs the paymaster.
    assert_eq!(
        wld.allowance(safe_address, TFH_PAYMASTER_ADDRESS)
            .call()
            .await?,
        U256::ZERO
    );
    assert!(
        migration.end_state_holds().await?,
        "a Safe holding neither token has nothing to approve"
    );
    assert!(matches!(
        migration.reconcile().await?,
        WalletMigrationResult::Converged
    ));

    // 4) WLD only. The gap is per-token, so USDC must stay untouched.
    fund(
        &provider,
        WLD_ADDRESS,
        safe_address,
        wld_target(),
        WLD_BALANCES_SLOT,
    )
    .await?;
    assert!(!migration.end_state_holds().await?);
    assert!(matches!(
        migration.reconcile().await?,
        WalletMigrationResult::Submitted { .. }
    ));
    assert_eq!(
        wld.allowance(safe_address, TFH_PAYMASTER_ADDRESS)
            .call()
            .await?,
        wld_target(),
        "WLD should be approved for exactly the target, not uint256::max"
    );
    assert_eq!(
        usdc.allowance(safe_address, TFH_PAYMASTER_ADDRESS)
            .call()
            .await?,
        U256::ZERO,
        "USDC is not held, so it must not have been approved"
    );
    assert!(migration.end_state_holds().await?);

    // 5) Now USDC too. WLD is already at target, so only USDC is submitted.
    fund(
        &provider,
        USDC_ADDRESS,
        safe_address,
        usdc_target(),
        USDC_BALANCES_SLOT,
    )
    .await?;
    assert!(!migration.end_state_holds().await?);
    assert!(matches!(
        migration.reconcile().await?,
        WalletMigrationResult::Submitted { .. }
    ));
    assert_eq!(
        usdc.allowance(safe_address, TFH_PAYMASTER_ADDRESS)
            .call()
            .await?,
        usdc_target(),
        "USDC should be approved for exactly 30 USDC"
    );
    assert_eq!(
        wld.allowance(safe_address, TFH_PAYMASTER_ADDRESS)
            .call()
            .await?,
        wld_target(),
        "the WLD allowance was already at target and must be left alone"
    );

    // 6) The paymaster spends a little WLD. Still at or above half, so no work.
    let ten_wld = U256::from(10u64) * U256::from(10u64).pow(U256::from(18));
    paymaster_spends(&anvil.endpoint_url(), WLD_ADDRESS, safe_address, ten_wld).await?;
    assert_eq!(
        wld.allowance(safe_address, TFH_PAYMASTER_ADDRESS)
            .call()
            .await?,
        wld_target() - ten_wld
    );
    assert!(
        migration.end_state_holds().await?,
        "90 WLD is still above half the target, so nothing is topped up"
    );

    // 7) It spends past half. That reopens the gap and the top-up restores the
    //    full target.
    let fifty_wld = U256::from(50u64) * U256::from(10u64).pow(U256::from(18));
    paymaster_spends(&anvil.endpoint_url(), WLD_ADDRESS, safe_address, fifty_wld)
        .await?;
    let drained = wld
        .allowance(safe_address, TFH_PAYMASTER_ADDRESS)
        .call()
        .await?;
    assert!(
        drained < wld_target() / U256::from(2),
        "the allowance should now be below half the target, got {drained}"
    );

    assert!(!migration.end_state_holds().await?);
    assert!(matches!(
        migration.reconcile().await?,
        WalletMigrationResult::Submitted { .. }
    ));
    assert_eq!(
        wld.allowance(safe_address, TFH_PAYMASTER_ADDRESS)
            .call()
            .await?,
        wld_target(),
        "the top-up should restore the full target allowance"
    );
    assert!(migration.end_state_holds().await?);

    // 8) The same for USDC, which consumes allowance differently: Circle's
    //    FiatToken decrements even from `type(uint256).max`, where a standard
    //    ERC-20 skips the decrement there. Finite approvals sidestep that split
    //    — both decrement below MAX — so USDC needs no special case here, and
    //    this proves it rather than assuming it.
    let twenty_usdc = U256::from(20_000_000u64);
    paymaster_spends(
        &anvil.endpoint_url(),
        USDC_ADDRESS,
        safe_address,
        twenty_usdc,
    )
    .await?;
    assert_eq!(
        usdc.allowance(safe_address, TFH_PAYMASTER_ADDRESS)
            .call()
            .await?,
        usdc_target() - twenty_usdc,
        "USDC should decrement by exactly what was pulled"
    );

    assert!(!migration.end_state_holds().await?);
    assert!(matches!(
        migration.reconcile().await?,
        WalletMigrationResult::Submitted { .. }
    ));
    assert_eq!(
        usdc.allowance(safe_address, TFH_PAYMASTER_ADDRESS)
            .call()
            .await?,
        usdc_target(),
        "the USDC top-up should restore the full target"
    );
    assert_eq!(
        wld.allowance(safe_address, TFH_PAYMASTER_ADDRESS)
            .call()
            .await?,
        wld_target(),
        "WLD was at target, so the USDC top-up must leave it alone"
    );

    drop(std::fs::remove_dir_all(&root));
    Ok(())
}
