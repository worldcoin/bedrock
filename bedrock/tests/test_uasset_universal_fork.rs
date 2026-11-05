//! World Chain fork test using Universal PR #17's migration/setup sequence.
use std::{sync::Arc, time::Duration};

use alloy::{
    network::Ethereum,
    primitives::{address, keccak256, Address, B256, U256},
    providers::{ext::AnvilApi, Provider, ProviderBuilder},
    signers::local::PrivateKeySigner,
    sol,
    sol_types::SolValue,
};
use anyhow::{ensure, Context};
use bedrock::{
    primitives::http_client::set_http_client,
    smart_account::{SafeSmartAccount, ENTRYPOINT_4337},
    test_utils::{AnvilBackedHttpClient, IEntryPoint},
    transactions::UAssetRedemption,
};

mod common;

const VAULT: Address = address!("1f69bbf9f7ed316bcf1e0cf12f81d261a9bdc2ca");
const CONTROLLER: Address = address!("271fe8f945693eb6a5e55621c39ac47f7004a8bf");
const USDC: Address = address!("79a02482a880bce3f13e09da970dc34db4cd24d1");
const TOKENS: [Address; 2] = [
    address!("9b8df6e244526ab5f6e6400d331db28c8fdddb55"), // uSOL
    address!("2615a94df961278dcbc41fb0a54fec5f10a693ae"), // uXRP
];
// Existing holders at World Chain block 37_242_824. Only impersonated on the local fork.
const HOLDERS: [Address; 2] = [
    address!("abd69c9941888e1c795aaabafe5617371681e0fb"),
    address!("98df3857683c320b0eec2df21434130d3d0282c7"),
];
// Fractional amounts exercise the 18-decimal asset -> 6-decimal USDC conversion.
const AMOUNTS: [u64; 2] = [100_000_000_000_123, 100_000_000_000_000_123];

sol! {
    #[sol(rpc)]
    interface IUniversalVault {
        function USDC() external view returns (address);
        function MERCHANT_CONTROLLER() external view returns (address);
        function owner() external view returns (address);
        function paused() external view returns (bool);
        function pause() external;
        function unpause() external;
        function withdrawToken(address token, uint256 amount) external;
        function setRedemptionRates(address[] tokens, uint256[] rates) external;
        function redemptionRates(address token) external view returns (uint256);
        function quoteRedeem(address token, uint256 amount) external view returns (uint256);
        event Redeemed(address indexed redeemer, address indexed asset, uint256 assetAmount, uint256 usdcAmount);
    }

    #[sol(rpc)]
    interface IUniversalAsset {
        function name() external view returns (string);
        function totalSupply() external view returns (uint256);
        function MERCHANT_CONTROLLER() external view returns (address);
    }

    #[sol(rpc)]
    interface IUniversalController {
        function defaultAdmin() external view returns (address);
        function BURNER_ROLE() external view returns (bytes32);
        function grantRole(bytes32 role, address account) external;
        function setBurnPermissions(address burner, address[] assets, bool allowed) external;
        function burnPermissions(address burner, address asset) external view returns (bool);
    }

    #[sol(rpc)]
    interface IUniversalBeacon {
        function owner() external view returns (address);
        function implementation() external view returns (address);
        function upgradeTo(address implementation) external;
    }
}

// Deployment bytecode from Universal's pinned source, not a substitute token implementation.
sol!(
    #[sol(rpc)]
    WrappedAssetV2,
    "tests/fixtures/universal/WrappedAssetV2.json"
);

#[tokio::test]
async fn universal_vault_safe_redemption_and_rollback() -> anyhow::Result<()> {
    // Like the other Bedrock fork tests, use WORLDCHAIN_RPC_URL (or the public
    // fallback). Anvil owns all mutations and is killed on success, error or panic.
    let anvil = common::setup_anvil_at_block(37_242_824);
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .build()?;
    let owner = PrivateKeySigner::random();
    let provider = ProviderBuilder::new()
        .wallet(owner.clone())
        .connect_reqwest(client.clone(), anvil.endpoint_url());
    let admin = ProviderBuilder::new().connect_reqwest(client, anvil.endpoint_url());
    tokio::time::timeout(Duration::from_secs(180), exercise(provider, admin, owner))
        .await
        .context("Universal redemption integration test exceeded 180 seconds")?
}

/// The two-asset subset of Universal PR #17's setup. All changes use real admin
/// calls, except synthetic vault USDC funding (as in the upstream launcher).
async fn prepare_universal<P: Provider<Ethereum>, A: Provider<Ethereum>>(
    provider: &P,
    admin: &A,
) -> anyhow::Result<()> {
    let vault = IUniversalVault::new(VAULT, admin);
    let controller = IUniversalController::new(CONTROLLER, admin);
    let beacon_address = address!("a0b59b5a943551d703f611c1c1ac7c924975d2aa");
    let beacon = IUniversalBeacon::new(beacon_address, admin);
    let beacon_slot =
        U256::from_be_bytes(keccak256("eip1967.proxy.beacon").0) - U256::from(1);
    let mut previous = Vec::new();
    for (i, token) in TOKENS.iter().enumerate() {
        ensure!(
            provider.get_storage_at(*token, beacon_slot).await?
                == U256::from_be_slice(beacon_address.as_slice()),
            "unexpected asset beacon at the pinned block"
        );
        let asset = IUniversalAsset::new(*token, provider);
        previous.push((
            asset.name().call().await?,
            asset.totalSupply().call().await?,
            common::IERC20::new(*token, provider)
                .balanceOf(HOLDERS[i])
                .call()
                .await?,
        ));
    }

    let vault_owner = vault.owner().call().await?;
    let controller_admin = controller.defaultAdmin().call().await?;
    let beacon_owner = beacon.owner().call().await?;
    for account in [vault_owner, controller_admin, beacon_owner] {
        admin
            .anvil_set_balance(account, U256::from(10u64.pow(18)))
            .await?;
        admin.anvil_impersonate_account(account).await?;
    }
    // Exact mock uSOL/uXRP rates from the pinned Universal redemption-rates.json.
    let rates = vec![
        U256::from(97_720_000_000_000_000_000u128),
        U256::from(1_400_400_000_000_000_000u128),
    ];
    ensure!(
        vault
            .setRedemptionRates(TOKENS.to_vec(), rates.clone())
            .from(vault_owner)
            .send()
            .await?
            .get_receipt()
            .await?
            .status(),
        "setting rates reverted"
    );
    let burner_role = controller.BURNER_ROLE().call().await?;
    ensure!(
        controller
            .grantRole(burner_role, VAULT)
            .from(controller_admin)
            .send()
            .await?
            .get_receipt()
            .await?
            .status(),
        "granting burner role reverted"
    );
    ensure!(
        controller
            .setBurnPermissions(VAULT, TOKENS.to_vec(), true)
            .from(controller_admin)
            .send()
            .await?
            .get_receipt()
            .await?
            .status(),
        "setting burn permissions reverted"
    );

    // World Chain USDC's balance mapping is slot 9 at the pinned block. Preserve
    // its deployed implementation; only the vault's synthetic funding is changed.
    let liquidity = U256::from(100_000_000_000_000u64);
    let slot = U256::from_be_bytes(keccak256((VAULT, U256::from(9)).abi_encode()).0);
    admin
        .anvil_set_storage_at(USDC, slot, B256::from(liquidity))
        .await?;
    ensure!(
        common::IERC20::new(USDC, provider)
            .balanceOf(VAULT)
            .call()
            .await?
            == liquidity,
        "USDC storage layout does not match the pinned fork"
    );

    let implementation = WrappedAssetV2::deploy(provider, CONTROLLER).await?;
    ensure!(
        beacon
            .upgradeTo(*implementation.address())
            .from(beacon_owner)
            .send()
            .await?
            .get_receipt()
            .await?
            .status(),
        "beacon migration reverted"
    );
    ensure!(
        beacon.implementation().call().await? == *implementation.address(),
        "beacon migration failed"
    );
    for (i, token) in TOKENS.iter().enumerate() {
        let asset = IUniversalAsset::new(*token, provider);
        ensure!(
            asset.MERCHANT_CONTROLLER().call().await? == CONTROLLER,
            "migrated asset has the wrong controller"
        );
        let current = (
            asset.name().call().await?,
            asset.totalSupply().call().await?,
            common::IERC20::new(*token, provider)
                .balanceOf(HOLDERS[i])
                .call()
                .await?,
        );
        ensure!(
            current == previous[i],
            "migration changed asset name, supply or holder balance"
        );
        ensure!(
            vault.redemptionRates(*token).call().await? == rates[i],
            "rate not configured"
        );
        ensure!(
            controller.burnPermissions(VAULT, *token).call().await?,
            "missing burn permission"
        );
    }
    ensure!(
        vault
            .unpause()
            .from(vault_owner)
            .send()
            .await?
            .get_receipt()
            .await?
            .status(),
        "unpausing vault reverted"
    );
    ensure!(!vault.paused().call().await?, "vault still paused");
    for account in [vault_owner, controller_admin, beacon_owner] {
        admin.anvil_stop_impersonating_account(account).await?;
    }
    Ok(())
}

#[derive(Debug, PartialEq, Eq)]
struct Balances {
    safe_assets: [U256; 2],
    vault_assets: [U256; 2],
    supplies: [U256; 2],
    allowances: [U256; 2],
    safe_usdc: U256,
    vault_usdc: U256,
}

async fn balances<P: Provider<Ethereum>>(
    provider: &P,
    safe: Address,
) -> anyhow::Result<Balances> {
    let mut result = Balances {
        safe_assets: [U256::ZERO; 2],
        vault_assets: [U256::ZERO; 2],
        supplies: [U256::ZERO; 2],
        allowances: [U256::ZERO; 2],
        safe_usdc: common::IERC20::new(USDC, provider)
            .balanceOf(safe)
            .call()
            .await?,
        vault_usdc: common::IERC20::new(USDC, provider)
            .balanceOf(VAULT)
            .call()
            .await?,
    };
    for (i, token) in TOKENS.iter().enumerate() {
        let erc20 = common::IERC20::new(*token, provider);
        result.safe_assets[i] = erc20.balanceOf(safe).call().await?;
        result.vault_assets[i] = erc20.balanceOf(VAULT).call().await?;
        result.allowances[i] = erc20.allowance(safe, VAULT).call().await?;
        result.supplies[i] = IUniversalAsset::new(*token, provider)
            .totalSupply()
            .call()
            .await?;
    }
    Ok(result)
}

fn assert_settlement(
    before: &Balances,
    after: &Balances,
    total: U256,
) -> anyhow::Result<()> {
    for (i, amount) in AMOUNTS.iter().enumerate() {
        ensure!(
            after.safe_assets[i] == before.safe_assets[i] - U256::from(*amount),
            "asset debit mismatch"
        );
        ensure!(
            after.supplies[i] == before.supplies[i] - U256::from(*amount),
            "tokens were not burned"
        );
    }
    ensure!(
        after.vault_assets == before.vault_assets,
        "vault retained redeemed assets"
    );
    ensure!(
        after.allowances == [U256::ZERO; 2],
        "approval was not consumed"
    );
    ensure!(
        after.safe_usdc == before.safe_usdc + total
            && after.vault_usdc == before.vault_usdc - total,
        "USDC settlement mismatch"
    );

    Ok(())
}

async fn assert_execution<P: Provider<Ethereum>>(
    provider: &P,
    from_block: u64,
    safe: Address,
    success: bool,
    payouts: [U256; 2],
) -> anyhow::Result<()> {
    let operations = IEntryPoint::new(*ENTRYPOINT_4337, provider)
        .UserOperationEvent_filter()
        .from_block(from_block)
        .query()
        .await?;
    ensure!(operations.len() == 1, "expected one executed UserOperation");
    ensure!(
        operations[0].0.sender == safe && operations[0].0.success == success,
        "unexpected UserOperation outcome"
    );
    let redemptions = IUniversalVault::new(VAULT, provider)
        .Redeemed_filter()
        .from_block(from_block)
        .query()
        .await?;
    ensure!(
        redemptions.len() == if success { 2 } else { 0 },
        "unexpected committed redemption events"
    );
    if success {
        for (i, (event, _)) in redemptions.iter().enumerate() {
            ensure!(
                event.redeemer == safe
                    && event.asset == TOKENS[i]
                    && event.assetAmount == U256::from(AMOUNTS[i])
                    && event.usdcAmount == payouts[i],
                "incorrect redemption event"
            );
        }
    }
    Ok(())
}

async fn exercise<P, A>(
    provider: P,
    admin: A,
    owner: PrivateKeySigner,
) -> anyhow::Result<()>
where
    P: Provider<Ethereum> + Clone + Send + Sync + 'static,
    A: Provider<Ethereum>,
{
    ensure!(
        provider.get_chain_id().await? == 480,
        "expected World Chain"
    );
    let vault = IUniversalVault::new(VAULT, &admin);
    ensure!(vault.USDC().call().await? == USDC, "wrong payout token");
    ensure!(
        vault.MERCHANT_CONTROLLER().call().await? == CONTROLLER,
        "wrong controller"
    );
    ensure!(
        vault.paused().call().await?,
        "expected the deployed vault to be paused at the pinned block"
    );
    // Keep fee estimation inside the local fork's history, including on older Anvil versions.
    provider.anvil_mine(Some(10), None).await?;
    provider
        .anvil_set_balance(owner.address(), U256::from(10u64.pow(19)))
        .await?;
    prepare_universal(&provider, &admin).await?;
    let safe = common::deploy_safe(&provider, owner.address(), U256::ZERO).await?;
    let mut payouts = [U256::ZERO; 2];
    for (i, token) in TOKENS.iter().enumerate() {
        let asset = IUniversalAsset::new(*token, &admin);
        ensure!(
            asset.MERCHANT_CONTROLLER().call().await? == CONTROLLER,
            "token beacon migration has not been applied"
        );
        let amount = U256::from(AMOUNTS[i]);
        let rate = vault.redemptionRates(*token).call().await?;
        payouts[i] = amount * rate / U256::from(10u64).pow(U256::from(30));
        ensure!(payouts[i] > U256::ZERO, "test amount rounds to zero USDC");
        ensure!(
            vault.quoteRedeem(*token, amount).call().await? == payouts[i],
            "quote rounding mismatch"
        );
        let erc20 = common::IERC20::new(*token, &admin);
        let funding = amount * U256::from(3);
        let holder_before = erc20.balanceOf(HOLDERS[i]).call().await?;
        ensure!(
            holder_before >= funding,
            "pinned holder lacks funds; use fork block 37242824"
        );
        let supply_before = asset.totalSupply().call().await?;
        admin
            .anvil_set_balance(HOLDERS[i], U256::from(10u64.pow(18)))
            .await?;
        admin.anvil_impersonate_account(HOLDERS[i]).await?;
        let receipt = erc20
            .transfer(safe, funding)
            .from(HOLDERS[i])
            .send()
            .await?
            .get_receipt()
            .await?;
        ensure!(receipt.status(), "holder transfer reverted");
        admin.anvil_stop_impersonating_account(HOLDERS[i]).await?;
        ensure!(
            erc20.balanceOf(safe).call().await? == funding,
            "Safe was not funded"
        );
        ensure!(
            erc20.balanceOf(HOLDERS[i]).call().await? == holder_before - funding,
            "holder debit mismatch"
        );
        ensure!(
            asset.totalSupply().call().await? == supply_before,
            "funding changed supply"
        );
    }
    IEntryPoint::new(*ENTRYPOINT_4337, &provider)
        .depositTo(safe)
        .value(U256::from(10u64.pow(18)))
        .send()
        .await?
        .get_receipt()
        .await?;
    // Screening/sponsorship are mocked; signed calldata executes through the real EntryPoint.
    set_http_client(Arc::new(AnvilBackedHttpClient::new(provider.clone())));
    let account = SafeSmartAccount::from_private_key_hex(
        hex::encode(owner.to_bytes()),
        &safe.to_string(),
    )?;
    let quotes = || {
        TOKENS
            .iter()
            .enumerate()
            .map(|(i, token)| UAssetRedemption {
                token_address: token.to_string(),
                amount: AMOUNTS[i].to_string(),
                minimum_usdc_amount: payouts[i].to_string(),
            })
            .collect::<Vec<_>>()
    };
    let total = payouts[0] + payouts[1];

    // A real burn and payout for both assets, from the Safe (not its EOA owner).
    let before = balances(&provider, safe).await?;
    let block = provider.get_block_number().await? + 1;
    account.transaction_uasset_redeem(quotes(), None).await?;
    assert_execution(&provider, block, safe, true, payouts).await?;
    let after = balances(&provider, safe).await?;
    assert_settlement(&before, &after, total)?;

    // The second minimum is one USDC base unit too high. An executed failure, not
    // merely any RPC error, must leave balances, supply and both approvals unchanged.
    let mut invalid = quotes();
    invalid[1].minimum_usdc_amount = (payouts[1] + U256::from(1)).to_string();
    let block = provider.get_block_number().await? + 1;
    ensure!(
        account
            .transaction_uasset_redeem(invalid, None)
            .await
            .is_err(),
        "invalid minimum succeeded"
    );
    assert_execution(&provider, block, safe, false, payouts).await?;
    ensure!(
        balances(&provider, safe).await? == after,
        "minimum-payout failure was not atomic"
    );

    // Leave enough shared USDC for asset one, but one base unit short for the batch.
    let vault_owner = vault.owner().call().await?;
    admin
        .anvil_set_balance(vault_owner, U256::from(10u64.pow(18)))
        .await?;
    admin.anvil_impersonate_account(vault_owner).await?;
    vault
        .pause()
        .from(vault_owner)
        .send()
        .await?
        .get_receipt()
        .await?;
    let withdrawal = after.vault_usdc - (total - U256::from(1));
    vault
        .withdrawToken(USDC, withdrawal)
        .from(vault_owner)
        .send()
        .await?
        .get_receipt()
        .await?;
    vault
        .unpause()
        .from(vault_owner)
        .send()
        .await?
        .get_receipt()
        .await?;
    let underfunded = balances(&provider, safe).await?;
    ensure!(
        underfunded.vault_usdc == total - U256::from(1),
        "incorrect liquidity fixture"
    );
    let block = provider.get_block_number().await? + 1;
    ensure!(
        account
            .transaction_uasset_redeem(quotes(), None)
            .await
            .is_err(),
        "underfunded batch succeeded"
    );
    assert_execution(&provider, block, safe, false, payouts).await?;
    ensure!(
        balances(&provider, safe).await? == underfunded,
        "liquidity failure was not atomic"
    );

    common::IERC20::new(USDC, &admin)
        .transfer(VAULT, withdrawal)
        .from(vault_owner)
        .send()
        .await?
        .get_receipt()
        .await?;
    admin.anvil_stop_impersonating_account(vault_owner).await?;
    let block = provider.get_block_number().await? + 1;
    account.transaction_uasset_redeem(quotes(), None).await?;
    assert_execution(&provider, block, safe, true, payouts).await?;
    let recovered = balances(&provider, safe).await?;
    assert_settlement(&after, &recovered, total)?;
    Ok(())
}
