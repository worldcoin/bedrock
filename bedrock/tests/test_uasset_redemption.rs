use std::sync::Arc;

use alloy::{
    primitives::{Address, U256},
    providers::{ext::AnvilApi, ProviderBuilder},
    signers::local::PrivateKeySigner,
    sol,
};

use bedrock::{
    primitives::http_client::set_http_client,
    smart_account::{SafeSmartAccount, ENTRYPOINT_4337},
    test_utils::{AnvilBackedHttpClient, IEntryPoint},
    transactions::UAssetRedemption,
};

mod common;
mod foundry;

sol! {
    #[sol(rpc)]
    interface IUAssetRedemptionFixture {
        function tokenA() external view returns (address);
        function tokenB() external view returns (address);
        function USDC() external view returns (address);
        function fundUser(address user) external;
    }
}

#[tokio::test]
async fn test_uasset_redemption_safe_batch_and_rollback() -> anyhow::Result<()> {
    let anvil = common::setup_anvil();
    let owner = PrivateKeySigner::random();
    let private_key = hex::encode(owner.to_bytes());
    let provider = ProviderBuilder::new()
        .wallet(owner.clone())
        .connect_http(anvil.endpoint_url());
    provider
        .anvil_set_balance(owner.address(), U256::from(10u64.pow(19)))
        .await?;
    let vault: Address = foundry::ForgeCreate::new(
        "solidity/src/UAssetRedemptionFixture.sol:UAssetRedemptionFixture",
    )
    .run(format!("0x{private_key}"), anvil.endpoint_url().to_string())?
    .parse()?;
    let safe = common::deploy_safe(&provider, owner.address(), U256::ZERO).await?;
    let fixture = IUAssetRedemptionFixture::new(vault, &provider);
    fixture.fundUser(safe).send().await?.get_receipt().await?;
    let token_a = fixture.tokenA().call().await?;
    let token_b = fixture.tokenB().call().await?;
    let usdc = common::IERC20::new(fixture.USDC().call().await?, &provider);
    let a = common::IERC20::new(token_a, &provider);
    let b = common::IERC20::new(token_b, &provider);

    IEntryPoint::new(*ENTRYPOINT_4337, &provider)
        .depositTo(safe)
        .value(U256::from(10u64.pow(18)))
        .send()
        .await?
        .get_receipt()
        .await?;
    set_http_client(Arc::new(AnvilBackedHttpClient::new(provider.clone())));
    let account =
        SafeSmartAccount::from_private_key_hex(private_key, &safe.to_string())?;
    let quote = |token: Address, minimum: u64| UAssetRedemption {
        token_address: token.to_string(),
        amount: "1000000000000000000".to_string(),
        minimum_usdc_amount: minimum.to_string(),
    };

    account
        .transaction_uasset_redeem(
            &vault.to_string(),
            vec![quote(token_a, 1_000_000), quote(token_b, 2_000_000)],
        )
        .await?;
    assert_eq!(
        a.balanceOf(safe).call().await?,
        U256::from(9 * 10u64.pow(18))
    );
    assert_eq!(
        b.balanceOf(safe).call().await?,
        U256::from(9 * 10u64.pow(18))
    );
    assert_eq!(usdc.balanceOf(safe).call().await?, U256::from(3_000_000));
    assert_eq!(a.allowance(safe, vault).call().await?, U256::ZERO);
    assert_eq!(b.allowance(safe, vault).call().await?, U256::ZERO);

    // A failing second redemption must undo the first redemption and both approvals.
    let result = account
        .transaction_uasset_redeem(
            &vault.to_string(),
            vec![quote(token_a, 1_000_000), quote(token_b, 2_000_001)],
        )
        .await;
    assert!(result.is_err());
    assert_eq!(
        a.balanceOf(safe).call().await?,
        U256::from(9 * 10u64.pow(18))
    );
    assert_eq!(
        b.balanceOf(safe).call().await?,
        U256::from(9 * 10u64.pow(18))
    );
    assert_eq!(a.balanceOf(vault).call().await?, U256::from(10u64.pow(18)));
    assert_eq!(b.balanceOf(vault).call().await?, U256::from(10u64.pow(18)));
    assert_eq!(usdc.balanceOf(safe).call().await?, U256::from(3_000_000));
    assert_eq!(usdc.balanceOf(vault).call().await?, U256::from(27_000_000));
    assert_eq!(a.allowance(safe, vault).call().await?, U256::ZERO);
    assert_eq!(b.allowance(safe, vault).call().await?, U256::ZERO);
    Ok(())
}
