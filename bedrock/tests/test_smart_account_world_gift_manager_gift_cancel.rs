use std::sync::Arc;

mod common;
use alloy::{
    primitives::{address, U256},
    providers::{ext::AnvilApi, ProviderBuilder},
    signers::local::PrivateKeySigner,
};
use common::{
    deploy_safe, set_erc20_balance_for_safe, setup_anvil, IEntryPoint, IERC20,
};

use bedrock::{
    primitives::http_client::set_http_client,
    smart_account::{SafeSmartAccount, ENTRYPOINT_4337},
    test_utils::AnvilBackedHttpClient,
};

#[tokio::test]
async fn test_transaction_world_gift_manager_gift_cancel_user_operations(
) -> anyhow::Result<()> {
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

    let safe_address_giftor = deploy_safe(&provider, owner, U256::ZERO).await?;
    let safe_address_giftee = deploy_safe(&provider, owner, U256::from(1)).await?;

    let entry_point = IEntryPoint::new(*ENTRYPOINT_4337, &provider);
    for safe in [safe_address_giftor, safe_address_giftee] {
        let _ = entry_point
            .depositTo(safe)
            .value(U256::from(1e18 as u64))
            .send()
            .await?
            .get_receipt()
            .await?;
    }

    let wld_token_address = address!("0x2cFc85d8E48F8EAB294be644d9E25C3030863003");
    let wld = IERC20::new(wld_token_address, &provider);

    let starting_balance = U256::from(10u128.pow(18) * 10); // 10 WLD
    set_erc20_balance_for_safe(
        &provider,
        wld_token_address,
        safe_address_giftor,
        starting_balance,
    )
    .await?;

    let before_giftor = wld.balanceOf(safe_address_giftor).call().await?;
    let before_giftee = wld.balanceOf(safe_address_giftee).call().await?;

    let client = AnvilBackedHttpClient::new(provider.clone());

    set_http_client(Arc::new(client));

    let safe_account_giftor =
        SafeSmartAccount::new(owner_key_hex.clone(), &safe_address_giftor.to_string())?;
    let amount = U256::from(1e18);

    let gift_result = safe_account_giftor
        .transaction_world_gift_manager_gift(
            &wld_token_address.to_string(),
            &safe_address_giftee.to_string(),
            &amount.to_string(),
        )
        .await
        .expect("transaction_world_gift_manager_gift failed");

    let after_giftor = wld.balanceOf(safe_address_giftor).call().await?;
    let after_giftee = wld.balanceOf(safe_address_giftee).call().await?;
    assert_eq!(after_giftor, before_giftor - amount);
    assert_eq!(after_giftee, before_giftee);

    let _redeem_result = safe_account_giftor
        .transaction_world_gift_manager_cancel(gift_result.gift_id.as_str())
        .await
        .expect("transaction_world_gift_manager_cancel failed");

    let after_cancel_giftor = wld.balanceOf(safe_address_giftor).call().await?;
    assert_eq!(after_cancel_giftor, before_giftor);

    Ok(())
}
