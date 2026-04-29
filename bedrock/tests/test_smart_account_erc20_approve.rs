use std::sync::Arc;

mod common;
use alloy::{
    primitives::{address, U256},
    providers::{ext::AnvilApi, ProviderBuilder},
    signers::local::PrivateKeySigner,
};
use bedrock::{
    primitives::http_client::set_http_client,
    smart_account::{SafeSmartAccount, ENTRYPOINT_4337},
    test_utils::{AnvilBackedHttpClient, IEntryPoint},
};
use common::{deploy_safe, set_erc20_balance_for_safe, setup_anvil, IERC20};

#[tokio::test]
async fn test_transaction_erc20_approve_full_flow_sets_allowance() -> anyhow::Result<()>
{
    // 1) Spin up anvil fork
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

    // 4) Fund EntryPoint deposit for Safe
    let entry_point = IEntryPoint::new(*ENTRYPOINT_4337, &provider);
    entry_point
        .depositTo(safe_address)
        .value(U256::from(1e18 as u64))
        .send()
        .await?
        .get_receipt()
        .await?;

    // 5) Give Safe some ERC-20 balance to match real app usage
    let token_address = address!("0x2cFc85d8E48F8EAB294be644d9E25C3030863003");
    set_erc20_balance_for_safe(
        &provider,
        token_address,
        safe_address,
        U256::from(10u128.pow(18) * 10),
    )
    .await?;

    let token = IERC20::new(token_address, &provider);
    let spender = PrivateKeySigner::random().address();
    let amount = U256::from(10u128.pow(18));

    assert_eq!(
        token.allowance(safe_address, spender).call().await?,
        U256::ZERO
    );

    // 6) Install mocked HTTP client that routes sponsorship and send calls to Anvil
    let client = AnvilBackedHttpClient::new(provider.clone());
    set_http_client(Arc::new(client));

    // 7) Execute high-level approve via transaction_erc20_approve
    let safe_account = SafeSmartAccount::new(owner_key_hex, &safe_address.to_string())?;
    let _user_op_hash = safe_account
        .transaction_erc20_approve(
            &token_address.to_string(),
            &spender.to_string(),
            &amount.to_string(),
        )
        .await
        .expect("transaction_erc20_approve failed");

    // 8) Verify allowance updated on-chain
    assert_eq!(token.allowance(safe_address, spender).call().await?, amount);

    Ok(())
}
