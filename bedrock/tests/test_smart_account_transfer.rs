use std::sync::Arc;

mod common;
use alloy::{
    primitives::{address, U256},
    providers::{ext::AnvilApi, ProviderBuilder},
    signers::local::PrivateKeySigner,
};
use common::{deploy_safe, set_erc20_balance_for_safe, setup_anvil, IERC20};

use bedrock::{
    primitives::http_client::set_http_client,
    smart_account::{SafeSmartAccount, ENTRYPOINT_4337},
    test_utils::{AnvilBackedHttpClient, IEntryPoint},
};

// ------------------ The test for the full transaction_transfer flow ------------------

#[tokio::test]
async fn test_transaction_transfer_full_flow_executes_user_operation(
) -> anyhow::Result<()> {
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
    let deposit_tx = entry_point
        .depositTo(safe_address)
        .value(U256::from(1e18 as u64))
        .send()
        .await?;
    let _ = deposit_tx.get_receipt().await?;

    // 5) Give Safe some ERC-20 balance (WLD on World Chain test contract used in other tests)
    let wld_token_address = address!("0x2cFc85d8E48F8EAB294be644d9E25C3030863003");
    let wld = IERC20::new(wld_token_address, &provider);

    let starting_balance = U256::from(10u128.pow(18) * 10); // 10 WLD
    set_erc20_balance_for_safe(
        &provider,
        wld_token_address,
        safe_address,
        starting_balance,
    )
    .await?;

    // 6) Prepare recipient and assert initial balances
    let recipient = PrivateKeySigner::random().address();
    let before_recipient = wld.balanceOf(recipient).call().await?;
    let before_safe = wld.balanceOf(safe_address).call().await?;

    // 7) Install mocked HTTP client that routes calls to Anvil
    let client = AnvilBackedHttpClient::new(provider.clone());

    set_http_client(Arc::new(client));

    // 8) Execute high-level transfer via transaction_transfer
    let safe_account = SafeSmartAccount::new(owner_key_hex, &safe_address.to_string())?;
    let amount = "1000000000000000000"; // 1 WLD
    let _user_op_hash = safe_account
        .transaction_transfer(
            &wld_token_address.to_string(),
            &recipient.to_string(),
            amount,
            None,
        )
        .await
        .expect("transaction_transfer failed");

    // 9) Verify balances updated
    let after_recipient = wld.balanceOf(recipient).call().await?;
    let after_safe = wld.balanceOf(safe_address).call().await?;

    assert_eq!(
        after_recipient,
        before_recipient + U256::from(10u128.pow(18))
    );
    assert_eq!(after_safe, before_safe - U256::from(10u128.pow(18)));

    Ok(())
}
