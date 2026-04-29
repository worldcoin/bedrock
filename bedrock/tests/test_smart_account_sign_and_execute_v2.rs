use std::sync::Arc;

mod common;
use alloy::{
    primitives::{address, U256},
    providers::{ext::AnvilApi, ProviderBuilder},
    signers::local::PrivateKeySigner,
};
use common::{deploy_safe, set_erc20_balance_for_safe, setup_anvil, IERC20};

use bedrock::{
    primitives::{http_client::set_http_client, Network},
    smart_account::{Is4337Encodable, SafeSmartAccount, ENTRYPOINT_4337},
    test_utils::{AnvilBackedHttpClient, IEntryPoint},
    transactions::contracts::erc20::Erc20,
};

/// Integration test for `sign_and_execute_v2`.
///
/// Asserts that the V2 path:
/// 1. Calls `pm_sponsorUserOperation` to obtain gas/paymaster fields
/// 2. Merges the response into the `UserOperation`
/// 3. Signs and submits via `eth_sendUserOperation`
/// 4. Returns a non-zero userOpHash and the transfer executes on-chain
#[tokio::test]
async fn test_sign_and_execute_v2_full_flow() -> anyhow::Result<()> {
    // 1) Spin up an Anvil fork of World Chain
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

    // 2) Deploy Safe with the 4337 module enabled
    let safe_address = deploy_safe(&provider, owner, U256::ZERO).await?;

    // 3) Fund the EntryPoint deposit so the Safe can pay gas (bundler-sponsored, no paymaster)
    let entry_point = IEntryPoint::new(*ENTRYPOINT_4337, &provider);
    entry_point
        .depositTo(safe_address)
        .value(U256::from(1e18 as u64))
        .send()
        .await?
        .get_receipt()
        .await?;

    // 4) Give the Safe an ERC-20 balance to transfer
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

    // 5) Capture balances before the transfer
    let recipient = PrivateKeySigner::random().address();
    let before_recipient = wld.balanceOf(recipient).call().await?;
    let before_safe = wld.balanceOf(safe_address).call().await?;

    // 6) Wire up the mock HTTP client.
    //    AnvilBackedHttpClient handles pm_sponsorUserOperation (returns sane gas values,
    //    no paymaster) and eth_sendUserOperation (executes via EntryPoint.handleOps on Anvil).
    let client = AnvilBackedHttpClient::new(provider.clone());
    set_http_client(Arc::new(client));

    // 7) Build the transaction and call sign_and_execute_v2
    let transfer_amount = U256::from(10u128.pow(18)); // 1 WLD
    let erc20_tx = Erc20::new(wld_token_address, recipient, transfer_amount);
    let safe_account = SafeSmartAccount::new(owner_key_hex, &safe_address.to_string())?;

    let user_op_hash = erc20_tx
        .sign_and_execute_v2(&safe_account, Network::WorldChain, None)
        .await
        .expect("sign_and_execute_v2 failed");

    assert!(!user_op_hash.is_zero(), "userOpHash must not be zero");

    // 8) Verify the on-chain transfer succeeded
    let after_recipient = wld.balanceOf(recipient).call().await?;
    let after_safe = wld.balanceOf(safe_address).call().await?;

    assert_eq!(after_recipient, before_recipient + transfer_amount);
    assert_eq!(after_safe, before_safe - transfer_amount);

    Ok(())
}
