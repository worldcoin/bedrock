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
    transactions::foreign::UnparsedUserOperation,
};

use bedrock::smart_account::{
    ISafe4337Module, InstructionFlag, NonceKeyV1, SafeOperation, TransactionTypeId,
};

/// Integration test for the bundler-sponsored user operation flow.
///
/// This test deploys a Safe, creates an ERC-20 transfer user operation,
/// converts it to bundler-sponsored format (zeroed paymaster/fee fields),
/// signs it, and sends it via `send_bundler_sponsored_user_operation`.
#[tokio::test]
async fn test_send_bundler_sponsored_user_operation() -> anyhow::Result<()> {
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

    // 4) Fund EntryPoint deposit for Safe (needs enough to cover gas at zero fee)
    let entry_point = IEntryPoint::new(*ENTRYPOINT_4337, &provider);
    entry_point
        .depositTo(safe_address)
        .value(U256::from(1e18 as u64))
        .send()
        .await?
        .get_receipt()
        .await?;

    // 5) Give Safe some ERC-20 balance
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

    // 7) Install HTTP client that simulates bundler behaviour via Anvil
    let client = AnvilBackedHttpClient::new(provider.clone());
    set_http_client(Arc::new(client));

    // 8) Craft the user operation manually (mimicking what a Mini App would provide)
    let transfer_amount = U256::from(10u128.pow(18)); // 1 WLD
    let erc20_transfer_call_data = IERC20::transferCall {
        to: recipient,
        amount: transfer_amount,
    };
    let execute_call_data = ISafe4337Module::executeUserOpCall {
        to: wld_token_address,
        value: U256::ZERO,
        data: alloy::sol_types::SolCall::abi_encode(&erc20_transfer_call_data).into(),
        operation: SafeOperation::Call as u8,
    };

    let nonce_key = NonceKeyV1::new(
        TransactionTypeId::Transfer,
        InstructionFlag::Default,
        [0u8; 10],
    );
    let nonce = nonce_key.encode_with_sequence(0);

    let unparsed_user_op = UnparsedUserOperation {
        sender: safe_address.to_string(),
        nonce: format!("{nonce:#x}"),
        call_data: format!(
            "0x{}",
            hex::encode(alloy::sol_types::SolCall::abi_encode(&execute_call_data))
        ),
        call_gas_limit: "0x200000".to_string(),
        verification_gas_limit: "0x200000".to_string(),
        pre_verification_gas: "0x200000".to_string(),
        max_fee_per_gas: "0x12A05F200".to_string(),
        max_priority_fee_per_gas: "0x12A05F200".to_string(),
        paymaster: None,
        paymaster_verification_gas_limit: None,
        paymaster_post_op_gas_limit: None,
        paymaster_data: None,
        signature: format!("0x{}", hex::encode(vec![0xff; 77])),
        factory: None,
        factory_data: None,
    };

    // 9) Execute via send_bundler_sponsored_user_operation
    let safe_account = SafeSmartAccount::new(owner_key_hex, &safe_address.to_string())?;
    let _user_op_hash = safe_account
        .send_bundler_sponsored_user_operation(
            unparsed_user_op,
            "https://bundler.example.com".to_string(), // URL is irrelevant, test infra intercepts
        )
        .await
        .expect("send_bundler_sponsored_user_operation failed");

    // 10) Verify balances updated
    let after_recipient = wld.balanceOf(recipient).call().await?;
    let after_safe = wld.balanceOf(safe_address).call().await?;

    assert_eq!(
        after_recipient,
        before_recipient + U256::from(10u128.pow(18))
    );
    assert_eq!(after_safe, before_safe - U256::from(10u128.pow(18)));

    Ok(())
}
