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
    test_utils::{start_mock_bundler_server, AnvilBackedHttpClient, IEntryPoint},
    transactions::{foreign::UnparsedUserOperation, TransactionError},
};

use bedrock::smart_account::{
    ISafe4337Module, InstructionFlag, NonceKeyV1, SafeOperation, TransactionTypeId,
};

// ── Helpers for error-handling integration tests ──────────────────────────────

/// Starts a loopback HTTP server that responds to every request with the given
/// status code and body. Returns `http://127.0.0.1:<port>`.
fn start_mock_http_server(status: u16, body: String) -> String {
    use std::io::{Read, Write};

    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());

    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let body = body.clone();
            let Ok(mut stream) = stream else { break };
            std::thread::spawn(move || {
                let mut buf = [0u8; 8192];
                let _ = stream.read(&mut buf);
                let response = format!(
                    "HTTP/1.1 {status} -\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = stream.write_all(response.as_bytes());
            });
        }
    });

    url
}

/// A minimal `UnparsedUserOperation` whose fields are valid hex strings.
/// The sender address is arbitrary because error tests never reach on-chain execution.
fn minimal_unparsed_user_op(sender: &str) -> UnparsedUserOperation {
    use bedrock::smart_account::{InstructionFlag, NonceKeyV1, TransactionTypeId};
    let nonce_key = NonceKeyV1::new(
        TransactionTypeId::Transfer,
        InstructionFlag::Default,
        [0u8; 10],
    );
    let nonce = nonce_key.encode_with_sequence(0);
    UnparsedUserOperation {
        sender: sender.to_string(),
        nonce: format!("{nonce:#x}"),
        call_data: "0x".to_string(),
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
    }
}

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

    // 7) Install HTTP client for backend RPC calls + start mock bundler server
    let client = AnvilBackedHttpClient::new(provider.clone());
    set_http_client(Arc::new(client.clone()));
    let bundler_url = start_mock_bundler_server(client).await;

    // 8) Craft the user operation manually
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
        .send_bundler_sponsored_user_operation(unparsed_user_op, bundler_url.clone())
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

// ── Error-handling tests (no Anvil required) ──────────────────────────────────
//
// These tests verify the error-handling behaviour of
// `send_bundler_sponsored_user_operation`. They use a lightweight mock HTTP
// server instead of a real Anvil fork, so they complete in milliseconds.

/// Bundler JSON-RPC rejections (HTTP 200, error body) must surface as
/// `TransactionError::BundlerRejected` with the bundler's code and message
/// forwarded verbatim. Covers the most common EIP-7769 rejection codes.
#[tokio::test]
async fn test_send_bundler_sponsored_user_operation_bundler_rejected_cases() {
    struct Case {
        code: i64,
        message: &'static str,
    }

    let cases = [
        Case {
            code: -32500,
            message: "AA23 reverted (or OOG)",
        },
        Case {
            code: -32507,
            message: "wallet signature check failed",
        },
        Case {
            code: -32602,
            message: "invalid UserOperation struct/fields",
        },
    ];

    // The sender address doesn't need to be deployed for these error tests —
    // the mock bundler rejects before any on-chain call.
    let safe_address = "0x1234567890123456789012345678901234567890";

    for case in &cases {
        let bundler_url = start_mock_http_server(
            200,
            serde_json::json!({ "jsonrpc": "2.0", "id": 1, "error": { "code": case.code, "message": case.message } }).to_string(),
        );
        let owner_key_hex =
            hex::encode(alloy::signers::local::PrivateKeySigner::random().to_bytes());
        let safe_account = SafeSmartAccount::new(owner_key_hex, safe_address)
            .expect("failed to create SafeSmartAccount");

        let err = safe_account
            .send_bundler_sponsored_user_operation(
                minimal_unparsed_user_op(safe_address),
                bundler_url,
            )
            .await
            .unwrap_err();

        match err {
            TransactionError::BundlerRejected { code, message } => {
                assert_eq!(code, case.code, "wrong code for '{}'", case.message);
                assert_eq!(
                    message, case.message,
                    "message not forwarded verbatim for code {}",
                    case.code
                );
            }
            other => panic!("expected BundlerRejected({}), got {other:?}", case.code),
        }
    }
}

/// When the bundler endpoint itself returns a non-2xx HTTP response (transport
/// failure — the request never reached bundler logic), the error must be
/// `TransactionError::Generic`, NOT `BundlerRejected`.
///
/// This exercises the key distinction: `BundlerRejected` means "bundler received
/// the request and made a decision"; `Generic` means "we couldn't even reach the
/// bundler".
#[tokio::test]
async fn test_send_bundler_sponsored_user_operation_http_error_is_generic() {
    let bundler_url = start_mock_http_server(500, String::new());

    let owner_key_hex =
        hex::encode(alloy::signers::local::PrivateKeySigner::random().to_bytes());
    let safe_address = "0x1234567890123456789012345678901234567890";
    let safe_account = SafeSmartAccount::new(owner_key_hex, safe_address)
        .expect("failed to create SafeSmartAccount");

    let err = safe_account
        .send_bundler_sponsored_user_operation(
            minimal_unparsed_user_op(safe_address),
            bundler_url,
        )
        .await
        .expect_err("expected an error for HTTP 500");

    assert!(
        matches!(err, TransactionError::Generic { .. }),
        "HTTP 500 should produce Generic; got {err:?}"
    );
}
