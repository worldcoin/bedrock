use alloy::{
    primitives::{address, Address, Bytes, U256},
    sol_types::{SolCall, SolValue},
};
use bedrock::{
    primitives::{
        http_client::{set_http_client, HttpHeader},
        AuthenticatedHttpClient, HttpError, HttpMethod,
    },
    smart_account::{ISafe4337Module, SafeSmartAccount, TransactionTypeId},
    transactions::{
        contracts::{
            erc20::{Erc20, IErc20},
            erc4626::IERC4626,
            multisend::{MultiSend, MultiSendTx, MULTISEND_ADDRESS},
            worldchain::{TFH_PAYMASTER_ADDRESS, WLD_ADDRESS},
        },
        TransactionError,
    },
};
use serde_json::{json, Value};
use std::sync::{Arc, Mutex, OnceLock};
use wiremock::{matchers::body_partial_json, Mock, MockServer, ResponseTemplate};

const VAULT: Address = address!("1234567890123456789012345678901234567890");

fn account() -> SafeSmartAccount {
    SafeSmartAccount::from_private_key_hex(
        "4142710b9b4caaeb000b8e5de271bbebac7f509aab2f5e61d1ed1958bfe6d583".to_string(),
        "0x4564420674EA68fcc61b463C0494807C759d47e6",
    )
    .unwrap()
}

struct TestHttpClient(Mutex<Arc<EarnHttpClient>>);

#[async_trait::async_trait]
impl AuthenticatedHttpClient for TestHttpClient {
    async fn fetch_from_app_backend(
        &self,
        url: String,
        method: HttpMethod,
        headers: Vec<HttpHeader>,
        body: Option<Vec<u8>>,
    ) -> Result<Vec<u8>, HttpError> {
        let client = self.0.lock().unwrap().clone();
        client
            .fetch_from_app_backend(url, method, headers, body)
            .await
    }
}

struct EarnHttpClient {
    asset: Address,
    balance: u64,
    shares: u64,
    required_shares: u64,
    redeemed_assets: u64,
    paid: bool,
    screening: Value,
    requests: Mutex<Vec<Value>>,
    screening_gate: Option<Arc<tokio::sync::Notify>>,
    sponsored: tokio::sync::Notify,
}

impl EarnHttpClient {
    fn new(balance: u64, paid: bool) -> Self {
        Self {
            asset: WLD_ADDRESS,
            balance,
            shares: 50,
            required_shares: 20,
            redeemed_assets: 4,
            paid,
            screening: json!({"result": true}),
            requests: Mutex::new(Vec::new()),
            screening_gate: None,
            sponsored: tokio::sync::Notify::new(),
        }
    }
}

#[async_trait::async_trait]
impl AuthenticatedHttpClient for EarnHttpClient {
    async fn fetch_from_app_backend(
        &self,
        url: String,
        _method: HttpMethod,
        _headers: Vec<HttpHeader>,
        body: Option<Vec<u8>>,
    ) -> Result<Vec<u8>, HttpError> {
        let request: Value = serde_json::from_slice(&body.unwrap()).unwrap();
        self.requests.lock().unwrap().push(request.clone());
        let response = match request["method"].as_str().unwrap() {
            "wa_screenAddresses" => {
                assert_eq!(url, "/v3/rpc/worldchain");
                assert_eq!(request["params"], json!([[account().wallet_address]]));
                if let Some(gate) = &self.screening_gate {
                    gate.notified().await;
                }
                self.screening.clone()
            }
            "eth_call" => {
                assert_eq!(url, "/v2/rpc/worldchain");
                let data: Bytes =
                    serde_json::from_value(request["params"][0]["data"].clone())
                        .unwrap();
                match data[..4].try_into().unwrap() {
                    IERC4626::assetCall::SELECTOR => {
                        json!({"result": Bytes::from(self.asset.abi_encode())})
                    }
                    IErc20::balanceOfCall::SELECTOR => {
                        let call = IErc20::balanceOfCall::abi_decode(&data).unwrap();
                        assert_eq!(call.account, account().wallet_address);
                        let balance = if request["params"][0]["to"] == json!(VAULT) {
                            self.shares
                        } else {
                            self.balance
                        };
                        json!({"result": Bytes::from(U256::from(balance).abi_encode())})
                    }
                    IERC4626::previewWithdrawCall::SELECTOR => {
                        json!({"result": Bytes::from(U256::from(self.required_shares).abi_encode())})
                    }
                    IERC4626::previewRedeemCall::SELECTOR => {
                        let call =
                            IERC4626::previewRedeemCall::abi_decode(&data).unwrap();
                        assert_eq!(call.shares, U256::from(self.shares));
                        json!({"result": Bytes::from(U256::from(self.redeemed_assets).abi_encode())})
                    }
                    IErc20::allowanceCall::SELECTOR => {
                        json!({"result": Bytes::from(U256::MAX.abi_encode())})
                    }
                    _ => panic!("Unexpected eth_call: {request}"),
                }
            }
            "pm_sponsorUserOperation" => {
                assert_eq!(url, "/v3/rpc/worldchain");
                self.sponsored.notify_one();
                if self.paid {
                    json!({"result": {
                        "callGasLimit":"0x10000", "verificationGasLimit":"0x10000",
                        "preVerificationGas":"0x2000", "maxFeePerGas":"0xa", "maxPriorityFeePerGas":"0x1",
                        "paymaster": TFH_PAYMASTER_ADDRESS,
                        "paymasterData": Bytes::from((WLD_ADDRESS, U256::from(1_000_000_000_000_000_000_u64), U256::from(2000)).abi_encode()),
                        "paymasterVerificationGasLimit":"0x10000", "paymasterPostOpGasLimit":"0x1000",
                        "fee": {"token": WLD_ADDRESS, "estimatedCostInToken":"10", "declineReason":"dev_redirect"}
                    }})
                } else {
                    json!({"result": {
                        "callGasLimit":"0x10000", "verificationGasLimit":"0x10000",
                        "preVerificationGas":"0x0", "maxFeePerGas":"0x0", "maxPriorityFeePerGas":"0x0"
                    }})
                }
            }
            "eth_sendUserOperation" => {
                assert_eq!(url, "/v3/rpc/worldchain");
                json!({"result": format!("0x{}", "11".repeat(32))})
            }
            method => panic!("Unexpected RPC method: {method}"),
        };
        Ok(serde_json::to_vec(&response).unwrap())
    }
}

fn install(client: EarnHttpClient) -> Arc<EarnHttpClient> {
    static HTTP: OnceLock<Arc<TestHttpClient>> = OnceLock::new();
    let client = Arc::new(client);
    let http = HTTP.get_or_init(|| {
        let http = Arc::new(TestHttpClient(Mutex::new(client.clone())));
        set_http_client(http.clone());
        http
    });
    *http.0.lock().unwrap() = client.clone();
    client
}

fn assert_deposit(operation: &Value, asset: Address, amount: u64) {
    let wallet = account().wallet_address;
    let approve = Erc20::encode_approve(VAULT, U256::from(amount));
    let deposit = IERC4626::depositCall {
        assets: U256::from(amount),
        receiver: wallet,
    }
    .abi_encode();
    let bundle = MultiSend::build_bundle(&[
        MultiSendTx {
            operation: 0,
            to: asset,
            value: U256::ZERO,
            data_length: U256::from(approve.len()),
            data: approve.into(),
        },
        MultiSendTx {
            operation: 0,
            to: VAULT,
            value: U256::ZERO,
            data_length: U256::from(deposit.len()),
            data: deposit.into(),
        },
    ]);
    let expected = ISafe4337Module::executeUserOpCall {
        to: MULTISEND_ADDRESS,
        value: U256::ZERO,
        data: bundle.data.into(),
        operation: 1,
    }
    .abi_encode();
    assert_eq!(operation["callData"], json!(Bytes::from(expected)));
    let nonce: U256 = serde_json::from_value(operation["nonce"].clone()).unwrap();
    assert_eq!(
        nonce.to_be_bytes::<32>()[5],
        TransactionTypeId::ERC4626Deposit.as_u8()
    );
}

#[tokio::test]
#[serial_test::serial]
async fn deposit_preserves_calldata_and_reports_amount_and_fee_before_signing() {
    for (balance, requested, actual, paid) in [(7, "10", 7, false), (17, "7", 7, true)]
    {
        let http = install(EarnHttpClient::new(balance, paid));
        let prepared = account()
            .prepare_transaction_erc4626_deposit(&VAULT.to_string(), requested, None)
            .await
            .unwrap();
        assert_eq!(prepared.asset_address, WLD_ADDRESS.to_string());
        assert_eq!(prepared.asset_amount, actual.to_string());
        assert_eq!(
            prepared
                .transaction
                .fee_details()
                .map(|fee| fee.estimated_cost_in_token),
            paid.then(|| "10".to_string())
        );
        let original = http
            .requests
            .lock()
            .unwrap()
            .iter()
            .find(|r| r["method"] == "pm_sponsorUserOperation")
            .unwrap()["params"][0]
            .clone();
        assert_deposit(&original, WLD_ADDRESS, actual);
        assert!(!http
            .requests
            .lock()
            .unwrap()
            .iter()
            .any(|r| r["method"] == "eth_sendUserOperation"));
        account()
            .submit_prepared_transaction(&prepared.transaction)
            .await
            .unwrap();
        let requests = http.requests.lock().unwrap();
        let signed = &requests
            .iter()
            .find(|r| r["method"] == "eth_sendUserOperation")
            .unwrap()["params"][0];
        for field in ["sender", "callData", "nonce"] {
            assert_eq!(signed[field], original[field]);
        }
        assert_ne!(signed["signature"], original["signature"]);
        assert_eq!(
            requests
                .iter()
                .filter(|r| r["method"] == "wa_screenAddresses")
                .count(),
            1
        );
    }
}

#[tokio::test]
#[serial_test::serial]
async fn deposit_reserves_the_fee_without_reducing_the_deposit() {
    install(EarnHttpClient::new(16, true));
    let error = account()
        .prepare_transaction_erc4626_deposit(&VAULT.to_string(), "7", None)
        .await
        .unwrap_err();
    assert!(matches!(error, TransactionError::InsufficientFunds { .. }));
}

#[tokio::test]
#[serial_test::serial]
async fn deposit_with_a_different_asset_only_requires_the_fee_token_fee_balance() {
    let asset = address!("1111111111111111111111111111111111111111");
    let mut client = EarnHttpClient::new(10, true);
    client.asset = asset;
    let http = install(client);
    let prepared = account()
        .prepare_transaction_erc4626_deposit(&VAULT.to_string(), "10", None)
        .await
        .unwrap();
    assert_eq!(prepared.asset_address, asset.to_string());
    let requests = http.requests.lock().unwrap();
    let operation = &requests
        .iter()
        .find(|r| r["method"] == "pm_sponsorUserOperation")
        .unwrap()["params"][0];
    assert_deposit(operation, asset, 10);
}

#[tokio::test]
#[serial_test::serial]
async fn deposit_sponsorship_runs_while_screening_is_pending() {
    let gate = Arc::new(tokio::sync::Notify::new());
    let mut client = EarnHttpClient::new(7, false);
    client.screening_gate = Some(gate.clone());
    let http = install(client);
    let wallet = account();
    let vault = VAULT.to_string();
    let preparation = wallet.prepare_transaction_erc4626_deposit(&vault, "7", None);
    tokio::pin!(preparation);
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        tokio::select! {
            result = &mut preparation => panic!("Returned before screening: {result:?}"),
            () = http.sponsored.notified() => {}
        }
        assert!(futures::poll!(&mut preparation).is_pending());
        gate.notify_one();
        preparation.await.unwrap();
    }).await.unwrap();
}

#[tokio::test]
#[serial_test::serial]
async fn deposit_custom_route_estimates_and_submits_at_the_same_url() {
    let http = install(EarnHttpClient::new(7, false));
    let server = MockServer::start().await;
    Mock::given(body_partial_json(
        json!({"method":"eth_estimateUserOperationGas"}),
    ))
    .respond_with(ResponseTemplate::new(200).set_body_json(
        json!({"result":{"callGasLimit":"0xc350","verificationGasLimit":"0xea60"}}),
    ))
    .expect(1)
    .mount(&server)
    .await;
    Mock::given(body_partial_json(json!({"method":"eth_sendUserOperation"})))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({"result":format!("0x{}", "11".repeat(32))})),
        )
        .expect(1)
        .mount(&server)
        .await;
    let prepared = account()
        .prepare_transaction_erc4626_deposit(
            &VAULT.to_string(),
            "7",
            Some(server.uri()),
        )
        .await
        .unwrap();
    assert!(prepared.transaction.fee_details().is_none());
    account()
        .submit_prepared_transaction(&prepared.transaction)
        .await
        .unwrap();
    let requests = server.received_requests().await.unwrap();
    let estimated: Value = requests[0].body_json().unwrap();
    let signed: Value = requests[1].body_json().unwrap();
    assert_deposit(&estimated["params"][0], WLD_ADDRESS, 7);
    assert_eq!(
        estimated["params"][0]["callData"],
        signed["params"][0]["callData"]
    );
    assert!(!http
        .requests
        .lock()
        .unwrap()
        .iter()
        .any(|r| r["method"] == "pm_sponsorUserOperation"
            || r["method"] == "eth_sendUserOperation"));
}

#[tokio::test]
#[serial_test::serial]
async fn deposit_rejects_restricted_and_unavailable_screening_on_both_routes() {
    for custom in [None, Some("http://127.0.0.1:1".to_string())] {
        for (code, reason) in [
            (-32602, "address_restricted"),
            (-32603, "screening_unavailable"),
        ] {
            let mut client = EarnHttpClient::new(7, false);
            client.screening = json!({"error":{"code":code,"message":"Screening failed","data":{"reason":reason}}});
            install(client);
            let error = account()
                .prepare_transaction_erc4626_deposit(
                    &VAULT.to_string(),
                    "7",
                    custom.clone(),
                )
                .await
                .unwrap_err();
            assert!(matches!(
                (reason, error),
                ("address_restricted", TransactionError::AddressRestricted)
                    | (
                        "screening_unavailable",
                        TransactionError::ScreeningUnavailable
                    )
            ));
        }
    }
}

fn assert_withdrawal(operation: &Value, shares: Option<u64>) {
    let wallet = account().wallet_address;
    let (data, action) = if let Some(shares) = shares {
        (
            IERC4626::redeemCall {
                shares: U256::from(shares),
                receiver: wallet,
                owner: wallet,
            }
            .abi_encode(),
            TransactionTypeId::ERC4626Redeem,
        )
    } else {
        (
            IERC4626::withdrawCall {
                assets: U256::from(20),
                receiver: wallet,
                owner: wallet,
            }
            .abi_encode(),
            TransactionTypeId::ERC4626Withdraw,
        )
    };
    let expected = ISafe4337Module::executeUserOpCall {
        to: VAULT,
        value: U256::ZERO,
        data: data.into(),
        operation: 0,
    }
    .abi_encode();
    assert_eq!(operation["callData"], json!(Bytes::from(expected)));
    let nonce: U256 = serde_json::from_value(operation["nonce"].clone()).unwrap();
    assert_eq!(nonce.to_be_bytes::<32>()[5], action.as_u8());
}

#[tokio::test]
#[serial_test::serial]
async fn withdrawal_preserves_withdraw_or_redeem_and_exposes_preview_before_signing() {
    for (shares, expected, paid) in [(50, "20", false), (4, "4", true)] {
        let mut client = EarnHttpClient::new(10, paid);
        client.shares = shares;
        let http = install(client);
        let prepared = account()
            .prepare_transaction_erc4626_withdraw(&VAULT.to_string(), "20", None)
            .await
            .unwrap();
        assert_eq!(prepared.asset_amount, expected);
        assert_eq!(prepared.asset_address, WLD_ADDRESS.to_string());
        assert_eq!(
            prepared
                .transaction
                .fee_details()
                .map(|fee| fee.estimated_cost_in_token),
            paid.then(|| "10".to_string())
        );
        let original = http
            .requests
            .lock()
            .unwrap()
            .iter()
            .find(|r| r["method"] == "pm_sponsorUserOperation")
            .unwrap()["params"][0]
            .clone();
        assert_withdrawal(&original, (shares == 4).then_some(4));
        assert!(!http
            .requests
            .lock()
            .unwrap()
            .iter()
            .any(|r| r["method"] == "eth_sendUserOperation"));
        account()
            .submit_prepared_transaction(&prepared.transaction)
            .await
            .unwrap();
        let requests = http.requests.lock().unwrap();
        let signed = &requests
            .iter()
            .find(|r| r["method"] == "eth_sendUserOperation")
            .unwrap()["params"][0];
        for field in ["sender", "callData", "nonce"] {
            assert_eq!(signed[field], original[field]);
        }
        assert_ne!(signed["signature"], original["signature"]);
        assert_eq!(
            requests
                .iter()
                .filter(|r| r["method"] == "wa_screenAddresses")
                .count(),
            1
        );
    }
}

#[tokio::test]
#[serial_test::serial]
async fn withdrawal_cannot_pay_validation_fees_with_future_proceeds() {
    install(EarnHttpClient::new(0, true));
    let error = account()
        .prepare_transaction_erc4626_withdraw(&VAULT.to_string(), "20", None)
        .await
        .unwrap_err();
    assert!(matches!(error, TransactionError::InsufficientFunds { .. }));
}

#[tokio::test]
#[serial_test::serial]
async fn withdrawal_rejects_zero_preview_and_empty_positions_before_sponsorship() {
    for shares in [0, 4] {
        let mut client = EarnHttpClient::new(10, false);
        client.shares = shares;
        client.redeemed_assets = 0;
        let http = install(client);
        assert!(account()
            .prepare_transaction_erc4626_withdraw(&VAULT.to_string(), "20", None)
            .await
            .is_err());
        assert!(!http
            .requests
            .lock()
            .unwrap()
            .iter()
            .any(|r| r["method"] == "pm_sponsorUserOperation"));
    }
}

#[tokio::test]
#[serial_test::serial]
async fn withdrawal_custom_route_estimates_and_submits_at_the_same_url() {
    let http = install(EarnHttpClient::new(0, false));
    let server = MockServer::start().await;
    Mock::given(body_partial_json(
        json!({"method":"eth_estimateUserOperationGas"}),
    ))
    .respond_with(ResponseTemplate::new(200).set_body_json(
        json!({"result":{"callGasLimit":"0xc350","verificationGasLimit":"0xea60"}}),
    ))
    .expect(1)
    .mount(&server)
    .await;
    Mock::given(body_partial_json(json!({"method":"eth_sendUserOperation"})))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({"result":format!("0x{}", "11".repeat(32))})),
        )
        .expect(1)
        .mount(&server)
        .await;
    let prepared = account()
        .prepare_transaction_erc4626_withdraw(
            &VAULT.to_string(),
            "20",
            Some(server.uri()),
        )
        .await
        .unwrap();
    assert!(prepared.transaction.fee_details().is_none());
    account()
        .submit_prepared_transaction(&prepared.transaction)
        .await
        .unwrap();
    let requests = server.received_requests().await.unwrap();
    let estimated: Value = requests[0].body_json().unwrap();
    let signed: Value = requests[1].body_json().unwrap();
    assert_withdrawal(&estimated["params"][0], None);
    assert_eq!(
        estimated["params"][0]["callData"],
        signed["params"][0]["callData"]
    );
    assert!(!http
        .requests
        .lock()
        .unwrap()
        .iter()
        .any(|r| r["method"] == "pm_sponsorUserOperation"
            || r["method"] == "eth_sendUserOperation"));
}

#[tokio::test]
#[serial_test::serial]
async fn withdrawal_cannot_prepare_without_screening_on_either_route() {
    for custom in [None, Some("http://127.0.0.1:1".to_string())] {
        for (code, reason) in [
            (-32602, "address_restricted"),
            (-32603, "screening_unavailable"),
        ] {
            let mut client = EarnHttpClient::new(10, false);
            client.screening = json!({"error":{"code":code,"message":"Screening failed","data":{"reason":reason}}});
            install(client);
            let error = account()
                .prepare_transaction_erc4626_withdraw(
                    &VAULT.to_string(),
                    "20",
                    custom.clone(),
                )
                .await
                .unwrap_err();
            assert!(matches!(
                (reason, error),
                ("address_restricted", TransactionError::AddressRestricted)
                    | (
                        "screening_unavailable",
                        TransactionError::ScreeningUnavailable
                    )
            ));
        }
    }
}
