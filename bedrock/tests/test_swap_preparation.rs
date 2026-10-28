use alloy::{
    primitives::{address, Address, Bytes, B256, U256},
    sol_types::{SolCall, SolValue},
};
use bedrock::{
    primitives::{
        http_client::{set_http_client, HttpHeader},
        AuthenticatedHttpClient, HttpError, HttpMethod,
    },
    smart_account::{Is4337Encodable, SafeSmartAccount},
    transactions::{
        contracts::{
            worldchain::{TFH_PAYMASTER_ADDRESS, USDC_ADDRESS, WLD_ADDRESS},
            zero_ex::{
                AllowedSlippage, IAllowanceHolder, ISettlerRegistry,
                ISettlerTakerSubmitted, ZeroExSwap, ZeroExSwapQuote, ZeroExSwapRequest,
                ALLOWANCE_HOLDER_ADDRESS,
            },
        },
        foreign::{UnparsedZeroExSwapQuote, UnparsedZeroExSwapRequest},
        rpc::IMulticall3,
        PreparedTransaction, TransactionError,
    },
};
use serde_json::{json, Value};
use std::{
    collections::VecDeque,
    sync::{Arc, Mutex, OnceLock},
};
use wiremock::{matchers::body_partial_json, Mock, MockServer, ResponseTemplate};

const WALLET: Address = address!("4564420674ea68fcc61b463c0494807c759d47e6");
const SETTLER: Address = address!("4444444444444444444444444444444444444444");
const OTHER: Address = address!("5555555555555555555555555555555555555555");
const HASH: B256 = B256::repeat_byte(0xab);

fn account(wallet: Address) -> SafeSmartAccount {
    SafeSmartAccount::from_private_key_hex(
        "4142710b9b4caaeb000b8e5de271bbebac7f509aab2f5e61d1ed1958bfe6d583".to_string(),
        &wallet.to_string(),
    )
    .unwrap()
}

fn request() -> UnparsedZeroExSwapRequest {
    UnparsedZeroExSwapRequest {
        token_in: WLD_ADDRESS.to_string(),
        token_out: USDC_ADDRESS.to_string(),
        amount_in: "100".to_string(),
        amount_out_min: "90".to_string(),
    }
}

fn quote() -> UnparsedZeroExSwapQuote {
    let settlement = ISettlerTakerSubmitted::executeCall {
        slippage: AllowedSlippage {
            recipient: WALLET,
            buyToken: USDC_ADDRESS,
            minAmountOut: U256::from(90),
        },
        actions: vec![Bytes::from_static(&[1, 2, 3, 4])],
        affiliate: B256::ZERO,
    };
    UnparsedZeroExSwapQuote {
        to: ALLOWANCE_HOLDER_ADDRESS.to_string(),
        value: "0".to_string(),
        data: Bytes::from(
            IAllowanceHolder::execCall {
                operator: SETTLER,
                token: WLD_ADDRESS,
                amount: U256::from(100),
                target: SETTLER,
                data: settlement.abi_encode().into(),
            }
            .abi_encode(),
        )
        .to_string(),
        amount_out: "95".to_string(),
    }
}

struct TestHttpClient(Mutex<Arc<dyn AuthenticatedHttpClient>>);

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

struct ScriptedHttpClient {
    responses: Mutex<VecDeque<Value>>,
    requests: Mutex<Vec<Value>>,
}

#[async_trait::async_trait]
impl AuthenticatedHttpClient for ScriptedHttpClient {
    async fn fetch_from_app_backend(
        &self,
        url: String,
        _method: HttpMethod,
        _headers: Vec<HttpHeader>,
        body: Option<Vec<u8>>,
    ) -> Result<Vec<u8>, HttpError> {
        let request: Value = serde_json::from_slice(&body.unwrap()).unwrap();
        let method = request["method"].as_str().unwrap();
        let expected_url = match method {
            "eth_call" => "/v2/rpc/worldchain",
            "pm_sponsorUserOperation"
            | "wa_screenAddresses"
            | "eth_sendUserOperation" => "/v3/rpc/worldchain",
            _ => panic!("unexpected RPC method: {method}"),
        };
        assert_eq!(url, expected_url);
        self.requests.lock().unwrap().push(request);
        let response = self
            .responses
            .lock()
            .unwrap()
            .pop_front()
            .expect("unexpected RPC request");
        Ok(serde_json::to_vec(&response).unwrap())
    }
}

fn install(responses: Vec<Value>) -> Arc<ScriptedHttpClient> {
    let client = Arc::new(ScriptedHttpClient {
        responses: Mutex::new(responses.into()),
        requests: Mutex::new(Vec::new()),
    });
    install_client(client.clone());
    client
}

fn install_client(client: Arc<dyn AuthenticatedHttpClient>) {
    // The public initializer is one-shot; serialized tests replace its delegate.
    static HTTP: OnceLock<Arc<TestHttpClient>> = OnceLock::new();
    let http = HTTP.get_or_init(|| {
        let http = Arc::new(TestHttpClient(Mutex::new(client.clone())));
        set_http_client(http.clone());
        http
    });
    *http.0.lock().unwrap() = client;
}

fn registry(current: Address, previous: Address) -> Value {
    let results = [current, previous].map(|address| IMulticall3::Result {
        success: true,
        returnData: ISettlerRegistry::ownerOfCall::abi_encode_returns(&address).into(),
    });
    json!({"result": Bytes::from(IMulticall3::aggregate3Call::abi_encode_returns(&results.to_vec()))})
}

fn sponsored() -> Value {
    json!({"result": {
        "callGasLimit": "0x10000", "verificationGasLimit": "0x10000",
        "preVerificationGas": "0x0", "maxFeePerGas": "0x0",
        "maxPriorityFeePerGas": "0x0",
    }})
}

fn paid(token: Address) -> Value {
    let mut response = sponsored();
    let result = response["result"].as_object_mut().unwrap();
    result.extend(json!({
        "preVerificationGas": "0x2000",
        "maxFeePerGas": "0xa", "maxPriorityFeePerGas": "0x1",
        "paymaster": TFH_PAYMASTER_ADDRESS,
        "paymasterVerificationGasLimit": "0x10000", "paymasterPostOpGasLimit": "0x1000",
        "paymasterData": Bytes::from((token, U256::from(1_000_000_000_000_000_000_u64), U256::from(2000)).abi_encode()),
        "fee": {"token": token, "estimatedCostInToken": "10", "declineReason": "future_policy"},
    }).as_object().unwrap().clone());
    response
}

fn uint_response(amount: u64) -> Value {
    json!({"result": format!("0x{:064x}", U256::from(amount))})
}

async fn prepare(
    custom: Option<String>,
) -> Result<PreparedTransaction, TransactionError> {
    account(WALLET)
        .prepare_transaction_swap(request(), quote(), custom)
        .await
}

async fn bundler(submission: Value) -> MockServer {
    let server = MockServer::start().await;
    Mock::given(body_partial_json(
        json!({"method": "eth_estimateUserOperationGas"}),
    ))
    .respond_with(ResponseTemplate::new(200).set_body_json(json!({"result": {
        "callGasLimit": "0xc350", "verificationGasLimit": "0xea60",
    }})))
    .mount(&server)
    .await;
    Mock::given(body_partial_json(
        json!({"method": "eth_sendUserOperation"}),
    ))
    .respond_with(ResponseTemplate::new(200).set_body_json(submission))
    .mount(&server)
    .await;
    server
}

fn assert_dummy_signature(operation: &Value) {
    let signature: Bytes =
        serde_json::from_value(operation["signature"].clone()).unwrap();
    assert_eq!(signature.len(), 77);
    assert_eq!(&signature[12..], &[0xff; 65]);
    assert!(signature[..12] == [0xff; 12] || signature[..12] == [0; 12]);
}

#[tokio::test]
#[serial_test::serial]
async fn default_prepares_without_signing_then_submits_retained_swap_after_registry_recheck(
) {
    let http = install(vec![
        registry(SETTLER, Address::ZERO),
        json!({"result": true}),
        sponsored(),
        // The quote's Settler may move to the previous slot while confirmation is open.
        registry(OTHER, SETTLER),
        json!({"result": HASH}),
    ]);
    let prepared = prepare(None).await.unwrap();
    assert!(prepared.fee_details().is_none());
    {
        let requests = http.requests.lock().unwrap();
        assert_eq!(requests.len(), 3);
        assert_eq!(requests[1]["method"], "wa_screenAddresses");
        assert_eq!(requests[1]["params"], json!([[WALLET]]));
        let operation = &requests[2]["params"][0];
        assert_dummy_signature(operation);
        let nonce: U256 = serde_json::from_value(operation["nonce"].clone()).unwrap();
        assert_eq!(&nonce.to_be_bytes::<32>()[..6], b"bdrck\x90");
        let expected = ZeroExSwap::new(
            &ZeroExSwapRequest {
                wallet_address: WALLET,
                token_in: WLD_ADDRESS,
                token_out: USDC_ADDRESS,
                amount_in: U256::from(100),
                amount_out_min: U256::from(90),
            },
            &ZeroExSwapQuote::try_from(quote()).unwrap(),
            SETTLER,
        )
        .unwrap();
        assert_eq!(
            operation["callData"],
            json!(expected.build_execute_user_op_call_data())
        );
    }
    let reviewed: Value =
        serde_json::from_str(&prepared.user_operation_json().unwrap()).unwrap();
    assert_dummy_signature(&reviewed);
    account(WALLET)
        .submit_prepared_transaction(&prepared)
        .await
        .unwrap();
    let requests = http.requests.lock().unwrap();
    assert_eq!(requests.len(), 5);
    assert_eq!(requests[3]["method"], "eth_call");
    assert_eq!(requests[4]["method"], "eth_sendUserOperation");
    let mut signed = requests[4]["params"][0].clone();
    signed["signature"] = reviewed["signature"].clone();
    assert_eq!(
        signed, reviewed,
        "metadata must describe the operation submitted after confirmation"
    );
    let mut sent = requests[4]["params"][0].clone();
    let mut expected = requests[2]["params"][0].clone();
    assert_ne!(sent["signature"], expected["signature"]);
    sent.as_object_mut().unwrap().remove("signature");
    expected.as_object_mut().unwrap().remove("signature");
    for (field, value) in sponsored()["result"].as_object().unwrap() {
        expected[field] = value.clone();
    }
    assert_eq!(
        sent, expected,
        "submission must preserve the reviewed operation and final fee fields"
    );
}

#[tokio::test]
#[serial_test::serial]
async fn custom_bundler_retains_estimated_fields_and_url_without_backend_fallback() {
    for response in [
        json!({"result": HASH}),
        json!({"error": {"code": -32500, "message": "unsupported"}}),
    ] {
        let http = install(vec![
            registry(SETTLER, Address::ZERO),
            json!({"result": true}),
            registry(SETTLER, Address::ZERO),
        ]);
        let server = bundler(response.clone()).await;
        let prepared = prepare(Some(format!("{}/rpc?key=private-key", server.uri())))
            .await
            .unwrap();
        assert!(prepared.fee_details().is_none());
        assert!(!format!("{prepared:?}").contains("private-key"));
        let exported = prepared.user_operation_json().unwrap();
        assert!(!exported.contains("private-key"));
        assert!(!exported.contains(&server.uri()));
        let before = server.received_requests().await.unwrap();
        assert_eq!(before.len(), 1);
        let estimate: Value = before[0].body_json().unwrap();
        assert_dummy_signature(&estimate["params"][0]);
        let result = account(WALLET).submit_prepared_transaction(&prepared).await;
        assert_eq!(result.is_ok(), response.get("result").is_some());
        let after = server.received_requests().await.unwrap();
        assert_eq!(after.len(), 2);
        assert_eq!(after[1].url.path(), "/rpc");
        assert_eq!(after[1].url.query(), Some("key=private-key"));
        let sent: Value = after[1].body_json().unwrap();
        assert_eq!(sent["method"], "eth_sendUserOperation");
        let operation = &sent["params"][0];
        for (field, value) in [
            ("callGasLimit", "0xc350"),
            ("verificationGasLimit", "0xea60"),
            ("preVerificationGas", "0x0"),
            ("maxFeePerGas", "0x0"),
            ("maxPriorityFeePerGas", "0x0"),
        ] {
            assert_eq!(operation[field], value);
        }
        assert!(operation["paymaster"].is_null());
        assert_ne!(operation["signature"], estimate["params"][0]["signature"]);
        assert_eq!(operation["callData"], estimate["params"][0]["callData"]);
        assert_eq!(http.requests.lock().unwrap().len(), 3);
    }
}

#[tokio::test]
#[serial_test::serial]
async fn paused_or_unrecognized_registry_blocks_preparation_before_estimation() {
    for response in [
        registry(Address::ZERO, SETTLER),
        registry(OTHER, Address::ZERO),
        json!({"error": {"code": -32000, "message": "registry unavailable"}}),
    ] {
        let http = install(vec![response]);
        assert!(prepare(None).await.is_err());
        assert_eq!(http.requests.lock().unwrap().len(), 1);
    }
}

#[tokio::test]
#[serial_test::serial]
async fn paused_rotated_or_unavailable_registry_blocks_both_submission_routes() {
    for custom in [false, true] {
        for response in [
            registry(Address::ZERO, SETTLER),
            registry(OTHER, Address::ZERO),
            json!({"error": {"code": -32000, "message": "registry unavailable"}}),
        ] {
            let mut responses =
                vec![registry(SETTLER, Address::ZERO), json!({"result": true})];
            if !custom {
                responses.push(sponsored());
            }
            responses.push(response);
            let http = install(responses);
            let server = bundler(json!({"result": HASH})).await;
            let prepared = prepare(custom.then(|| server.uri())).await.unwrap();
            let error = account(WALLET)
                .submit_prepared_transaction(&prepared)
                .await
                .unwrap_err();
            assert!(error
                .to_string()
                .contains("Failed to validate swap Settler"));
            {
                let requests = http.requests.lock().unwrap();
                assert_eq!(requests.len(), if custom { 3 } else { 4 });
                assert!(requests
                    .iter()
                    .all(|r| r["method"] != "eth_sendUserOperation"));
            }
            assert_eq!(
                server.received_requests().await.unwrap().len(),
                usize::from(custom)
            );
        }
    }
}

#[tokio::test]
#[serial_test::serial]
async fn both_routes_require_wallet_screening_without_screening_router_contracts() {
    for custom in [false, true] {
        for (response, expected) in [
            (
                json!({"error": {"code": -32602, "message": "restricted", "data": {"reason": "address_restricted"}}}),
                "restricted",
            ),
            (
                json!({"error": {"code": -32603, "message": "unavailable", "data": {"reason": "screening_unavailable"}}}),
                "unavailable",
            ),
            (json!({"result": false}), "screening failed"),
        ] {
            let mut responses = vec![registry(SETTLER, Address::ZERO), response];
            if !custom {
                responses.push(sponsored());
            }
            let http = install(responses);
            let server = bundler(json!({"result": HASH})).await;
            let error = prepare(custom.then(|| server.uri())).await.unwrap_err();
            match expected {
                "restricted" => {
                    assert!(matches!(error, TransactionError::AddressRestricted))
                }
                "unavailable" => {
                    assert!(matches!(error, TransactionError::ScreeningUnavailable))
                }
                _ => {
                    assert!(matches!(error, TransactionError::Generic { .. }));
                    assert!(error.to_string().contains(expected), "{error}");
                }
            }
            let requests = http.requests.lock().unwrap();
            assert_eq!(requests.len(), if custom { 2 } else { 3 });
            assert_eq!(requests[1]["params"], json!([[WALLET]]));
        }
    }
}

#[tokio::test]
#[serial_test::serial]
async fn self_sponsored_swap_requires_upfront_fee_balance_excluding_expected_proceeds()
{
    for (token, balance, success) in [
        (WLD_ADDRESS, 110, true),
        (WLD_ADDRESS, 109, false),
        (USDC_ADDRESS, 10, true),
        (USDC_ADDRESS, 9, false),
    ] {
        let http = install(vec![
            registry(SETTLER, Address::ZERO),
            json!({"result": true}),
            paid(token),
            uint_response(10),
            uint_response(balance),
        ]);
        let result = prepare(None).await;
        if success {
            let fee = result.unwrap().fee_details().unwrap();
            assert_eq!(fee.token_address, token.to_string());
            assert_eq!(fee.estimated_cost_in_token, "10");
        } else {
            assert!(
                matches!(result.unwrap_err(), TransactionError::InsufficientFunds { token_address } if token_address == token.to_string())
            );
        }
        assert_eq!(http.requests.lock().unwrap().len(), 5);
    }
}

#[tokio::test]
#[serial_test::serial]
async fn fee_allowance_is_required_before_returning_a_paid_swap() {
    let http = install(vec![
        registry(SETTLER, Address::ZERO),
        json!({"result": true}),
        paid(WLD_ADDRESS),
        uint_response(9),
    ]);
    let error = prepare(None).await.unwrap_err();
    assert!(error
        .to_string()
        .contains("Insufficient fee-token allowance"));
    assert_eq!(http.requests.lock().unwrap().len(), 4);
}

#[tokio::test]
#[serial_test::serial]
async fn wrong_account_is_rejected_before_registry_or_submission_requests() {
    let http = install(vec![
        registry(SETTLER, Address::ZERO),
        json!({"result": true}),
        sponsored(),
    ]);
    let prepared = prepare(None).await.unwrap();
    let error = account(OTHER)
        .submit_prepared_transaction(&prepared)
        .await
        .unwrap_err();
    assert!(error.to_string().contains("another account"));
    assert_eq!(http.requests.lock().unwrap().len(), 3);
}

#[tokio::test]
#[serial_test::serial]
async fn foreign_input_and_quote_mismatches_are_rejected_before_rpc() {
    let http = install(vec![]);
    let mut inputs = vec![];
    for value in ["invalid", "-1"] {
        inputs.push((
            UnparsedZeroExSwapRequest {
                amount_in: value.to_string(),
                ..request()
            },
            quote(),
        ));
    }
    inputs.push((
        request(),
        UnparsedZeroExSwapQuote {
            data: "invalid".to_string(),
            ..quote()
        },
    ));
    inputs.push((
        request(),
        UnparsedZeroExSwapQuote {
            amount_out: "invalid".to_string(),
            ..quote()
        },
    ));
    inputs.push((
        UnparsedZeroExSwapRequest {
            token_in: "invalid".to_string(),
            ..request()
        },
        quote(),
    ));
    inputs.push((
        UnparsedZeroExSwapRequest {
            amount_in: "101".to_string(),
            ..request()
        },
        quote(),
    ));
    inputs.push((
        UnparsedZeroExSwapRequest {
            token_out: OTHER.to_string(),
            ..request()
        },
        quote(),
    ));
    inputs.push((
        UnparsedZeroExSwapRequest {
            amount_out_min: "96".to_string(),
            ..request()
        },
        quote(),
    ));
    for (request, quote) in inputs {
        assert!(account(WALLET)
            .prepare_transaction_swap(request, quote, None)
            .await
            .is_err());
    }
    // The receiving wallet is derived from the account, rather than supplied by the quote.
    assert!(account(OTHER)
        .prepare_transaction_swap(request(), quote(), None)
        .await
        .is_err());
    assert!(http.requests.lock().unwrap().is_empty());
}

struct DelayedScreeningClient {
    inner: Arc<ScriptedHttpClient>,
    started: Arc<tokio::sync::Notify>,
    release: Arc<tokio::sync::Notify>,
    response: Value,
}

#[async_trait::async_trait]
impl AuthenticatedHttpClient for DelayedScreeningClient {
    async fn fetch_from_app_backend(
        &self,
        url: String,
        method: HttpMethod,
        headers: Vec<HttpHeader>,
        body: Option<Vec<u8>>,
    ) -> Result<Vec<u8>, HttpError> {
        let request: Value = serde_json::from_slice(body.as_deref().unwrap()).unwrap();
        if request["method"] == "wa_screenAddresses" {
            assert_eq!(url, "/v3/rpc/worldchain");
            assert_eq!(request["params"], json!([[WALLET]]));
            self.started.notify_one();
            self.release.notified().await;
            return Ok(serde_json::to_vec(&self.response).unwrap());
        }
        self.inner
            .fetch_from_app_backend(url, method, headers, body)
            .await
    }
}

#[tokio::test]
#[serial_test::serial]
async fn screening_outcome_takes_precedence_over_fast_preparation_failures_on_both_routes(
) {
    for custom in [false, true] {
        for reason in ["address_restricted", "screening_unavailable", "clear"] {
            let response = match reason {
                "address_restricted" => {
                    json!({"error": {"code": -32602, "message": "restricted", "data": {"reason": reason}}})
                }
                "screening_unavailable" => {
                    json!({"error": {"code": -32603, "message": "unavailable", "data": {"reason": reason}}})
                }
                _ => json!({"result": true}),
            };
            let mut responses = vec![registry(SETTLER, Address::ZERO)];
            if !custom {
                responses.push(json!({"error": {"code": -32000, "message": "sponsor unavailable"}}));
            }
            let http = install(responses);
            let started = Arc::new(tokio::sync::Notify::new());
            let release = Arc::new(tokio::sync::Notify::new());
            install_client(Arc::new(DelayedScreeningClient {
                inner: http.clone(),
                started: started.clone(),
                release: release.clone(),
                response,
            }));
            // URL validation fails before networking on the custom route.
            let preparation = prepare(custom.then(|| "http://example.com".to_string()));
            tokio::pin!(preparation);
            assert!(
                futures::poll!(&mut preparation).is_pending(),
                "preparation must wait for screening"
            );
            tokio::time::timeout(std::time::Duration::from_secs(5), started.notified())
                .await
                .unwrap();
            release.notify_one();
            let error = preparation.await.unwrap_err();
            match reason {
                "address_restricted" => {
                    assert!(matches!(error, TransactionError::AddressRestricted))
                }
                "screening_unavailable" => {
                    assert!(matches!(error, TransactionError::ScreeningUnavailable))
                }
                _ => assert!(matches!(error, TransactionError::Generic { .. })),
            }
            assert!(http
                .requests
                .lock()
                .unwrap()
                .iter()
                .all(|request| request["method"] != "eth_sendUserOperation"));
        }
    }
}

#[tokio::test]
#[serial_test::serial]
async fn registry_failure_preserves_the_rpc_cause_during_preparation_and_submission() {
    let unavailable = json!({"error": {"code": -32000, "message": "registry offline"}});
    install(vec![unavailable.clone()]);
    let error = prepare(None).await.unwrap_err();
    assert!(error.to_string().contains("registry offline"), "{error}");
    install(vec![
        registry(SETTLER, Address::ZERO),
        json!({"result": true}),
        sponsored(),
        unavailable,
    ]);
    let prepared = prepare(None).await.unwrap();
    let error = account(WALLET)
        .submit_prepared_transaction(&prepared)
        .await
        .unwrap_err();
    assert!(error.to_string().contains("registry offline"), "{error}");
}
