use alloy::primitives::{address, Address, Bytes, U256};
use alloy::sol_types::SolValue;
use bedrock::{
    primitives::{
        http_client::{set_http_client, HttpHeader},
        AuthenticatedHttpClient, HttpError, HttpMethod,
    },
    smart_account::SafeSmartAccount,
    transactions::{
        contracts::worldchain::{TFH_PAYMASTER_ADDRESS, WLD_ADDRESS},
        PreparedTransaction, TransactionError,
    },
};
use serde_json::{json, Value};
use std::{
    collections::VecDeque,
    sync::{Arc, Mutex, OnceLock},
};
use wiremock::{matchers::body_partial_json, Mock, MockServer, ResponseTemplate};

const TEST_RECIPIENT: Address = address!("1234567890123456789012345678901234567890");

fn account() -> SafeSmartAccount {
    SafeSmartAccount::from_private_key_hex(
        "4142710b9b4caaeb000b8e5de271bbebac7f509aab2f5e61d1ed1958bfe6d583".to_string(),
        "0x4564420674EA68fcc61b463C0494807C759d47e6",
    )
    .unwrap()
}

struct TestHttpClient {
    inner: Mutex<Arc<dyn AuthenticatedHttpClient>>,
}

#[async_trait::async_trait]
impl AuthenticatedHttpClient for TestHttpClient {
    async fn fetch_from_app_backend(
        &self,
        url: String,
        method: HttpMethod,
        headers: Vec<HttpHeader>,
        body: Option<Vec<u8>>,
    ) -> Result<Vec<u8>, HttpError> {
        let client = self.inner.lock().unwrap().clone();
        client
            .fetch_from_app_backend(url, method, headers, body)
            .await
    }
}

async fn prepare_transfer(
    client: &Arc<dyn AuthenticatedHttpClient>,
    custom_url: Option<&str>,
) -> Result<PreparedTransaction, TransactionError> {
    // The public initializer is one-shot; serialized tests replace this test client's delegate.
    static HTTP_CLIENT: OnceLock<Arc<TestHttpClient>> = OnceLock::new();
    let http = HTTP_CLIENT.get_or_init(|| {
        let http = Arc::new(TestHttpClient {
            inner: Mutex::new(client.clone()),
        });
        set_http_client(http.clone());
        http
    });
    *http.inner.lock().unwrap() = client.clone();
    account()
        .prepare_transaction_transfer(
            &WLD_ADDRESS.to_string(),
            &TEST_RECIPIENT.to_string(),
            "7",
            None,
            custom_url.map(str::to_owned),
        )
        .await
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
        match request["method"].as_str() {
            Some("pm_sponsorUserOperation" | "wa_screenAddresses") => {
                assert_eq!(url, "/v3/rpc/worldchain");
            }
            Some("eth_call") => assert_eq!(url, "/v2/rpc/worldchain"),
            method => panic!("unexpected RPC method: {method:?}"),
        }
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

fn rpc(
    responses: Vec<Value>,
) -> (Arc<dyn AuthenticatedHttpClient>, Arc<ScriptedHttpClient>) {
    let http = Arc::new(ScriptedHttpClient {
        responses: Mutex::new(responses.into()),
        requests: Mutex::new(Vec::new()),
    });
    (http.clone(), http)
}

fn uint_response(amount: u64) -> Value {
    json!({
        "jsonrpc": "2.0", "id": "test",
        "result": format!("0x{:064x}", U256::from(amount)),
    })
}

fn token_sponsorship(token: Address) -> Value {
    json!({
        "jsonrpc": "2.0", "id": "test",
        "result": {
            "callGasLimit": "0x10000",
            "verificationGasLimit": "0x10000",
            "preVerificationGas": "0x2000",
            "maxFeePerGas": "0xa",
            "maxPriorityFeePerGas": "0x1",
            "paymaster": TFH_PAYMASTER_ADDRESS,
            "fee": {
                "estimatedCostInToken": "10",
                "token": token,
                "declineReason": "future_policy",
            },
            "paymasterData": Bytes::from((token, U256::from(1_000_000_000_000_000_000_u64), U256::from(2000)).abi_encode()),
            "paymasterVerificationGasLimit": "0x10000",
            "paymasterPostOpGasLimit": "0x1000",
        },
    })
}

#[tokio::test]
#[serial_test::serial]
async fn custom_bundler_requires_address_clearance() {
    for response in [
        json!({"error": {"code": -32602, "message": "Address is restricted"}}),
        json!({"error": {"code": -32603, "message": "Address screening unavailable"}}),
        json!({"result": false}),
        json!({"result": null}),
        json!({"result": "true"}),
        json!({}),
    ] {
        let server = MockServer::start().await;
        Mock::given(body_partial_json(
            json!({"method": "eth_estimateUserOperationGas"}),
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "result": {"callGasLimit": "0xc350", "verificationGasLimit": "0xea60"}
        })))
        .mount(&server)
        .await;
        let (client, http) = rpc(vec![response]);
        assert!(prepare_transfer(&client, Some(&server.uri()))
            .await
            .is_err());
        assert_eq!(
            http.requests.lock().unwrap().len(),
            1,
            "screening must not retry through another route"
        );
        for request in server.received_requests().await.unwrap() {
            let body: Value = request.body_json().unwrap();
            assert_eq!(body["method"], "eth_estimateUserOperationGas");
        }
    }
}

struct PendingScreeningClient {
    started: Arc<tokio::sync::Notify>,
    release: Arc<tokio::sync::Notify>,
}

#[async_trait::async_trait]
impl AuthenticatedHttpClient for PendingScreeningClient {
    async fn fetch_from_app_backend(
        &self,
        _url: String,
        _method: HttpMethod,
        _headers: Vec<HttpHeader>,
        _body: Option<Vec<u8>>,
    ) -> Result<Vec<u8>, HttpError> {
        self.started.notify_one();
        self.release.notified().await;
        Ok(serde_json::to_vec(&json!({"result": true})).unwrap())
    }
}

#[tokio::test]
#[serial_test::serial]
async fn custom_bundler_estimates_in_parallel_and_waits_for_screening() {
    let screening_started = Arc::new(tokio::sync::Notify::new());
    let release_screening = Arc::new(tokio::sync::Notify::new());
    let estimation_started = Arc::new(tokio::sync::Notify::new());
    let client: Arc<dyn AuthenticatedHttpClient> = Arc::new(PendingScreeningClient {
        started: screening_started.clone(),
        release: release_screening.clone(),
    });
    let server = MockServer::start().await;
    let estimated = estimation_started.clone();
    Mock::given(body_partial_json(
        json!({"method": "eth_estimateUserOperationGas"}),
    ))
    .respond_with(move |_: &wiremock::Request| {
        estimated.notify_one();
        ResponseTemplate::new(200).set_body_json(json!({
            "result": {"callGasLimit": "0xc350", "verificationGasLimit": "0xea60"}
        }))
    })
    .expect(1)
    .mount(&server)
    .await;
    let url = server.uri();
    let preparation = prepare_transfer(&client, Some(&url));
    tokio::pin!(preparation);
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        tokio::select! {
            result = &mut preparation => panic!("preparation finished before clearance: {result:?}"),
            () = async {
                screening_started.notified().await;
                estimation_started.notified().await;
            } => {}
        }
        assert!(futures::poll!(&mut preparation).is_pending());
        release_screening.notify_one();
        preparation.await.unwrap();
    }).await.expect("screening and estimation must start concurrently");
}

#[tokio::test]
#[serial_test::serial]
async fn custom_bundler_waits_for_estimation_after_clearance() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let (client, http) = rpc(vec![json!({"result": true})]);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let estimation_started = Arc::new(tokio::sync::Notify::new());
    let release_estimation = Arc::new(tokio::sync::Notify::new());
    let started = estimation_started.clone();
    let release = release_estimation.clone();
    let bundler = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut buffer = [0; 8192];
        assert!(socket.read(&mut buffer).await.unwrap() > 0);
        started.notify_one();
        release.notified().await;
        let body =
            json!({"result":{"callGasLimit":"0xc350","verificationGasLimit":"0xea60"}})
                .to_string();
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        socket.write_all(response.as_bytes()).await.unwrap();
    });
    let preparation = prepare_transfer(&client, Some(&url));
    tokio::pin!(preparation);
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        tokio::select! {
            result = &mut preparation => panic!("preparation finished before estimation: {result:?}"),
            () = estimation_started.notified() => {}
        }
        assert_eq!(http.requests.lock().unwrap().len(), 1);
        assert!(futures::poll!(&mut preparation).is_pending());
        release_estimation.notify_one();
        preparation.await.unwrap();
        bundler.await.unwrap();
    }).await.expect("preparation must await estimation after address clearance");
}

#[tokio::test]
#[serial_test::serial]
async fn default_route_screens_sender_and_recipient_before_returning_prepared_transfer()
{
    let (client, http) = rpc(vec![
        json!({"result": true}),
        token_sponsorship(WLD_ADDRESS),
        uint_response(10),
        uint_response(17),
    ]);
    let prepared = prepare_transfer(&client, None).await.unwrap();
    assert!(prepared.fee_details().is_some());
    let requests = http.requests.lock().unwrap();
    assert_eq!(requests[0]["method"], "wa_screenAddresses");
    assert_eq!(
        requests[0]["params"],
        json!([[account().wallet_address, TEST_RECIPIENT]])
    );
    assert_eq!(requests[1]["method"], "pm_sponsorUserOperation");
    assert_eq!(requests.len(), 4);
}

#[tokio::test]
#[serial_test::serial]
async fn default_route_requires_address_clearance() {
    for response in [
        json!({"error": {"code": -32602, "message": "Address is restricted"}}),
        json!({"error": {"code": -32603, "message": "Address screening unavailable"}}),
        json!({"result": false}),
        json!({"result": null}),
        json!({"result": "true"}),
        json!({}),
    ] {
        let (client, _) = rpc(vec![response]);
        let error = prepare_transfer(&client, None).await.unwrap_err();
        assert!(error.to_string().contains("Address screening failed"));
    }
}

struct PendingPreparationClient {
    started: [Arc<tokio::sync::Notify>; 2],
    release: [Arc<tokio::sync::Notify>; 2],
}

#[async_trait::async_trait]
impl AuthenticatedHttpClient for PendingPreparationClient {
    async fn fetch_from_app_backend(
        &self,
        _url: String,
        _method: HttpMethod,
        _headers: Vec<HttpHeader>,
        body: Option<Vec<u8>>,
    ) -> Result<Vec<u8>, HttpError> {
        let request: Value = serde_json::from_slice(&body.unwrap()).unwrap();
        let index = match request["method"].as_str().unwrap() {
            "wa_screenAddresses" => 0,
            "pm_sponsorUserOperation" => 1,
            method => panic!("unexpected RPC method: {method}"),
        };
        self.started[index].notify_one();
        self.release[index].notified().await;
        let response = if index == 0 {
            json!({"result": true})
        } else {
            json!({"result": {
                "callGasLimit": "0x10000", "verificationGasLimit": "0x10000",
                "preVerificationGas": "0x0", "maxFeePerGas": "0x0", "maxPriorityFeePerGas": "0x0"
            }})
        };
        Ok(serde_json::to_vec(&response).unwrap())
    }
}

#[tokio::test]
#[serial_test::serial]
async fn default_route_runs_requests_in_parallel_and_waits_for_both() {
    for first in 0..2 {
        let started = [
            Arc::new(tokio::sync::Notify::new()),
            Arc::new(tokio::sync::Notify::new()),
        ];
        let release = [
            Arc::new(tokio::sync::Notify::new()),
            Arc::new(tokio::sync::Notify::new()),
        ];
        let client: Arc<dyn AuthenticatedHttpClient> =
            Arc::new(PendingPreparationClient {
                started: started.clone(),
                release: release.clone(),
            });
        let preparation = prepare_transfer(&client, None);
        tokio::pin!(preparation);
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            tokio::select! {
                result = &mut preparation => panic!("preparation finished before responses: {result:?}"),
                () = async { started[0].notified().await; started[1].notified().await; } => {}
            }
            release[first].notify_one();
            assert!(futures::poll!(&mut preparation).is_pending());
            release[1-first].notify_one();
            preparation.await.unwrap();
        }).await.expect("screening and sponsorship must run concurrently and both finish");
    }
}

#[tokio::test]
#[serial_test::serial]
async fn preparation_preserves_screening_failure_classification_on_both_routes() {
    let server = MockServer::start().await;
    for custom_url in [None, Some(server.uri())] {
        for (code, reason, retryable) in [
            (-32602, "address_restricted", false),
            (-32603, "screening_unavailable", true),
        ] {
            let (client, _) = rpc(vec![json!({"error": {
                "code": code, "message": "Screening request failed",
                "data": {"reason": reason, "retryable": retryable}
            }})]);
            let error = prepare_transfer(&client, custom_url.as_deref())
                .await
                .unwrap_err();
            if retryable {
                assert!(matches!(error, TransactionError::ScreeningUnavailable));
            } else {
                assert!(matches!(error, TransactionError::AddressRestricted));
            }
        }
    }
}

#[tokio::test]
#[serial_test::serial]
async fn unknown_screening_errors_are_not_classified_as_restricted() {
    for data in [
        serde_json::Value::Null,
        json!({"reason": "invalid_addresses"}),
    ] {
        let (client, _) = rpc(vec![json!({"error": {
            "code": -32602, "message": "Address is restricted", "data": data
        }})]);
        let error = prepare_transfer(&client, None).await.unwrap_err();
        assert!(matches!(error, TransactionError::Generic { .. }));
    }
}
