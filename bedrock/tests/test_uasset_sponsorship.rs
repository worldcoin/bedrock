use std::{
    collections::VecDeque,
    sync::{Arc, Mutex},
};

use bedrock::{
    primitives::{
        http_client::{set_http_client, HttpHeader},
        AuthenticatedHttpClient, HttpError, HttpMethod,
    },
    smart_account::SafeSmartAccount,
    transactions::{TransactionError, UAssetRedemption},
};
use serde_json::{json, Value};
use wiremock::{matchers::body_partial_json, Mock, MockServer, ResponseTemplate};

struct ScriptedHttpClient {
    responses: Mutex<VecDeque<(&'static str, Value)>>,
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
        assert_eq!(url, "/v3/rpc/worldchain");
        let request: Value = serde_json::from_slice(&body.unwrap()).unwrap();
        let (method, response) = self
            .responses
            .lock()
            .unwrap()
            .pop_front()
            .expect("unexpected RPC request");
        assert_eq!(request["method"], method);
        self.requests.lock().unwrap().push(request);
        Ok(serde_json::to_vec(&response).unwrap())
    }
}

#[tokio::test]
async fn redemption_uses_free_v3_or_custom_bundler_and_requires_screening() {
    let http = Arc::new(ScriptedHttpClient {
        responses: Mutex::default(),
        requests: Mutex::default(),
    });
    set_http_client(http.clone());
    let account = SafeSmartAccount::from_private_key_hex(
        "4142710b9b4caaeb000b8e5de271bbebac7f509aab2f5e61d1ed1958bfe6d583".to_string(),
        "0x4564420674EA68fcc61b463C0494807C759d47e6",
    )
    .unwrap();
    let vault = "0x1f69bbf9f7ed316bcf1e0cf12f81d261a9bdc2ca";
    let quote = || {
        vec![UAssetRedemption {
            token_address: "0x2222222222222222222222222222222222222222".to_string(),
            amount: "1000000000000000000".to_string(),
            minimum_usdc_amount: "1000000".to_string(),
        }]
    };
    let free = json!({"jsonrpc": "2.0", "id": 1, "result": {
        "callGasLimit": "0x10000", "verificationGasLimit": "0x10000",
        "preVerificationGas": "0x0", "maxFeePerGas": "0x0", "maxPriorityFeePerGas": "0x0"
    }});
    let screened = json!({"jsonrpc": "2.0", "id": 1, "result": true});
    let hash = format!("0x{}", "ab".repeat(32));
    http.responses.lock().unwrap().extend([
        ("wa_screenAddresses", screened.clone()),
        ("pm_sponsorUserOperation", free.clone()),
        (
            "eth_sendUserOperation",
            json!({"jsonrpc": "2.0", "id": 1, "result": hash}),
        ),
    ]);
    let result = account
        .transaction_uasset_redeem(vault, quote(), None)
        .await
        .unwrap();
    assert_eq!(result.as_str(), hash);
    let requests = http.requests.lock().unwrap().clone();
    let submitted = &requests[2]["params"][0];
    assert_eq!(submitted["maxFeePerGas"], "0x0");
    assert_eq!(submitted["maxPriorityFeePerGas"], "0x0");
    assert!(submitted["paymaster"].is_null());
    assert!(http.responses.lock().unwrap().is_empty());

    let mut paid = free;
    paid["result"]["preVerificationGas"] = json!("0x1000");
    paid["result"]["maxFeePerGas"] = json!("0x1");
    paid["result"]["paymaster"] = json!(vault);
    paid["result"]["paymasterVerificationGasLimit"] = json!("0x1000");
    paid["result"]["paymasterPostOpGasLimit"] = json!("0x1000");
    paid["result"]["paymasterData"] = json!("0x01");
    paid["result"]["fee"] = json!({
        "estimatedCostInToken": "10", "token": vault, "declineReason": "base_fee",
    });
    let declined = json!({"jsonrpc": "2.0", "id": 1,
        "error": {"code": -32602, "message": "sponsorship declined", "data": {"reason": "gas_usage"}}});
    for sponsorship in [paid, declined] {
        http.requests.lock().unwrap().clear();
        http.responses.lock().unwrap().extend([
            ("wa_screenAddresses", screened.clone()),
            ("pm_sponsorUserOperation", sponsorship),
        ]);
        assert!(account
            .transaction_uasset_redeem(vault, quote(), None)
            .await
            .is_err());
        assert_eq!(http.requests.lock().unwrap().len(), 2);
        assert!(http.responses.lock().unwrap().is_empty());
    }

    // Custom estimation and submission never use backend sponsorship/submission.
    for failure in [None, Some("estimate"), Some("submit")] {
        http.requests.lock().unwrap().clear();
        http.responses
            .lock()
            .unwrap()
            .push_back(("wa_screenAddresses", screened.clone()));
        let server = MockServer::start().await;
        let rpc_error = json!({"jsonrpc": "2.0", "id": 1,
            "error": {"code": -32603, "message": "bundler unavailable"}});
        Mock::given(body_partial_json(
            json!({"method": "eth_estimateUserOperationGas"}),
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(
            if failure == Some("estimate") {
                rpc_error.clone()
            } else {
                json!({"jsonrpc": "2.0", "id": 1, "result": {
                    "callGasLimit": "0xc350", "verificationGasLimit": "0xea60",
                    "preVerificationGas": "0xffff"}})
            },
        ))
        .expect(1)
        .mount(&server)
        .await;
        Mock::given(body_partial_json(
            json!({"method": "eth_sendUserOperation"}),
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(
            if failure == Some("submit") {
                rpc_error
            } else {
                json!({"jsonrpc": "2.0", "id": 1, "result": hash})
            },
        ))
        .expect(if failure == Some("estimate") { 0 } else { 1 })
        .mount(&server)
        .await;
        let result = account
            .transaction_uasset_redeem(vault, quote(), Some(server.uri()))
            .await;
        match failure {
            None => assert_eq!(result.unwrap().as_str(), hash),
            Some(stage) => {
                let error = result.unwrap_err().to_string();
                assert!(
                    error.contains(if stage == "estimate" {
                        "Custom bundler preparation failed"
                    } else {
                        "Custom bundler submission failed"
                    }),
                    "{error}"
                );
            }
        }
        assert_eq!(http.requests.lock().unwrap().len(), 1);
        assert!(http.responses.lock().unwrap().is_empty());
        let requests = server.received_requests().await.unwrap();
        if failure != Some("estimate") {
            let estimate: Value = requests[0].body_json().unwrap();
            let submitted: Value = requests[1].body_json().unwrap();
            let op = &submitted["params"][0];
            assert_eq!(op["callData"], estimate["params"][0]["callData"]);
            assert_eq!(op["callGasLimit"], "0xc350");
            assert_eq!(op["verificationGasLimit"], "0xea60");
            assert_eq!(op["preVerificationGas"], "0x0");
            assert_eq!(op["maxFeePerGas"], "0x0");
            assert_eq!(op["maxPriorityFeePerGas"], "0x0");
            assert!(op["paymaster"].is_null());
            assert_ne!(op["signature"], estimate["params"][0]["signature"]);
        }
        server.verify().await;
    }

    // Both routes stop before estimation or submission when screening fails.
    let server = MockServer::start().await;
    for custom_bundler_url in [None, Some(server.uri())] {
        http.requests.lock().unwrap().clear();
        http.responses.lock().unwrap().push_back(("wa_screenAddresses", json!({
            "jsonrpc": "2.0", "id": 1, "error": {
                "code": -32602, "message": "Address is restricted", "data": {"reason": "address_restricted"}
            }
        })));
        assert!(matches!(
            account
                .transaction_uasset_redeem(vault, quote(), custom_bundler_url.clone())
                .await,
            Err(TransactionError::AddressRestricted)
        ));
        assert_eq!(http.requests.lock().unwrap().len(), 1);
        http.requests.lock().unwrap().clear();
        assert!(account
            .transaction_uasset_redeem(vault, vec![], custom_bundler_url.clone())
            .await
            .is_err());
        assert!(account
            .transaction_uasset_redeem(
                "0x1111111111111111111111111111111111111111",
                quote(),
                custom_bundler_url,
            )
            .await
            .is_err());
        assert!(http.requests.lock().unwrap().is_empty());
    }
    assert!(server.received_requests().await.unwrap().is_empty());
}
