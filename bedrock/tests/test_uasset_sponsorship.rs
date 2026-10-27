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
    transactions::{TransactionError, UAssetRedemption, UserOperationStage},
};
use serde_json::{json, Value};

struct ScriptedHttpClient {
    responses: Mutex<VecDeque<(&'static str, Result<Value, HttpError>)>>,
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
        response.map(|response| serde_json::to_vec(&response).unwrap())
    }
}

#[tokio::test]
async fn redemption_requires_free_v3_sponsorship_and_wallet_screening() {
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
    let vault = "0x1111111111111111111111111111111111111111";
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
        ("wa_screenAddresses", Ok(screened.clone())),
        ("pm_sponsorUserOperation", Ok(free.clone())),
        (
            "eth_sendUserOperation",
            Ok(json!({"jsonrpc": "2.0", "id": 1, "result": hash})),
        ),
    ]);
    let result = account
        .transaction_uasset_redeem(vault, quote())
        .await
        .unwrap();
    assert_eq!(result.as_str(), hash);
    let requests = http.requests.lock().unwrap().clone();
    let submitted = &requests[2]["params"][0];
    assert_eq!(submitted["maxFeePerGas"], "0x0");
    assert_eq!(submitted["maxPriorityFeePerGas"], "0x0");
    assert!(submitted["paymaster"].is_null());
    assert!(http.responses.lock().unwrap().is_empty());

    let mut paid = free.clone();
    paid["result"]["preVerificationGas"] = json!("0x1000");
    paid["result"]["maxFeePerGas"] = json!("0x1");
    paid["result"]["paymaster"] = json!(vault);
    paid["result"]["paymasterVerificationGasLimit"] = json!("0x1000");
    paid["result"]["paymasterPostOpGasLimit"] = json!("0x1000");
    paid["result"]["paymasterData"] = json!("0x01");
    paid["result"]["fee"] = json!({
        "estimatedCostInToken": "10", "token": vault, "declineReason": "gas_usage",
    });
    let declined = json!({"jsonrpc": "2.0", "id": 1,
        "error": {"code": -32602, "message": "sponsorship declined", "data": {"reason": "tx_count"}}});
    let mut malformed = free.clone();
    malformed["result"]["callGasLimit"] = json!("0x0");
    for (sponsorship, code, reason) in [
        (paid, None, Some("gas_usage")),
        (declined, Some(-32602), Some("tx_count")),
        (malformed, None, None),
    ] {
        http.requests.lock().unwrap().clear();
        http.responses.lock().unwrap().extend([
            ("wa_screenAddresses", Ok(screened.clone())),
            ("pm_sponsorUserOperation", Ok(sponsorship)),
        ]);
        let error = account
            .transaction_uasset_redeem(vault, quote())
            .await
            .unwrap_err();
        let TransactionError::UserOperationFailed { failure } = error else {
            panic!("Expected structured sponsorship failure: {error:?}");
        };
        assert_eq!(failure.stage, UserOperationStage::Sponsorship);
        assert_eq!(failure.rpc_code, code);
        assert_eq!(failure.reason.as_deref(), reason);
        assert!(!failure.transport_error);
        assert_eq!(http.requests.lock().unwrap().len(), 2);
        assert!(http.responses.lock().unwrap().is_empty());
    }

    // A bundler rejection remains distinguishable from a transport failure.
    http.requests.lock().unwrap().clear();
    http.responses.lock().unwrap().extend([
        ("wa_screenAddresses", Ok(screened.clone())),
        ("pm_sponsorUserOperation", Ok(free.clone())),
        ("eth_sendUserOperation", Ok(json!({
            "jsonrpc": "2.0", "id": 1,
            "error": {"code": -32521, "message": "execution reverted", "data": {"reason": "validation_failed"}}
        }))),
    ]);
    let error = account
        .transaction_uasset_redeem(vault, quote())
        .await
        .unwrap_err();
    let TransactionError::UserOperationFailed { failure } = error else {
        panic!("Expected structured submission failure: {error:?}");
    };
    assert_eq!(failure.stage, UserOperationStage::Submission);
    assert_eq!(failure.rpc_code, Some(-32521));
    assert_eq!(failure.reason.as_deref(), Some("validation_failed"));
    assert!(!failure.transport_error);
    assert_eq!(http.requests.lock().unwrap().len(), 3);

    for stage in [
        UserOperationStage::Sponsorship,
        UserOperationStage::Submission,
    ] {
        http.requests.lock().unwrap().clear();
        http.responses
            .lock()
            .unwrap()
            .push_back(("wa_screenAddresses", Ok(screened.clone())));
        if stage == UserOperationStage::Submission {
            http.responses
                .lock()
                .unwrap()
                .push_back(("pm_sponsorUserOperation", Ok(free.clone())));
        }
        let method = if stage == UserOperationStage::Submission {
            "eth_sendUserOperation"
        } else {
            "pm_sponsorUserOperation"
        };
        http.responses
            .lock()
            .unwrap()
            .push_back((method, Err(HttpError::Timeout)));
        let error = account
            .transaction_uasset_redeem(vault, quote())
            .await
            .unwrap_err();
        let TransactionError::UserOperationFailed { failure } = error else {
            panic!("Expected structured transport failure: {error:?}");
        };
        assert_eq!(failure.stage, stage);
        assert!(failure.transport_error);
        assert_eq!(failure.rpc_code, None);
        assert_eq!(failure.reason, None);
        let expected_requests = if stage == UserOperationStage::Submission {
            3
        } else {
            2
        };
        assert_eq!(http.requests.lock().unwrap().len(), expected_requests);
        assert!(http.responses.lock().unwrap().is_empty());
    }

    http.requests.lock().unwrap().clear();
    http.responses.lock().unwrap().push_back(("wa_screenAddresses", Ok(json!({
        "jsonrpc": "2.0", "id": 1, "error": {
            "code": -32602, "message": "Address is restricted", "data": {"reason": "address_restricted"}
        }
    }))));
    assert!(matches!(
        account.transaction_uasset_redeem(vault, quote()).await,
        Err(TransactionError::AddressRestricted)
    ));
    assert_eq!(http.requests.lock().unwrap().len(), 1);
    http.requests.lock().unwrap().clear();
    assert!(account
        .transaction_uasset_redeem(vault, vec![])
        .await
        .is_err());
    assert!(http.requests.lock().unwrap().is_empty());
}
