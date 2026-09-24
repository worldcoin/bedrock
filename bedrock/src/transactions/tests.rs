use super::*;
use crate::primitives::http_client::HttpHeader;
use crate::primitives::{AuthenticatedHttpClient, HttpError, HttpMethod};
use crate::transactions::contracts::worldchain::{TFH_PAYMASTER_ADDRESS, WLD_ADDRESS};
use alloy::primitives::address;
use serde_json::{json, Value};
use std::collections::VecDeque;
use std::sync::Mutex;

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
        assert_eq!(url, "/v2/rpc/worldchain");
        assert_eq!(request["method"], "pm_sponsorUserOperation");
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

fn rpc(responses: Vec<Value>) -> (RpcClient, Arc<ScriptedHttpClient>) {
    let http = Arc::new(ScriptedHttpClient {
        responses: Mutex::new(responses.into()),
        requests: Mutex::new(Vec::new()),
    });
    (RpcClient::new(http.clone()), http)
}

fn decline() -> PmSponsorshipDecline {
    serde_json::from_value(json!({
        "token": WLD_ADDRESS,
        "paymasterAddress": TFH_PAYMASTER_ADDRESS,
        "reason": "future_policy",
        "estimatedCostInToken": "10",
    }))
    .unwrap()
}

fn token_sponsorship() -> Value {
    json!({
        "jsonrpc": "2.0", "id": "test",
        "result": {
            "callGasLimit": "0x10000",
            "verificationGasLimit": "0x10000",
            "preVerificationGas": "0x2000",
            "maxFeePerGas": "0xa",
            "maxPriorityFeePerGas": "0x1",
            "paymaster": TFH_PAYMASTER_ADDRESS,
            "paymasterData": "0x1234",
            "paymasterVerificationGasLimit": "0x10000",
            "paymasterPostOpGasLimit": "0x1000",
        },
    })
}

fn transfer() -> UserOperation {
    Erc20::new(
        WLD_ADDRESS,
        address!("1234567890123456789012345678901234567890"),
        U256::from(7),
    )
    .build_preflight_user_operation(
        address!("4564420674ea68fcc61b463c0494807c759d47e6"),
        Some(MetadataArg {
            association: Some(TransferAssociation::XmtpMessage),
        }),
    )
    .unwrap()
}

#[tokio::test]
async fn token_retry_preserves_unsigned_transfer_and_exposes_advisory() {
    let original = transfer();
    let response = token_sponsorship();
    let (rpc, http) = rpc(vec![response.clone()]);
    let prepared = prepare_self_sponsored_transfer(&rpc, original.clone(), &decline())
        .await
        .unwrap();
    assert_eq!(prepared.user_operation.sender, original.sender);
    assert_eq!(prepared.user_operation.call_data, original.call_data);
    assert_eq!(prepared.user_operation.nonce, original.nonce);
    assert_eq!(prepared.user_operation.signature, original.signature);
    assert_eq!(
        prepared.user_operation.paymaster,
        Some(TFH_PAYMASTER_ADDRESS)
    );
    let operation = serde_json::to_value(&prepared.user_operation).unwrap();
    for (field, value) in response["result"].as_object().unwrap() {
        if field == "paymaster" {
            continue;
        }
        assert_eq!(&operation[field], value, "{field}");
    }
    let fee = prepared.fee_details().unwrap();
    assert_eq!(fee.token_address, WLD_ADDRESS.to_string());
    assert_eq!(fee.paymaster_address, TFH_PAYMASTER_ADDRESS.to_string());
    assert_eq!(fee.decline_reason, "future_policy");
    assert_eq!(fee.estimated_cost_in_token, "10");

    // Preparation only retries sponsorship: no allowance reads or submissions.
    let requests = http.requests.lock().unwrap();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0]["params"][0], json!(original));
    assert_eq!(requests[0]["params"][1], json!(*ENTRYPOINT_4337));
    assert_eq!(requests[0]["params"][2], json!({"token": WLD_ADDRESS}));
    assert!(http.responses.lock().unwrap().is_empty());
}

#[tokio::test]
async fn invalid_fee_estimate_stops_before_token_retry() {
    for estimate in [
        "0",
        "-1",
        "1.5",
        "invalid",
        "0x10",
        "115792089237316195423570985008687907853269984665640564039457584007913129639936",
    ] {
        let mut decline = decline();
        decline.estimated_cost_in_token = estimate.to_string();
        let (rpc, http) = rpc(vec![]);
        let error = prepare_self_sponsored_transfer(&rpc, transfer(), &decline)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("fee estimate"));
        assert!(http.requests.lock().unwrap().is_empty());
    }
}

#[tokio::test]
async fn non_tfh_advisory_stops_even_if_token_sponsorship_would_match() {
    let unexpected_paymaster = address!("1111111111111111111111111111111111111111");
    let mut decline = decline();
    decline.paymaster_address = unexpected_paymaster;
    let mut response = token_sponsorship();
    response["result"]["paymaster"] = json!(unexpected_paymaster);
    let (rpc, http) = rpc(vec![response]);

    let error = prepare_self_sponsored_transfer(&rpc, transfer(), &decline)
        .await
        .unwrap_err();
    assert!(error
        .to_string()
        .contains("requires the migrated TFH paymaster"));
    assert!(http.requests.lock().unwrap().is_empty());
}

#[tokio::test]
async fn missing_or_mismatched_paymaster_fields_stop_preparation() {
    for field in [
        "paymaster",
        "paymasterData",
        "paymasterVerificationGasLimit",
        "paymasterPostOpGasLimit",
        "mismatchedPaymaster",
    ] {
        let mut response = token_sponsorship();
        if field == "mismatchedPaymaster" {
            response["result"]["paymaster"] = json!(Address::ZERO);
        } else {
            response["result"].as_object_mut().unwrap().remove(field);
        }
        let (rpc, http) = rpc(vec![response]);
        let error = prepare_self_sponsored_transfer(&rpc, transfer(), &decline())
            .await
            .unwrap_err();
        assert!(error.to_string().contains("paymaster fields"), "{field}");
        assert_eq!(http.requests.lock().unwrap().len(), 1);
    }
}

#[tokio::test]
async fn token_sponsorship_decline_stops_without_another_retry() {
    let (rpc, http) = rpc(vec![json!({
        "jsonrpc": "2.0", "id": "test",
        "error": {
            "code": -32602, "message": "sponsorship declined",
            "data": {
                "token": WLD_ADDRESS, "paymasterAddress": TFH_PAYMASTER_ADDRESS,
                "reason": "future_policy", "estimatedCostInToken": "10",
            },
        },
    })]);
    let error = prepare_self_sponsored_transfer(&rpc, transfer(), &decline())
        .await
        .unwrap_err();
    assert!(error
        .to_string()
        .contains("Token-paid sponsorship was declined"));
    assert_eq!(http.requests.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn token_sponsorship_error_stops_without_submission() {
    let (rpc, http) = rpc(vec![json!({
        "jsonrpc": "2.0", "id": "test",
        "error": { "code": -32603, "message": "sponsorship unavailable" },
    })]);
    let error = prepare_self_sponsored_transfer(&rpc, transfer(), &decline())
        .await
        .unwrap_err();
    assert!(error.to_string().contains("sponsorship unavailable"));
    assert_eq!(http.requests.lock().unwrap().len(), 1);
}
