use super::*;
use crate::primitives::http_client::HttpHeader;
use crate::primitives::{AuthenticatedHttpClient, HttpError, HttpMethod};
use crate::transactions::contracts::erc20::IErc20;
use crate::transactions::contracts::worldchain::{
    TFH_PAYMASTER_ADDRESS, USDC_ADDRESS, WLD_ADDRESS,
};
use alloy::primitives::{address, Bytes};
use alloy::sol_types::SolCall;
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
        assert!(matches!(
            request["method"].as_str(),
            Some("eth_call" | "pm_sponsorUserOperation")
        ));
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

fn allowance_response(amount: u64) -> Value {
    json!({
        "jsonrpc": "2.0", "id": "test",
        "result": format!("0x{:064x}", U256::from(amount)),
    })
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
    let (rpc, http) = rpc(vec![allowance_response(10), response.clone()]);
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

    // Preparation only reads allowance and retries sponsorship.
    let requests = http.requests.lock().unwrap();
    assert_eq!(requests.len(), 2);
    assert_eq!(requests[0]["method"], "eth_call");
    assert_eq!(requests[1]["method"], "pm_sponsorUserOperation");
    assert_eq!(requests[1]["params"][0], json!(original));
    assert_eq!(requests[1]["params"][1], json!(*ENTRYPOINT_4337));
    assert_eq!(requests[1]["params"][2], json!({"token": WLD_ADDRESS}));
    assert!(http.responses.lock().unwrap().is_empty());
}

#[tokio::test]
async fn insufficient_allowance_stops_before_token_retry() {
    for allowance in [0, 9] {
        let (rpc, http) = rpc(vec![allowance_response(allowance)]);
        let error = prepare_self_sponsored_transfer(&rpc, transfer(), &decline())
            .await
            .unwrap_err();
        assert!(error
            .to_string()
            .contains("Insufficient fee-token allowance"));
        let requests = http.requests.lock().unwrap();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0]["method"], "eth_call");
    }
}

#[tokio::test]
async fn allowance_read_failure_stops_before_token_retry() {
    for response in [
        json!({
            "jsonrpc": "2.0", "id": "test",
            "error": { "code": -32603, "message": "allowance unavailable" },
        }),
        json!({ "jsonrpc": "2.0", "id": "test", "result": "0x" }),
    ] {
        let (rpc, http) = rpc(vec![response]);
        let error = prepare_self_sponsored_transfer(&rpc, transfer(), &decline())
            .await
            .unwrap_err();
        assert!(error
            .to_string()
            .contains("Failed to read fee-token allowance"));
        let requests = http.requests.lock().unwrap();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0]["method"], "eth_call");
    }
}

#[tokio::test]
async fn allowance_checks_fee_token_sender_and_migrated_spender() {
    let original = transfer();
    let sender = original.sender;
    let mut decline = decline();
    decline.token = USDC_ADDRESS;
    let (rpc, http) = rpc(vec![allowance_response(11), token_sponsorship()]);
    let prepared = prepare_self_sponsored_transfer(&rpc, original, &decline)
        .await
        .unwrap();
    assert_eq!(
        prepared.fee_details().unwrap().estimated_cost_in_token,
        "10"
    );

    let requests = http.requests.lock().unwrap();
    assert_eq!(requests.len(), 2);
    assert_eq!(requests[0]["method"], "eth_call");
    assert_eq!(requests[0]["params"][0]["to"], json!(USDC_ADDRESS));
    assert_eq!(requests[0]["params"][1], "latest");
    let data: Bytes =
        serde_json::from_value(requests[0]["params"][0]["data"].clone()).unwrap();
    assert_eq!(&data[..4], &IErc20::allowanceCall::SELECTOR);
    let call = IErc20::allowanceCall::abi_decode_raw(&data[4..]).unwrap();
    assert_eq!(call.owner, sender);
    assert_eq!(call.spender, TFH_PAYMASTER_ADDRESS);
    assert_eq!(requests[1]["method"], "pm_sponsorUserOperation");
    assert_eq!(requests[1]["params"][2], json!({ "token": USDC_ADDRESS }));
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
        .contains("Self-sponsorship requires TFH paymaster"));
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
        let (rpc, http) = rpc(vec![allowance_response(10), response]);
        let error = prepare_self_sponsored_transfer(&rpc, transfer(), &decline())
            .await
            .unwrap_err();
        assert!(error.to_string().contains("paymaster fields"), "{field}");
        assert_eq!(http.requests.lock().unwrap().len(), 2);
    }
}

#[tokio::test]
async fn token_sponsorship_decline_stops_without_another_retry() {
    let (rpc, http) = rpc(vec![
        allowance_response(10),
        json!({
            "jsonrpc": "2.0", "id": "test",
            "error": {
                "code": -32602, "message": "sponsorship declined",
                "data": {
                    "token": WLD_ADDRESS, "paymasterAddress": TFH_PAYMASTER_ADDRESS,
                    "reason": "future_policy", "estimatedCostInToken": "10",
                },
            },
        }),
    ]);
    let error = prepare_self_sponsored_transfer(&rpc, transfer(), &decline())
        .await
        .unwrap_err();
    assert!(error
        .to_string()
        .contains("Token-paid sponsorship was declined"));
    assert_eq!(http.requests.lock().unwrap().len(), 2);
}

#[tokio::test]
async fn token_sponsorship_error_stops_without_submission() {
    let (rpc, http) = rpc(vec![
        allowance_response(10),
        json!({
            "jsonrpc": "2.0", "id": "test",
            "error": { "code": -32603, "message": "sponsorship unavailable" },
        }),
    ]);
    let error = prepare_self_sponsored_transfer(&rpc, transfer(), &decline())
        .await
        .unwrap_err();
    assert!(error.to_string().contains("sponsorship unavailable"));
    assert_eq!(http.requests.lock().unwrap().len(), 2);
}
