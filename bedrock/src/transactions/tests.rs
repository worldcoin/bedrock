use super::*;
use crate::primitives::http_client::HttpHeader;
use crate::primitives::{AuthenticatedHttpClient, HttpError, HttpMethod};
use crate::transactions::contracts::erc20::IErc20;
use crate::transactions::contracts::worldchain::{
    TFH_PAYMASTER_ADDRESS, USDC_ADDRESS, WLD_ADDRESS,
};
use alloy::primitives::{address, Bytes};
use alloy::sol_types::{SolCall, SolValue};
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
            "estimatedCostInToken": "10",
            "token": token,
            "declineReason": "future_policy",
            "paymasterData": Bytes::from((token, U256::from(1_000_000_000_000_000_000_u64), U256::from(2000)).abi_encode()),
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
async fn one_request_preserves_unsigned_transfer_and_exposes_final_fee() {
    let original = transfer();
    let response = token_sponsorship(WLD_ADDRESS);
    let (rpc, http) = rpc(vec![response.clone(), uint_response(10), uint_response(17)]);
    let prepared = prepare_transfer(&rpc, original.clone(), WLD_ADDRESS, U256::from(7))
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
        if [
            "paymaster",
            "estimatedCostInToken",
            "token",
            "declineReason",
        ]
        .contains(&field.as_str())
        {
            continue;
        }
        assert_eq!(&operation[field], value, "{field}");
    }
    let fee = prepared.fee_details().unwrap();
    assert_eq!(fee.token_address, WLD_ADDRESS.to_string());
    assert_eq!(fee.paymaster_address, TFH_PAYMASTER_ADDRESS.to_string());
    assert_eq!(fee.decline_reason, "future_policy");
    assert_eq!(fee.estimated_cost_in_token, "10");

    // Allowance and balance checks use the returned fee estimate.
    let requests = http.requests.lock().unwrap();
    assert_eq!(requests.len(), 3);
    assert_eq!(requests[0]["method"], "pm_sponsorUserOperation");
    assert_eq!(requests[1]["method"], "eth_call");
    assert_eq!(requests[2]["method"], "eth_call");
    assert_eq!(requests[0]["params"][0], json!(original));
    assert_eq!(requests[0]["params"][1], json!(*ENTRYPOINT_4337));
    assert_eq!(requests[0]["params"].as_array().unwrap().len(), 2);
    assert!(http.responses.lock().unwrap().is_empty());
}

#[tokio::test]
async fn free_preparation_has_no_fee_or_balance_reads() {
    let original = transfer();
    let (rpc, http) = rpc(vec![json!({
        "jsonrpc": "2.0", "id": "test", "result": {
            "callGasLimit": "0x0", "verificationGasLimit": "0x0", "preVerificationGas": "0x0",
            "maxFeePerGas": "0x0", "maxPriorityFeePerGas": "0x0"
        }
    })]);
    let prepared = prepare_transfer(&rpc, original.clone(), WLD_ADDRESS, U256::from(7))
        .await
        .unwrap();
    assert!(prepared.fee_details().is_none());
    assert_eq!(prepared.user_operation.call_data, original.call_data);
    assert_eq!(prepared.user_operation.signature, original.signature);
    assert!(prepared.user_operation.paymaster.is_none());
    assert_eq!(http.requests.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn final_fee_drives_confirmation_and_coverage() {
    for (allowance, balance, failure) in [
        (20, 27, None),
        (19, 27, Some("Insufficient fee-token allowance")),
        (20, 26, Some("Not enough funds")),
    ] {
        let mut response = token_sponsorship(WLD_ADDRESS);
        response["result"]["estimatedCostInToken"] = json!("20");
        let (rpc, _) = rpc(vec![
            response,
            uint_response(allowance),
            uint_response(balance),
        ]);
        let result =
            prepare_transfer(&rpc, transfer(), WLD_ADDRESS, U256::from(7)).await;
        if let Some(failure) = failure {
            assert!(result.unwrap_err().to_string().contains(failure));
        } else {
            assert_eq!(
                result
                    .unwrap()
                    .fee_details()
                    .unwrap()
                    .estimated_cost_in_token,
                "20"
            );
        }
    }
}

#[tokio::test]
async fn missing_final_fee_stops_preparation() {
    let mut response = token_sponsorship(WLD_ADDRESS);
    response["result"]
        .as_object_mut()
        .unwrap()
        .remove("estimatedCostInToken");
    let (rpc, http) = rpc(vec![response]);
    let error = prepare_transfer(&rpc, transfer(), WLD_ADDRESS, U256::from(7))
        .await
        .unwrap_err();
    assert!(error.to_string().contains("no final fee estimate"));
    assert_eq!(http.requests.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn insufficient_allowance_stops_preparation() {
    for allowance in [0, 9] {
        let (rpc, http) = rpc(vec![
            token_sponsorship(WLD_ADDRESS),
            uint_response(allowance),
        ]);
        let error = prepare_transfer(&rpc, transfer(), WLD_ADDRESS, U256::from(7))
            .await
            .unwrap_err();
        assert!(error
            .to_string()
            .contains("Insufficient fee-token allowance"));
        let requests = http.requests.lock().unwrap();
        assert_eq!(requests.len(), 2);
        assert_eq!(requests[1]["method"], "eth_call");
    }
}

#[tokio::test]
async fn allowance_read_failure_stops_preparation() {
    for response in [
        json!({
            "jsonrpc": "2.0", "id": "test",
            "error": { "code": -32603, "message": "allowance unavailable" },
        }),
        json!({ "jsonrpc": "2.0", "id": "test", "result": "0x" }),
    ] {
        let (rpc, http) = rpc(vec![token_sponsorship(WLD_ADDRESS), response]);
        let error = prepare_transfer(&rpc, transfer(), WLD_ADDRESS, U256::from(7))
            .await
            .unwrap_err();
        assert!(error
            .to_string()
            .contains("Failed to read fee-token allowance"));
        let requests = http.requests.lock().unwrap();
        assert_eq!(requests.len(), 2);
        assert_eq!(requests[1]["method"], "eth_call");
    }
}

#[tokio::test]
async fn allowance_checks_fee_token_sender_and_migrated_spender() {
    let original = transfer();
    let sender = original.sender;

    let (rpc, http) = rpc(vec![
        token_sponsorship(USDC_ADDRESS),
        uint_response(11),
        uint_response(10),
    ]);
    let prepared = prepare_transfer(&rpc, original, WLD_ADDRESS, U256::from(7))
        .await
        .unwrap();
    assert_eq!(
        prepared.fee_details().unwrap().estimated_cost_in_token,
        "10"
    );

    let requests = http.requests.lock().unwrap();
    assert_eq!(requests.len(), 3);
    assert_eq!(requests[1]["method"], "eth_call");
    assert_eq!(requests[1]["params"][0]["to"], json!(USDC_ADDRESS));
    assert_eq!(requests[1]["params"][1], "latest");
    let data: Bytes =
        serde_json::from_value(requests[1]["params"][0]["data"].clone()).unwrap();
    assert_eq!(&data[..4], &IErc20::allowanceCall::SELECTOR);
    let call = IErc20::allowanceCall::abi_decode_raw(&data[4..]).unwrap();
    assert_eq!(call.owner, sender);
    assert_eq!(call.spender, TFH_PAYMASTER_ADDRESS);
    assert_eq!(requests[2]["method"], "eth_call");
    assert_eq!(requests[0]["method"], "pm_sponsorUserOperation");
    assert_eq!(requests[0]["params"].as_array().unwrap().len(), 2);
}

#[tokio::test]
async fn invalid_final_fee_estimate_stops_preparation() {
    for estimate in [
        "0",
        "-1",
        "1.5",
        "invalid",
        "0x10",
        "115792089237316195423570985008687907853269984665640564039457584007913129639936",
    ] {
        let mut response = token_sponsorship(WLD_ADDRESS);
        response["result"]["estimatedCostInToken"] = json!(estimate);
        let (rpc, http) = rpc(vec![response]);
        let error = prepare_transfer(&rpc, transfer(), WLD_ADDRESS, U256::from(7))
            .await
            .unwrap_err();
        assert!(error.to_string().contains("fee estimate"));
        assert_eq!(http.requests.lock().unwrap().len(), 1);
    }
}

#[tokio::test]
async fn non_tfh_paymaster_stops_preparation() {
    let unexpected_paymaster = address!("1111111111111111111111111111111111111111");

    let mut response = token_sponsorship(WLD_ADDRESS);
    response["result"]["paymaster"] = json!(unexpected_paymaster);
    let (rpc, http) = rpc(vec![response]);

    let error = prepare_transfer(&rpc, transfer(), WLD_ADDRESS, U256::from(7))
        .await
        .unwrap_err();
    assert!(error
        .to_string()
        .contains("Self-sponsorship requires TFH paymaster"));
    assert_eq!(http.requests.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn missing_or_mismatched_paymaster_fields_stop_preparation() {
    for field in [
        "paymaster",
        "paymasterData",
        "paymasterVerificationGasLimit",
        "paymasterPostOpGasLimit",
        "token",
        "declineReason",
    ] {
        let mut response = token_sponsorship(WLD_ADDRESS);
        response["result"].as_object_mut().unwrap().remove(field);
        let (rpc, http) = rpc(vec![response]);
        let error = prepare_transfer(&rpc, transfer(), WLD_ADDRESS, U256::from(7))
            .await
            .unwrap_err();
        assert!(error.to_string().contains("paymaster fields"), "{field}");
        assert_eq!(http.requests.lock().unwrap().len(), 1);
    }
}

#[tokio::test]
async fn both_tfh_payload_formats_preserve_the_advertised_fee_token() {
    for token in [WLD_ADDRESS, USDC_ADDRESS] {
        for data in [
            (token, U256::from(10)).abi_encode(),
            (token, U256::from(10), U256::from(2000)).abi_encode(),
        ] {
            let data = Bytes::from(data);
            let mut response = token_sponsorship(token);
            response["result"]["paymasterData"] = json!(data);

            let (rpc, _) = rpc(vec![response, uint_response(10), uint_response(17)]);
            let prepared =
                prepare_transfer(&rpc, transfer(), WLD_ADDRESS, U256::from(7))
                    .await
                    .unwrap();
            assert_eq!(
                prepared.fee_details().unwrap().token_address,
                token.to_string()
            );
            assert_eq!(prepared.user_operation.paymaster_data, Some(data));
        }
    }
}

#[tokio::test]
async fn mismatched_fee_token_in_paymaster_data_stops_preparation() {
    for token in [USDC_ADDRESS, Address::ZERO] {
        for data in [
            (token, U256::from(10)).abi_encode(),
            (token, U256::from(10), U256::from(2000)).abi_encode(),
        ] {
            let mut response = token_sponsorship(WLD_ADDRESS);
            response["result"]["paymasterData"] = json!(Bytes::from(data));
            let (rpc, _) = rpc(vec![response]);
            let error = prepare_transfer(&rpc, transfer(), WLD_ADDRESS, U256::from(7))
                .await
                .unwrap_err();
            assert!(error
                .to_string()
                .contains("fee token does not match the fee quote"));
        }
    }
}

#[tokio::test]
async fn malformed_tfh_paymaster_data_stops_preparation() {
    let mut invalid_payloads: Vec<_> = [0, 32, 63, 65, 95, 97, 128]
        .into_iter()
        .map(|length| (vec![0; length], "length"))
        .collect();
    for mut data in [
        (WLD_ADDRESS, U256::from(10)).abi_encode(),
        (WLD_ADDRESS, U256::from(10), U256::from(2000)).abi_encode(),
    ] {
        // Solidity rejects nonzero padding in the ABI address word.
        data[0] = 1;
        invalid_payloads.push((data, "encoding"));
    }
    for (data, reason) in invalid_payloads {
        let mut response = token_sponsorship(WLD_ADDRESS);
        response["result"]["paymasterData"] = json!(Bytes::from(data));
        let (rpc, _) = rpc(vec![response]);
        let error = prepare_transfer(&rpc, transfer(), WLD_ADDRESS, U256::from(7))
            .await
            .unwrap_err();
        assert!(error
            .to_string()
            .contains(&format!("Invalid TFH paymaster data {reason}")));
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
    let error = prepare_transfer(&rpc, transfer(), WLD_ADDRESS, U256::from(7))
        .await
        .unwrap_err();
    assert!(error.to_string().contains("sponsorship declined"));
    assert_eq!(http.requests.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn token_sponsorship_error_stops_without_submission() {
    let (rpc, http) = rpc(vec![json!({
        "jsonrpc": "2.0", "id": "test",
        "error": { "code": -32603, "message": "sponsorship unavailable" },
    })]);
    let error = prepare_transfer(&rpc, transfer(), WLD_ADDRESS, U256::from(7))
        .await
        .unwrap_err();
    assert!(error.to_string().contains("sponsorship unavailable"));
    assert_eq!(http.requests.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn balance_covers_transfer_and_final_fee() {
    for (fee_token, balance, insufficient) in [
        (WLD_ADDRESS, 17, false),
        (WLD_ADDRESS, 18, false),
        (USDC_ADDRESS, 10, false),
        (WLD_ADDRESS, 7, true),
        (WLD_ADDRESS, 16, true),
        (WLD_ADDRESS, 0, true),
        (USDC_ADDRESS, 9, true),
    ] {
        let original = transfer();
        let sender = original.sender;
        let (rpc, http) = rpc(vec![
            token_sponsorship(fee_token),
            uint_response(10),
            uint_response(balance),
        ]);
        let result = prepare_transfer(&rpc, original, WLD_ADDRESS, U256::from(7)).await;
        if insufficient {
            let error = result.unwrap_err();
            assert_eq!(
                error.to_string(),
                "Not enough funds to cover the transfer and network fee."
            );
            assert!(
                matches!(error, TransactionError::InsufficientFunds { token_address }
                if token_address == fee_token.to_string())
            );
        } else {
            assert_eq!(
                result
                    .unwrap()
                    .fee_details()
                    .unwrap()
                    .estimated_cost_in_token,
                "10"
            );
        }
        let requests = http.requests.lock().unwrap();
        assert_eq!(requests.len(), 3);
        assert_eq!(requests[2]["method"], "eth_call");
        assert_eq!(requests[2]["params"][0]["to"], json!(fee_token));
        let data: Bytes =
            serde_json::from_value(requests[2]["params"][0]["data"].clone()).unwrap();
        drop(requests);
        assert_eq!(&data[..4], &IErc20::balanceOfCall::SELECTOR);
        let call = IErc20::balanceOfCall::abi_decode_raw(&data[4..]).unwrap();
        assert_eq!(call.account, sender);
        assert!(http.responses.lock().unwrap().is_empty());
    }
}

#[tokio::test]
async fn balance_read_failure_stops_preparation() {
    for response in [
        json!({ "jsonrpc": "2.0", "id": "test", "result": "0x" }),
        json!({
            "jsonrpc": "2.0", "id": "test",
            "error": { "code": -32603, "message": "balance unavailable" },
        }),
    ] {
        let (rpc, http) = rpc(vec![
            token_sponsorship(WLD_ADDRESS),
            uint_response(10),
            response,
        ]);
        let error = prepare_transfer(&rpc, transfer(), WLD_ADDRESS, U256::from(7))
            .await
            .unwrap_err();
        assert!(error
            .to_string()
            .contains("Failed to read fee-token balance"));
        assert!(matches!(error, TransactionError::Generic { .. }));
        let requests = http.requests.lock().unwrap();
        assert_eq!(requests.len(), 3);
        assert!(requests
            .iter()
            .skip(1)
            .all(|request| request["method"] == "eth_call"));
        drop(requests);
    }
}

#[tokio::test]
async fn transfer_and_fee_exceeding_u256_max_is_insufficient() {
    let (rpc, _) = rpc(vec![json!({
        "jsonrpc": "2.0", "id": "test", "result": format!("{:#x}", U256::MAX),
    })]);
    let error = check_fee_balance(
        &rpc,
        transfer().sender,
        WLD_ADDRESS,
        WLD_ADDRESS,
        U256::MAX,
        U256::from(1),
    )
    .await
    .unwrap_err();
    assert!(matches!(error, TransactionError::InsufficientFunds { .. }));
}

#[tokio::test]
async fn incomplete_fee_metadata_cannot_be_treated_as_free() {
    for (field, value) in [
        ("token", json!(WLD_ADDRESS)),
        ("estimatedCostInToken", json!("10")),
        ("declineReason", json!("gas_usage")),
        ("paymasterData", json!("0x")),
        ("maxFeePerGas", json!("0x1")),
    ] {
        let mut response = json!({
            "jsonrpc": "2.0", "id": "test", "result": {
                "callGasLimit": "0x0", "verificationGasLimit": "0x0", "preVerificationGas": "0x0",
                "maxFeePerGas": "0x0", "maxPriorityFeePerGas": "0x0"
            }
        });
        response["result"][field] = value;
        let (rpc, http) = rpc(vec![response]);
        assert!(
            prepare_transfer(&rpc, transfer(), WLD_ADDRESS, U256::from(7))
                .await
                .is_err()
        );
        assert_eq!(http.requests.lock().unwrap().len(), 1);
    }
}
