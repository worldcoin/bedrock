use super::*;
use crate::primitives::http_client::HttpHeader;
use crate::primitives::{AuthenticatedHttpClient, HttpError, HttpMethod};
use crate::smart_account::{ISafe4337Module, SafeOperation};
use crate::transactions::contracts::erc20::IErc20;
use crate::transactions::contracts::multisend::{IMultiSend, MULTISEND_ADDRESS};
use alloy::primitives::{address, B256};
use alloy::sol_types::SolCall;
use serde_json::{json, Value};
use std::collections::VecDeque;
use std::sync::Mutex;

const TOKEN: Address = address!("2cfc85d8e48f8eab294be644d9e25c3030863003");
const PAYMASTER: Address = address!("0000000000000039cd5e8ae05257ce51c473ddd1");
const RECIPIENT: Address = address!("1234567890123456789012345678901234567890");

struct ScriptedHttpClient {
    responses: Mutex<VecDeque<(&'static str, Value)>>,
    requests: Mutex<Vec<Value>>,
    repeat_last: bool,
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
        let mut responses = self.responses.lock().unwrap();
        let (method, response) = if self.repeat_last && responses.len() == 1 {
            responses.front().unwrap().clone()
        } else {
            responses.pop_front().expect("unexpected RPC request")
        };
        assert_eq!(request["method"], method);
        let expected_url = match method {
            "pm_sponsorUserOperation" | "eth_sendUserOperation" | "eth_call" => {
                "/v2/rpc/worldchain"
            }
            _ => "/v1/rpc/worldchain",
        };
        assert_eq!(url, expected_url);
        self.requests.lock().unwrap().push(request);
        Ok(serde_json::to_vec(&response).unwrap())
    }
}

fn rpc(
    responses: Vec<(&'static str, Value)>,
    repeat_last: bool,
) -> (RpcClient, Arc<ScriptedHttpClient>) {
    let http = Arc::new(ScriptedHttpClient {
        responses: Mutex::new(responses.into()),
        requests: Mutex::new(Vec::new()),
        repeat_last,
    });
    (RpcClient::new(http.clone()), http)
}

fn account() -> SafeSmartAccount {
    SafeSmartAccount::from_private_key_hex(
        "4142710b9b4caaeb000b8e5de271bbebac7f509aab2f5e61d1ed1958bfe6d583".to_string(),
        "0x4564420674EA68fcc61b463C0494807C759d47e6",
    )
    .unwrap()
}

fn decline(amount: u64) -> PmSponsorshipDecline {
    serde_json::from_value(json!({
        "token": TOKEN,
        "paymasterAddress": PAYMASTER,
        "reason": "future_policy",
        "estimatedCostInToken": amount.to_string(),
    }))
    .unwrap()
}

fn result(value: Value) -> Value {
    let mut response = json!({ "jsonrpc": "2.0", "id": "test" });
    response["result"] = value;
    response
}

fn allowance(amount: u64) -> Value {
    result(json!(format!("0x{:064x}", U256::from(amount))))
}

fn approval_sponsorship() -> Value {
    result(json!({
        "callGasLimit": "0x10000",
        "verificationGasLimit": "0x10000",
        "preVerificationGas": "0x0",
        "maxFeePerGas": "0x0",
        "maxPriorityFeePerGas": "0x0",
        "providerName": "pimlico",
        "paymaster": "0x1111111111111111111111111111111111111111",
        "paymasterData": "0xabcd",
        "paymasterVerificationGasLimit": "0x10000",
        "paymasterPostOpGasLimit": "0x1000",
    }))
}

fn token_sponsorship() -> Value {
    let mut response = approval_sponsorship();
    response["result"]["paymaster"] = json!(PAYMASTER);
    response["result"]["paymasterData"] = json!("0x1234");
    response["result"]["paymasterVerificationGasLimit"] = json!("0x10000");
    response["result"]["paymasterPostOpGasLimit"] = json!("0x1000");
    response["result"]["maxFeePerGas"] = json!("0xa");
    response
}

fn advisory(amount: u64) -> Value {
    json!({
        "jsonrpc": "2.0", "id": "test",
        "error": {
            "code": -32602, "message": "sponsorship declined",
            "data": {
                "token": TOKEN, "paymasterAddress": PAYMASTER,
                "reason": "future_policy", "estimatedCostInToken": amount.to_string(),
            },
        },
    })
}

fn receipt(status: &str) -> Value {
    result(json!({
        "userOpHash": B256::repeat_byte(1),
        "sender": account().wallet_address,
        "status": status,
        "source": "bedrock",
    }))
}

fn transfer(account: &SafeSmartAccount) -> UserOperation {
    Erc20::new(TOKEN, RECIPIENT, U256::from(7))
        .build_preflight_user_operation(
            account.wallet_address,
            Some(MetadataArg {
                association: Some(TransferAssociation::XmtpMessage),
            }),
        )
        .unwrap()
}

fn approval_steps(initial: u64, final_allowance: u64) -> Vec<(&'static str, Value)> {
    vec![
        ("eth_call", allowance(initial)),
        ("wa_sponsorUserOperation", approval_sponsorship()),
        ("eth_sendUserOperation", result(json!(B256::repeat_byte(1)))),
        ("wa_getUserOperationReceipt", receipt("pending")),
        ("wa_getUserOperationReceipt", receipt("mined_success")),
        ("eth_call", allowance(final_allowance)),
    ]
}

fn assert_approval_call(operation: &UserOperation, amounts: &[u64]) {
    assert_eq!(operation.nonce.to_be_bytes::<32>()[5], 143);
    let safe =
        ISafe4337Module::executeUserOpCall::abi_decode_raw(&operation.call_data[4..])
            .unwrap();
    assert_eq!(safe.to, MULTISEND_ADDRESS);
    assert_eq!(safe.operation, SafeOperation::DelegateCall as u8);
    let batch = IMultiSend::multiSendCall::abi_decode_raw(&safe.data[4..]).unwrap();
    assert_eq!(batch.transactions.len(), amounts.len() * 153);
    for (entry, amount) in batch.transactions.as_chunks::<153>().0.iter().zip(amounts) {
        assert_eq!(entry[0], SafeOperation::Call as u8);
        assert_eq!(&entry[1..21], TOKEN.as_slice());
        let approval = IErc20::approveCall::abi_decode_raw(&entry[89..]).unwrap();
        assert_eq!(approval.spender, PAYMASTER);
        assert_eq!(approval.value, U256::from(*amount));
    }
}

#[tokio::test(start_paused = true)]
async fn approval_is_mined_before_token_sponsorship_and_transfer_stays_separate() {
    let account = account();
    let original = transfer(&account);
    let mut responses = approval_steps(0, 10);
    responses.extend([
        ("pm_sponsorUserOperation", advisory(10)),
        ("pm_sponsorUserOperation", token_sponsorship()),
    ]);
    let (rpc, http) = rpc(responses, false);
    let prepared =
        prepare_self_sponsored_transfer(&rpc, &account, original.clone(), &decline(10))
            .await
            .unwrap();
    assert_eq!(prepared.user_operation.call_data, original.call_data);
    assert_eq!(prepared.user_operation.nonce, original.nonce);
    assert_eq!(prepared.user_operation.signature, original.signature);
    assert_eq!(
        prepared.fee_details().unwrap().decline_reason,
        "future_policy"
    );
    assert_eq!(
        prepared.fee_details().unwrap().estimated_cost_in_token,
        "10"
    );
    let requests = http.requests.lock().unwrap();
    let submitted: UserOperation =
        serde_json::from_value(requests[2]["params"][0].clone()).unwrap();
    assert_approval_call(&submitted, &[10]);
    assert_ne!(submitted.signature, original.signature);
    assert_eq!(requests[1]["params"].as_array().unwrap().len(), 2); // no fee token for approval
    assert_eq!(requests[7]["params"][2], json!({"token": TOKEN}));
    assert_eq!(
        requests[7]["params"][0]["callData"],
        json!(original.call_data)
    );
    assert!(http.responses.lock().unwrap().is_empty());
}

#[tokio::test]
async fn sufficient_allowance_skips_approval_and_signing() {
    let account = account();
    let (rpc, http) = rpc(
        vec![
            ("eth_call", allowance(20)),
            ("pm_sponsorUserOperation", advisory(15)),
            ("pm_sponsorUserOperation", token_sponsorship()),
        ],
        false,
    );
    let prepared = prepare_self_sponsored_transfer(
        &rpc,
        &account,
        transfer(&account),
        &decline(10),
    )
    .await
    .unwrap();
    assert_eq!(
        prepared.fee_details().unwrap().estimated_cost_in_token,
        "15"
    );
    assert_eq!(http.requests.lock().unwrap().len(), 3);
}

#[tokio::test(start_paused = true)]
async fn increased_fee_requires_confirmed_top_up_before_retry() {
    let account = account();
    let mut responses = vec![
        ("eth_call", allowance(10)),
        ("pm_sponsorUserOperation", advisory(12)),
    ];
    responses.extend(approval_steps(10, 12));
    responses.extend([
        ("pm_sponsorUserOperation", advisory(12)),
        ("pm_sponsorUserOperation", token_sponsorship()),
    ]);
    let (rpc, http) = rpc(responses, false);
    let prepared = prepare_self_sponsored_transfer(
        &rpc,
        &account,
        transfer(&account),
        &decline(10),
    )
    .await
    .unwrap();
    assert_eq!(
        prepared.fee_details().unwrap().estimated_cost_in_token,
        "12"
    );
    let requests = http.requests.lock().unwrap();
    let submitted: UserOperation =
        serde_json::from_value(requests[4]["params"][0].clone()).unwrap();
    drop(requests);
    assert_approval_call(&submitted, &[0, 12]);
    assert!(http.responses.lock().unwrap().is_empty());
}

#[tokio::test(start_paused = true)]
async fn failed_approval_stops_preparation() {
    for status in ["mined_revert", "error", "unexpected"] {
        let account = account();
        let mut responses = approval_steps(0, 10);
        responses.truncate(3);
        responses.push(("wa_getUserOperationReceipt", receipt(status)));
        let (rpc, http) = rpc(responses, false);
        let error = prepare_self_sponsored_transfer(
            &rpc,
            &account,
            transfer(&account),
            &decline(10),
        )
        .await
        .unwrap_err();
        assert!(error.to_string().contains(status));
        assert_eq!(http.requests.lock().unwrap().len(), 4);
    }
}

#[tokio::test(start_paused = true)]
async fn pending_approval_times_out_without_resubmitting_or_preparing_transfer() {
    let account = account();
    let mut responses = approval_steps(0, 10);
    responses.truncate(4);
    let (rpc, http) = rpc(responses, true);
    let error = prepare_self_sponsored_transfer(
        &rpc,
        &account,
        transfer(&account),
        &decline(10),
    )
    .await
    .unwrap_err();
    assert!(error.to_string().contains("Timed out waiting"));
    assert_eq!(
        http.requests
            .lock()
            .unwrap()
            .iter()
            .filter(|r| r["method"] == "eth_sendUserOperation")
            .count(),
        1
    );
}

#[tokio::test(start_paused = true)]
async fn successful_receipt_requires_sufficient_on_chain_allowance() {
    let account = account();
    let (rpc, http) = rpc(approval_steps(0, 0), false);
    let error = prepare_self_sponsored_transfer(
        &rpc,
        &account,
        transfer(&account),
        &decline(10),
    )
    .await
    .unwrap_err();
    assert!(error
        .to_string()
        .contains("did not establish sufficient allowance"));
    assert!(http.responses.lock().unwrap().is_empty());
}

#[tokio::test]
async fn approval_sponsorship_failure_stops_before_submission() {
    let account = account();
    let (rpc, http) = rpc(
        vec![
            ("eth_call", allowance(0)),
            (
                "wa_sponsorUserOperation",
                json!({
                    "jsonrpc": "2.0", "id": "test",
                    "error": { "code": -32603, "message": "sponsorship unavailable" },
                }),
            ),
        ],
        false,
    );
    let error = prepare_self_sponsored_transfer(
        &rpc,
        &account,
        transfer(&account),
        &decline(10),
    )
    .await
    .unwrap_err();
    assert!(error.to_string().contains("sponsorship unavailable"));
    assert_eq!(http.requests.lock().unwrap().len(), 2);
}
