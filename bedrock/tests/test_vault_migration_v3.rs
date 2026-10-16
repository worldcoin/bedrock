//! Exercises the public unified migration API with authenticated RPC fixtures.
use std::sync::{Arc, Mutex};

use alloy::{
    primitives::{address, keccak256, Address, U256},
    sol_types::SolValue,
};
use bedrock::{
    primitives::{
        http_client::{set_http_client, HttpHeader},
        AuthenticatedHttpClient, HttpError, HttpMethod,
    },
    smart_account::{SafeSmartAccount, UserOperation},
    transactions::{
        contracts::worldchain::{USDC_ADDRESS, WLD_ADDRESS},
        TransactionError,
    },
};
use serde_json::{json, Value};
use wiremock::{matchers::body_partial_json, Mock, MockServer, ResponseTemplate};

const DESTINATION: &str = "0x3333333333333333333333333333333333333333";
const SOURCES: [&str; 4] = [
    "0x2222222222222222222222222222222222222222",
    "0x14a028cc500108307947dca4a1aa35029fb66ce0",
    "0xb0e31149c03f1300bd9ff8c165b1fa38fda2f0bb",
    "0x6f1d98034d3055684f989f3ac9832ec37b3f22ec",
];

struct RpcState {
    asset: Address,
    legacy: bool,
    screening: Value,
    sponsorship: Value,
    requests: Vec<(String, Value)>,
}
struct MigrationHttpClient(Mutex<RpcState>);

fn sponsored() -> Value {
    json!({"result": {"callGasLimit":"0xc350", "verificationGasLimit":"0xea60",
        "preVerificationGas":"0x0", "maxFeePerGas":"0x0", "maxPriorityFeePerGas":"0x0"}})
}

#[async_trait::async_trait]
impl AuthenticatedHttpClient for MigrationHttpClient {
    async fn fetch_from_app_backend(
        &self,
        url: String,
        method: HttpMethod,
        _headers: Vec<HttpHeader>,
        body: Option<Vec<u8>>,
    ) -> Result<Vec<u8>, HttpError> {
        assert_eq!(method, HttpMethod::Post);
        let request: Value = serde_json::from_slice(&body.unwrap()).unwrap();
        let mut state = self.0.lock().unwrap();
        let response = match request["method"].as_str().unwrap() {
            "wa_screenAddresses" => {
                assert_eq!(url, "/v3/rpc/worldchain");
                assert_eq!(
                    request["params"],
                    json!([["0x4564420674ea68fcc61b463c0494807c759d47e6"]])
                );
                assert!(state.requests.is_empty(), "screening precedes construction");
                state.screening.clone()
            }
            "eth_call" => {
                assert_eq!(url, "/v2/rpc/worldchain");
                let data = request["params"][0]["data"].as_str().unwrap();
                let selector = &alloy::hex::decode(data).unwrap()[..4];
                let is =
                    |signature: &str| selector == &keccak256(signature.as_bytes())[..4];
                let bytes = if is("asset()") || is("token()") || is("USDC()") {
                    state.asset.abi_encode()
                } else if is("SDAI()") {
                    address!("859dbe24b90c9f2f7742083d3cf59ca41f55be5d").abi_encode()
                } else if is("ADDRESS_BOOK()") {
                    address!("5555555555555555555555555555555555555555").abi_encode()
                } else if is("addressVerifiedUntil(address)") {
                    U256::from(4_000_000_000_u64).abi_encode()
                } else if is("allowance(address,address)")
                    || is("LIMIT_WITHDRAWALS_TO_DEPOSITS()")
                {
                    U256::ZERO.abi_encode()
                } else if is("getDSRConversionRate()") {
                    U256::from(10).pow(U256::from(27)).abi_encode()
                } else if is("balanceOf(address)")
                    || is("maxRedeem(address)")
                    || is("previewRedeem(uint256)")
                    || is("previewDeposit(uint256)")
                {
                    U256::from(1_000_000_000_000_000_000_u64).abi_encode()
                } else {
                    panic!("unexpected contract call: {data}");
                };
                json!({"result": alloy::hex::encode_prefixed(bytes)})
            }
            "pm_sponsorUserOperation" => {
                assert_eq!(url, "/v3/rpc/worldchain");
                state.sponsorship.clone()
            }
            "wa_sponsorUserOperation" => {
                assert!(state.legacy);
                assert_eq!(url, "/v1/rpc/worldchain");
                let mut response = sponsored();
                response["result"]["providerName"] = json!("pimlico");
                response
            }
            "eth_sendUserOperation" => {
                assert_eq!(
                    url,
                    if state.legacy {
                        "/v1/rpc/worldchain"
                    } else {
                        "/v3/rpc/worldchain"
                    }
                );
                json!({"result": format!("0x{}", "ab".repeat(32))})
            }
            method => panic!("unexpected migration RPC: {method}"),
        };
        state.requests.push((url, request));
        Ok(serde_json::to_vec(&response).unwrap())
    }
}

fn assert_signed_free(request: &Value) {
    let op: UserOperation =
        serde_json::from_value(request["params"][0].clone()).unwrap();
    assert_eq!(
        op.sender,
        address!("4564420674ea68fcc61b463c0494807c759d47e6")
    );
    assert_eq!(op.call_gas_limit.to_string(), "50000");
    assert_eq!(op.verification_gas_limit.to_string(), "60000");
    assert!(op.max_fee_per_gas.is_zero());
    assert!(op.max_priority_fee_per_gas.is_zero());
    assert_eq!(op.pre_verification_gas, U256::ZERO);
    assert!(op.paymaster.is_none());
    assert_eq!(op.signature.len(), 77);
    assert_ne!(&op.signature[12..], &[0xff; 65]);
}

#[tokio::test]
async fn unified_vault_migrations_use_v3_or_the_selected_bundler() {
    let http = Arc::new(MigrationHttpClient(Mutex::new(RpcState {
        asset: WLD_ADDRESS,
        legacy: false,
        screening: json!({"result": true}),
        sponsorship: sponsored(),
        requests: vec![],
    })));
    set_http_client(http.clone());
    let account = SafeSmartAccount::from_private_key_hex(
        "4142710b9b4caaeb000b8e5de271bbebac7f509aab2f5e61d1ed1958bfe6d583".into(),
        "0x4564420674EA68fcc61b463C0494807C759d47e6",
    )
    .unwrap();
    for (i, source) in SOURCES.iter().enumerate() {
        for custom in [false, true] {
            {
                let mut state = http.0.lock().unwrap();
                state.asset = if i >= 2 { USDC_ADDRESS } else { WLD_ADDRESS };
                state.requests.clear();
            }
            let server = MockServer::start().await;
            if custom {
                Mock::given(body_partial_json(json!({"method":"eth_estimateUserOperationGas"})))
                    .respond_with(ResponseTemplate::new(200).set_body_json(json!({"jsonrpc":"2.0","id":1,"result": {
                        "callGasLimit":"0xc350", "verificationGasLimit":"0xea60", "preVerificationGas":"0xffff"}})))
                    .expect(1).mount(&server).await;
                Mock::given(body_partial_json(json!({"method":"eth_sendUserOperation"})))
                    .respond_with(ResponseTemplate::new(200).set_body_json(json!({"jsonrpc":"2.0","id":1,"result":format!("0x{}", "ab".repeat(32))})))
                    .expect(1).mount(&server).await;
            }
            let hash = account
                .transaction_erc4626_migrate(
                    source,
                    DESTINATION,
                    custom.then(|| server.uri()),
                )
                .await
                .unwrap();
            assert_eq!(hash.to_string(), format!("0x{}", "ab".repeat(32)));
            let backend = http.0.lock().unwrap().requests.clone();
            if custom {
                assert!(backend.iter().all(|(_, r)| matches!(
                    r["method"].as_str().unwrap(),
                    "eth_call" | "wa_screenAddresses"
                )));
                let requests = server.received_requests().await.unwrap();
                assert_signed_free(&requests[1].body_json::<Value>().unwrap());
            } else {
                assert_eq!(
                    backend[backend.len() - 2].1["method"],
                    "pm_sponsorUserOperation"
                );
                assert_signed_free(&backend.last().unwrap().1);
            }
        }
    }

    // Screening errors stop all source branches before reads or Permit2 signing.
    for source in SOURCES {
        for (reason, code) in [
            ("address_restricted", -32602),
            ("screening_unavailable", -32603),
        ] {
            {
                let mut state = http.0.lock().unwrap();
                state.requests.clear();
                state.screening = json!({"error":{"code":code,"message":"screening failed","data":{"reason":reason}}});
            }
            let result = account
                .transaction_erc4626_migrate(source, DESTINATION, None)
                .await;
            match reason {
                "address_restricted" => {
                    assert!(matches!(result, Err(TransactionError::AddressRestricted)))
                }
                _ => assert!(matches!(
                    result,
                    Err(TransactionError::ScreeningUnavailable)
                )),
            }
            assert_eq!(http.0.lock().unwrap().requests.len(), 1);
        }
    }
    // A paid or malformed sponsorship response must never be signed and submitted.
    for (field, value) in [
        ("maxFeePerGas", json!("0x1")),
        ("callGasLimit", json!("0x0")),
        ("paymaster", json!(WLD_ADDRESS)),
        (
            "fee",
            json!({"token":WLD_ADDRESS,"estimatedCostInToken":"1","declineReason":"dev_redirect"}),
        ),
    ] {
        {
            let mut state = http.0.lock().unwrap();
            state.requests.clear();
            state.asset = WLD_ADDRESS;
            state.screening = json!({"result":true});
            state.sponsorship = sponsored();
            state.sponsorship["result"][field] = value;
        }
        assert!(account
            .transaction_erc4626_migrate(SOURCES[0], DESTINATION, None)
            .await
            .is_err());
        assert!(http
            .0
            .lock()
            .unwrap()
            .requests
            .iter()
            .all(|(_, r)| r["method"] != "eth_sendUserOperation"));
    }
    // The custom route does not fall back when the selected provider fails.
    {
        let mut state = http.0.lock().unwrap();
        state.requests.clear();
        state.sponsorship = sponsored();
    }
    let server = MockServer::start().await;
    Mock::given(body_partial_json(
        json!({"method":"eth_estimateUserOperationGas"}),
    ))
    .respond_with(
        ResponseTemplate::new(200).set_body_json(json!({"jsonrpc":"2.0","id":1,
            "error":{"code":-32000,"message":"estimation failed"}})),
    )
    .mount(&server)
    .await;
    assert!(account
        .transaction_erc4626_migrate(SOURCES[0], DESTINATION, Some(server.uri()))
        .await
        .is_err());
    assert!(http
        .0
        .lock()
        .unwrap()
        .requests
        .iter()
        .all(|(_, r)| r["method"] != "pm_sponsorUserOperation"
            && r["method"] != "eth_sendUserOperation"));

    // Direct legacy callers retain the V1 path and do not invoke the unified prechecks.
    for (i, source) in SOURCES.iter().enumerate().skip(1) {
        {
            let mut state = http.0.lock().unwrap();
            state.requests.clear();
            state.legacy = true;
            state.asset = if i == 1 { WLD_ADDRESS } else { USDC_ADDRESS };
        }
        let hash = if i == 1 {
            account
                .transaction_wld_legacy_vault_migrate(source, DESTINATION)
                .await
        } else {
            account
                .transaction_usd_legacy_vault_migrate(source, DESTINATION)
                .await
        }
        .unwrap();
        assert_eq!(hash.to_string(), format!("0x{}", "ab".repeat(32)));
        let state = http.0.lock().unwrap();
        assert!(state
            .requests
            .iter()
            .all(|(_, r)| r["method"] != "wa_screenAddresses"));
        assert_eq!(
            state.requests[state.requests.len() - 2].1["method"],
            "wa_sponsorUserOperation"
        );
        assert_signed_free(&state.requests.last().unwrap().1);
    }
}
