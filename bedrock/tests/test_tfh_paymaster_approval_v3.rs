//! Verifies the approval migration's authenticated V3 requests without a chain.

use std::{
    collections::VecDeque,
    sync::{Arc, Mutex},
};

use alloy::{
    primitives::U256,
    sol_types::{SolCall, SolValue},
};
use bedrock::{
    migration::{
        wallet::tfh_paymaster_approval::TfhPaymasterApprovalMigration, WalletMigration,
        WalletMigrationResult,
    },
    primitives::{
        http_client::{set_http_client, HttpHeader},
        AuthenticatedHttpClient, HttpError, HttpMethod,
    },
    smart_account::{SafeSmartAccount, ENTRYPOINT_4337},
    transactions::{
        contracts::worldchain::{TFH_PAYMASTER_ADDRESS, WLD_ADDRESS},
        rpc::IMulticall3,
    },
};
use serde_json::{json, Value};

#[derive(Default)]
struct MigrationHttpClient {
    responses: Mutex<VecDeque<Value>>,
    requests: Mutex<Vec<Value>>,
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
        match request["method"].as_str().unwrap() {
            "eth_call" => assert_eq!(url, "/v2/rpc/worldchain"),
            "pm_sponsorUserOperation" | "eth_sendUserOperation" => {
                assert_eq!(url, "/v3/rpc/worldchain");
                assert_eq!(request["params"].as_array().unwrap().len(), 2);
                assert_eq!(request["params"][1], json!(*ENTRYPOINT_4337));
            }
            method => panic!("unexpected migration RPC: {method}"),
        }
        self.requests.lock().unwrap().push(request);
        let response = self
            .responses
            .lock()
            .unwrap()
            .pop_front()
            .expect("unexpected request");
        Ok(serde_json::to_vec(&response).unwrap())
    }
}

fn allowance_response(wld: U256, usdc: U256) -> Value {
    let results: Vec<IMulticall3::Result> = [wld, usdc]
        .into_iter()
        .map(|value| IMulticall3::Result {
            success: true,
            returnData: value.abi_encode().into(),
        })
        .collect();
    json!({"result": alloy::hex::encode_prefixed(IMulticall3::aggregate3Call::abi_encode_returns(&results))})
}

fn sponsored_response() -> Value {
    json!({"result": {
        "callGasLimit": "0xc350", "verificationGasLimit": "0xea60",
        "preVerificationGas": "0x0", "maxFeePerGas": "0x0", "maxPriorityFeePerGas": "0x0"
    }})
}

#[tokio::test]
async fn tfh_paymaster_migration_rejects_invalid_sponsored_v3_fields() {
    let http = Arc::new(MigrationHttpClient::default());
    set_http_client(http.clone());
    let account = Arc::new(
        SafeSmartAccount::from_private_key_hex(
            "4142710b9b4caaeb000b8e5de271bbebac7f509aab2f5e61d1ed1958bfe6d583"
                .to_string(),
            "0x4564420674EA68fcc61b463C0494807C759d47e6",
        )
        .unwrap(),
    );
    let migration = TfhPaymasterApprovalMigration::new(account);
    for (field, value) in [
        ("paymaster", json!(TFH_PAYMASTER_ADDRESS)),
        ("paymasterData", json!("0x01")),
        ("paymasterVerificationGasLimit", json!("0x1")),
        ("paymasterPostOpGasLimit", json!("0x1")),
        (
            "fee",
            json!({"token": WLD_ADDRESS, "estimatedCostInToken": "1", "declineReason": "dev_redirect"}),
        ),
        ("callGasLimit", json!("0x0")),
        ("verificationGasLimit", json!("0x0")),
        ("preVerificationGas", json!("0x1")),
        ("maxFeePerGas", json!("0x1")),
        ("maxPriorityFeePerGas", json!("0x1")),
    ] {
        let mut response = sponsored_response();
        response["result"][field] = value;
        http.responses
            .lock()
            .unwrap()
            .extend([allowance_response(U256::ZERO, U256::ZERO), response]);
        assert!(
            matches!(
                migration.reconcile().await.unwrap(),
                WalletMigrationResult::Retry { .. }
            ),
            "invalid {field} must retry"
        );
        assert_eq!(
            std::mem::take(&mut *http.requests.lock().unwrap()).len(),
            2,
            "invalid sponsorship must not submit"
        );
    }

    assert!(http.responses.lock().unwrap().is_empty());
}
