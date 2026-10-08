//! Verifies the approval migration's authenticated V3 requests without a chain.

use std::{
    collections::VecDeque,
    sync::{Arc, Mutex},
};

use alloy::{
    primitives::{aliases::U128, U256},
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
    smart_account::{
        Is4337Encodable, SafeSmartAccount, TransactionTypeId, UserOperation,
        ENTRYPOINT_4337,
    },
    transactions::{
        contracts::{
            erc20::{BatchErc20Approval, Erc20},
            worldchain::{TFH_PAYMASTER_ADDRESS, USDC_ADDRESS, WLD_ADDRESS},
        },
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
async fn tfh_paymaster_migration_uses_sponsored_v3_and_retries_failures() {
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
    let migration = TfhPaymasterApprovalMigration::new(account.clone());
    let wld_target = U256::from(100) * U256::from(10).pow(U256::from(18));
    let usdc_target = U256::from(30_000_000);
    let hash = format!("0x{}", "ab".repeat(32));

    for (wld_allowance, usdc_allowance, approvals) in [
        (
            U256::ZERO,
            U256::ZERO,
            vec![(WLD_ADDRESS, wld_target), (USDC_ADDRESS, usdc_target)],
        ),
        (wld_target, U256::ZERO, vec![(USDC_ADDRESS, usdc_target)]),
        (U256::ZERO, usdc_target, vec![(WLD_ADDRESS, wld_target)]),
    ] {
        http.responses.lock().unwrap().extend([
            allowance_response(wld_allowance, usdc_allowance),
            sponsored_response(),
            json!({"result": hash}),
        ]);
        assert!(
            matches!(migration.reconcile().await.unwrap(), WalletMigrationResult::Submitted { reference: Some(value) } if value == hash)
        );
        let requests = std::mem::take(&mut *http.requests.lock().unwrap());
        assert_eq!(
            requests.len(),
            3,
            "only allowance read, sponsor, and send are needed"
        );
        let allowance_call: IMulticall3::aggregate3Call =
            IMulticall3::aggregate3Call::abi_decode(
                &alloy::hex::decode(requests[0]["params"][0]["data"].as_str().unwrap())
                    .unwrap(),
            )
            .unwrap();
        assert_eq!(allowance_call.calls.len(), 2);
        for (call, token) in
            allowance_call.calls.iter().zip([WLD_ADDRESS, USDC_ADDRESS])
        {
            assert_eq!(call.target, token);
            assert_eq!(
                call.callData.as_ref(),
                Erc20::encode_allowance(account.wallet_address, TFH_PAYMASTER_ADDRESS)
            );
        }
        assert_eq!(requests[1]["method"], "pm_sponsorUserOperation");
        assert_eq!(requests[2]["method"], "eth_sendUserOperation");
        let prepared: UserOperation =
            serde_json::from_value(requests[1]["params"][0].clone()).unwrap();
        let mut submitted: UserOperation =
            serde_json::from_value(requests[2]["params"][0].clone()).unwrap();
        let expected = BatchErc20Approval::new(
            TFH_PAYMASTER_ADDRESS,
            &approvals,
            TransactionTypeId::TfhPaymasterApprove,
        )
        .build_preflight_user_operation(account.wallet_address, None)
        .unwrap();
        assert_eq!(prepared.call_data, expected.call_data);
        assert_eq!(prepared.sender, account.wallet_address);
        assert_eq!(submitted.signature.len(), 77);
        assert_ne!(submitted.signature, prepared.signature);
        assert!(submitted.paymaster.is_none());
        assert!(submitted.max_fee_per_gas.is_zero());
        submitted.signature = prepared.signature.clone();
        let mut expected_submission = prepared;
        expected_submission.call_gas_limit = U128::from(50_000);
        expected_submission.verification_gas_limit = U128::from(60_000);
        assert_eq!(
            submitted, expected_submission,
            "only sponsorship fields and signature may change"
        );
    }

    http.responses
        .lock()
        .unwrap()
        .push_back(allowance_response(wld_target, usdc_target));
    assert!(matches!(
        migration.reconcile().await.unwrap(),
        WalletMigrationResult::Converged
    ));
    assert_eq!(std::mem::take(&mut *http.requests.lock().unwrap()).len(), 1);

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

    let rpc_error =
        json!({"error": {"code": -32603, "message": "service unavailable"}});
    for responses in [
        vec![
            allowance_response(U256::ZERO, U256::ZERO),
            rpc_error.clone(),
        ],
        vec![
            allowance_response(U256::ZERO, U256::ZERO),
            sponsored_response(),
            rpc_error,
        ],
    ] {
        let count = responses.len();
        http.responses.lock().unwrap().extend(responses);
        assert!(matches!(
            migration.reconcile().await.unwrap(),
            WalletMigrationResult::Retry { .. }
        ));
        assert_eq!(
            std::mem::take(&mut *http.requests.lock().unwrap()).len(),
            count
        );
    }
    assert!(http.responses.lock().unwrap().is_empty());
}
