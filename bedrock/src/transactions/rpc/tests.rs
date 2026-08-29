use super::*;
use alloy::primitives::{address, bytes, U128, U256};
use serde_json::json;

#[test]
fn test_sponsor_response_parsing() {
    let json_response = json!({
        "paymaster": "0x0000000000000039cd5e8aE05257CE51C473ddd1",
        "paymasterData": "0x01000066d1a1a4",
        "preVerificationGas": "0x350f7",
        "verificationGasLimit": "0x501ab",
        "callGasLimit": "0x212df",
        "paymasterVerificationGasLimit": "0x6dae",
        "paymasterPostOpGasLimit": "0x706e",
        "maxPriorityFeePerGas": "0x3B9ACA00",
        "maxFeePerGas": "0x7A5CF70D5",
        "providerName":"pimlico",
    });

    let response: SponsorUserOperationResponse =
        serde_json::from_value(json_response).unwrap();

    assert_eq!(
        response.paymaster,
        Some(address!("0000000000000039cd5e8aE05257CE51C473ddd1"))
    );
    assert_eq!(response.call_gas_limit, U128::from(0x212df));
}

#[test]
fn test_error_payload_parsing() {
    let error_json = json!({
        "code": -32000,
        "message": "execution reverted",
        "data": null
    });

    let error_payload: ErrorPayload = serde_json::from_value(error_json).unwrap();

    assert_eq!(error_payload.code, -32000);
    assert_eq!(error_payload.message, "execution reverted");
}

#[test]
fn test_user_operation_serialization_with_null_fields() {
    let user_op = UserOperation {
        sender: address!("5a6b47F4131bf1feAFA56A05573314BcF44C9149"),
        nonce: U256::from_str_radix(
            "009aaffd82ed9852f394acca3e4b30ef51880188532374de0000000000000000",
            16,
        )
        .unwrap(),
        factory: None,
        factory_data: None,
        call_data: bytes!("0xe9ae5c53"),
        call_gas_limit: U128::from(0x13_880),
        verification_gas_limit: U128::from(0x60_B01),
        pre_verification_gas: U256::from(0xD3E3),
        max_fee_per_gas: U128::from(0x3B9A_CA00),
        max_priority_fee_per_gas: U128::from(0x2B9A_CA00),
        paymaster: None,
        paymaster_verification_gas_limit: None,
        paymaster_post_op_gas_limit: None,
        paymaster_data: None,
        signature: vec![0xff; 77].into(),
    };

    // Test that UserOperation can be serialized
    let serialized = serde_json::to_value(&user_op).unwrap();

    // Print the actual serialized output to see the format
    println!(
        "UserOperation serialization: {}",
        serde_json::to_string_pretty(&serialized).unwrap()
    );

    // Verify the key field is properly serialized with camelCase naming
    assert_eq!(serialized["callData"], "0xe9ae5c53");
    assert_eq!(serialized["callGasLimit"], "0x13880");
    assert_eq!(serialized["maxFeePerGas"], "0x3b9aca00");
    assert_eq!(serialized["maxPriorityFeePerGas"], "0x2b9aca00");
    assert_eq!(
        serialized["nonce"],
        "0x9aaffd82ed9852f394acca3e4b30ef51880188532374de0000000000000000" // no leading zeroes
    );
    assert_eq!(serialized["preVerificationGas"], "0xd3e3");
    assert_eq!(
        serialized["sender"],
        "0x5a6b47f4131bf1feafa56a05573314bcf44c9149"
    );
    assert_eq!(
        serialized["signature"],
        "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
    );
    assert_eq!(serialized["verificationGasLimit"], "0x60b01");

    // Optional fields should be null when None
    assert!(serialized["factory"].is_null());
    assert!(serialized["factoryData"].is_null());
    assert!(serialized["paymaster"].is_null());
    assert!(serialized["paymasterData"].is_null());
    assert!(serialized["paymasterVerificationGasLimit"].is_null());
    assert!(serialized["paymasterPostOpGasLimit"].is_null());
}

#[test]
fn test_user_operation_serialization_with() {
    let user_op = UserOperation {
        sender: address!("5a6b47F4131bf1feAFA56A05573314BcF44C9149"),
        nonce: U256::from_str_radix(
            "009aaffd82ed9852f394acca3e4b30ef51880188532374de0000000000000000",
            16,
        )
        .unwrap(),
        factory: Some(address!("0x0000000071727De22E5E9d8BAf0edAc6f37da032")),
        factory_data: Some(bytes!("0x7702")),
        call_data: bytes!("0xe9ae5c53"),
        call_gas_limit: U128::from(0x13_880),
        verification_gas_limit: U128::from(0x60_B01),
        pre_verification_gas: U256::from(0xD3E3),
        max_fee_per_gas: U128::from(0x3B9A_CA00),
        max_priority_fee_per_gas: U128::from(0x2B9A_CA00),
        paymaster: Some(address!("0xEF725Aa22d43Ea69FB22bE2EBe6ECa205a6BCf5B")),
        paymaster_verification_gas_limit: Some(U128::from(10)),
        paymaster_post_op_gas_limit: Some(U128::from(0)),
        paymaster_data: Some(bytes!("0x")),
        signature: vec![0xff; 77].into(),
    };

    // Test that UserOperation can be serialized
    let serialized = serde_json::to_value(&user_op).unwrap();

    // Print the actual serialized output to see the format
    println!(
        "UserOperation serialization: {}",
        serde_json::to_string_pretty(&serialized).unwrap()
    );

    // Verify the key field is properly serialized with camelCase naming
    assert_eq!(serialized["callData"], "0xe9ae5c53");
    assert_eq!(serialized["callGasLimit"], "0x13880");
    assert_eq!(serialized["maxFeePerGas"], "0x3b9aca00");
    assert_eq!(serialized["maxPriorityFeePerGas"], "0x2b9aca00");
    assert_eq!(
        serialized["nonce"],
        "0x9aaffd82ed9852f394acca3e4b30ef51880188532374de0000000000000000" // no leading zeroes
    );
    assert_eq!(serialized["preVerificationGas"], "0xd3e3");
    assert_eq!(
        serialized["sender"],
        "0x5a6b47f4131bf1feafa56a05573314bcf44c9149"
    );
    assert_eq!(
        serialized["signature"],
        "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
    );
    assert_eq!(serialized["verificationGasLimit"], "0x60b01");

    assert_eq!(
        serialized["factory"],
        "0x0000000071727De22E5E9d8BAf0edAc6f37da032"
    );
    assert_eq!(serialized["factoryData"], "0x7702");
    assert_eq!(
        serialized["paymaster"],
        "0xEF725Aa22d43Ea69FB22bE2EBe6ECa205a6BCf5B"
    );
    assert_eq!(serialized["paymasterData"], "0x");
    assert_eq!(serialized["paymasterVerificationGasLimit"], "0xa");
    assert_eq!(serialized["paymasterPostOpGasLimit"], "0x0");
}

#[test]
fn test_rpc_endpoint_v2_methods_route_to_v2() {
    let network = Network::WorldChain;
    for method in [
        RpcMethod::PmSponsorUserOperation,
        RpcMethod::SendUserOperationV2,
        RpcMethod::EthCall,
    ] {
        let url = RpcClient::rpc_endpoint(network, &method);
        assert!(
            url.starts_with("/v2/"),
            "{method:?} should route to /v2/, got {url}"
        );
    }
}

#[test]
fn test_rpc_endpoint_legacy_methods_stay_on_v1() {
    let network = Network::WorldChain;
    for method in [
        RpcMethod::SponsorUserOperation,
        RpcMethod::SendUserOperation,
        RpcMethod::WaGetUserOperationReceipt,
        RpcMethod::RelaySafeTransaction,
        RpcMethod::SupportedEntryPoints,
    ] {
        let url = RpcClient::rpc_endpoint(network, &method);
        assert!(
            url.starts_with("/v1/"),
            "{method:?} should route to /v1/, got {url}"
        );
    }
}

#[test]
fn test_rpc_endpoint_includes_network_name() {
    let url =
        RpcClient::rpc_endpoint(Network::WorldChain, &RpcMethod::SendUserOperationV2);
    assert_eq!(url, "/v2/rpc/worldchain");

    let url =
        RpcClient::rpc_endpoint(Network::WorldChain, &RpcMethod::SendUserOperation);
    assert_eq!(url, "/v1/rpc/worldchain");
}

#[test]
fn test_pm_sponsor_response_parsing() {
    // Bundler-sponsored shape — paymaster fields are absent from the
    // response body entirely (not present-with-zero). Modelled as
    // Option<T>, so all four deserialize to None.
    let no_paymaster = json!({
        "callGasLimit": "0x0",
        "verificationGasLimit": "0x0",
        "preVerificationGas": "0x0",
        "maxFeePerGas": "0x0",
        "maxPriorityFeePerGas": "0x0",
    });
    let r: PmSponsorUserOperationResponse =
        serde_json::from_value(no_paymaster).unwrap();
    assert_eq!(r.call_gas_limit, U128::ZERO);
    assert_eq!(r.verification_gas_limit, U128::ZERO);
    assert_eq!(r.pre_verification_gas, U256::ZERO);
    assert_eq!(r.max_fee_per_gas, U128::ZERO);
    assert_eq!(r.max_priority_fee_per_gas, U128::ZERO);
    assert!(r.paymaster.is_none());
    assert!(r.paymaster_verification_gas_limit.is_none());
    assert!(r.paymaster_post_op_gas_limit.is_none());
    assert!(r.paymaster_data.is_none());

    // Self-sponsored shape — all four paymaster fields present with real
    // values from Pimlico's ERC-20 paymaster.
    let with_paymaster = json!({
        "callGasLimit": "0x212df",
        "verificationGasLimit": "0x501ab",
        "preVerificationGas": "0x350f7",
        "maxFeePerGas": "0x7A5CF70D5",
        "maxPriorityFeePerGas": "0x3B9ACA00",
        "paymaster": "0x0000000000000039cd5e8aE05257CE51C473ddd1",
        "paymasterVerificationGasLimit": "0x6dae",
        "paymasterPostOpGasLimit": "0x706e",
        "paymasterData": "0x01000066d1a1a4",
    });
    let r: PmSponsorUserOperationResponse =
        serde_json::from_value(with_paymaster).unwrap();
    assert_eq!(
        r.paymaster,
        Some(address!("0000000000000039cd5e8aE05257CE51C473ddd1"))
    );
    assert_eq!(
        r.paymaster_verification_gas_limit,
        Some(U128::from(0x6dae_u32))
    );
    assert_eq!(r.paymaster_post_op_gas_limit, Some(U128::from(0x706e_u32)));
    assert!(r.paymaster_data.is_some());
}

#[test]
fn test_sponsorship_context_serialization() {
    // Protocol-sponsored: empty object is sent as the third param.
    assert_eq!(SponsorshipContext::Protocol.to_json_value(), json!({}));

    // Self-sponsored: { "token": "0x..." } with a lowercase 0x-prefixed
    // hex address, matching the entry_point formatting convention.
    let token = address!("2cfc85d8e48f8eab294be644d9e25c3030863003");
    assert_eq!(
        SponsorshipContext::SelfSponsoredToken(token).to_json_value(),
        json!({ "token": "0x2cfc85d8e48f8eab294be644d9e25c3030863003" })
    );
}
