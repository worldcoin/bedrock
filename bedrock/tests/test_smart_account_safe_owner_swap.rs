use std::sync::Arc;

use alloy::{
    network::Ethereum,
    primitives::{keccak256, U256},
    providers::{ext::AnvilApi, Provider, ProviderBuilder},
    signers::local::PrivateKeySigner,
    sol,
    sol_types::SolValue,
};
use bedrock::{
    primitives::{
        http_client::{set_http_client, AuthenticatedHttpClient, HttpError, HttpHeader, HttpMethod},
    },
    smart_account::{SafeSmartAccount, ENTRYPOINT_4337},
    transaction::foreign::UnparsedUserOperation,
};
use serde::Serialize;
use serde_json::json;

mod common;
use common::{deploy_safe, setup_anvil, IEntryPoint, PackedUserOperation};

sol! {
    /// Safe owner management interface
    #[sol(rpc)]
    interface IOwnerManager {
        function getOwners() external view returns (address[] memory);
        function isOwner(address owner) external view returns (bool);
        function swapOwner(address prevOwner, address oldOwner, address newOwner) external;
    }
}

// ------------------ Mock HTTP client that intercepts sponsor and executes on Anvil ------------------
#[derive(Clone)]
struct AnvilBackedHttpClient<P>
where
    P: Provider<Ethereum> + Clone + Send + Sync + 'static,
{
    provider: P,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SponsorUserOperationResponseLite<'a> {
    paymaster: &'a str,
    paymaster_data: &'a str,
    pre_verification_gas: String,
    verification_gas_limit: String,
    call_gas_limit: String,
    paymaster_verification_gas_limit: String,
    paymaster_post_op_gas_limit: String,
    max_priority_fee_per_gas: String,
    max_fee_per_gas: String,
}

#[async_trait::async_trait]
impl<P> AuthenticatedHttpClient for AnvilBackedHttpClient<P>
where
    P: Provider<Ethereum> + Clone + Send + Sync + 'static,
{
    async fn fetch_from_app_backend(
        &self,
        _url: String,
        method: HttpMethod,
        _headers: Vec<HttpHeader>,
        body: Option<Vec<u8>>,
    ) -> Result<Vec<u8>, HttpError> {
        if method != HttpMethod::Post {
            return Err(HttpError::Generic {
                message: "unsupported method".into(),
            });
        }

        let body = body.ok_or(HttpError::Generic {
            message: "missing body".into(),
        })?;

        let root: serde_json::Value =
            serde_json::from_slice(&body).map_err(|_| HttpError::Generic {
                message: "invalid json".into(),
            })?;

        let method =
            root.get("method")
                .and_then(|m| m.as_str())
                .ok_or(HttpError::Generic {
                    message: "invalid json".into(),
                })?;
        let id = root.get("id").cloned().unwrap_or(serde_json::Value::Null);
        let params = root
            .get("params")
            .cloned()
            .unwrap_or(serde_json::Value::Null);

        match method {
            // Intercept sponsor request and return minimal gas values with no paymaster
            "wa_sponsorUserOperation" => {
                let result = SponsorUserOperationResponseLite {
                    paymaster: "0x0000000000000000000000000000000000000000",
                    paymaster_data: "0x",
                    pre_verification_gas: "0x20000".into(),
                    verification_gas_limit: "0x20000".into(),
                    call_gas_limit: "0x20000".into(),
                    paymaster_verification_gas_limit: "0x0".into(),
                    paymaster_post_op_gas_limit: "0x0".into(),
                    max_priority_fee_per_gas: "0x3B9ACA00".into(), // 1 gwei
                    max_fee_per_gas: "0x3B9ACA00".into(),          // 1 gwei
                };

                let response = json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "result": result,
                });

                Ok(serde_json::to_vec(&response).unwrap())
            }
            // Execute the user operation on Anvil
            "eth_sendUserOperation" => {
                let params = params.as_array().ok_or(HttpError::Generic {
                    message: "invalid params".into(),
                })?;
                let user_op_val = params.first().ok_or(HttpError::Generic {
                    message: "missing userOp param".into(),
                })?;
                let _entry_point_str = params.get(1).and_then(|v| v.as_str()).ok_or(
                    HttpError::Generic {
                        message: "missing entryPoint param".into(),
                    },
                )?;

                // Build UnparsedUserOperation from JSON (which uses hex strings), then convert
                let obj = user_op_val.as_object().ok_or(HttpError::Generic {
                    message: "userOp param must be an object".into(),
                })?;

                let get_opt = |k: &str| -> Option<String> {
                    obj.get(k).and_then(|v| v.as_str()).map(|s| s.to_string())
                };
                let get_or_zero = |k: &str| -> String {
                    get_opt(k).unwrap_or_else(|| "0x0".to_string())
                };
                let get_required = |k: &str| -> Result<String, HttpError> {
                    get_opt(k).ok_or(HttpError::Generic {
                        message: format!("missing or invalid {k}"),
                    })
                };

                let unparsed = UnparsedUserOperation {
                    sender: get_required("sender")?,
                    nonce: get_required("nonce")?,
                    call_data: get_required("callData")?,
                    call_gas_limit: get_or_zero("callGasLimit"),
                    verification_gas_limit: get_or_zero("verificationGasLimit"),
                    pre_verification_gas: get_or_zero("preVerificationGas"),
                    max_fee_per_gas: get_or_zero("maxFeePerGas"),
                    max_priority_fee_per_gas: get_or_zero("maxPriorityFeePerGas"),
                    paymaster: get_opt("paymaster"),
                    paymaster_verification_gas_limit: get_or_zero(
                        "paymasterVerificationGasLimit",
                    ),
                    paymaster_post_op_gas_limit: get_or_zero("paymasterPostOpGasLimit"),
                    paymaster_data: get_opt("paymasterData"),
                    signature: get_required("signature")?,
                    factory: get_opt("factory"),
                    factory_data: get_opt("factoryData"),
                };

                let parsed_op: bedrock::smart_account::UserOperation =
                    unparsed.try_into().map_err(|e| HttpError::Generic {
                        message: format!("invalid userOp: {e}"),
                    })?;

                // Execute on Anvil via EntryPoint
                let entry_point_contract = IEntryPoint::new(*ENTRYPOINT_4337, &self.provider);
                let packed_op = PackedUserOperation::try_from(&parsed_op)
                    .map_err(|e| HttpError::Generic {
                        message: format!("failed to pack user operation: {e}"),
                    })?;
                let handle_ops = entry_point_contract
                    .handleOps(vec![packed_op], parsed_op.sender)
                    .gas(5_000_000)
                    .send()
                    .await
                    .map_err(|e| HttpError::Generic {
                        message: format!("failed to execute user operation: {e}"),
                    })?;

                let _receipt = handle_ops.get_receipt().await.map_err(|e| HttpError::Generic {
                    message: format!("failed to get receipt: {e}"),
                })?;

                // Create a user operation hash
                let user_op_hash = keccak256(parsed_op.abi_encode());

                let response = json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "result": format!("0x{}", hex::encode(user_op_hash)),
                });

                Ok(serde_json::to_vec(&response).unwrap())
            }
            _ => Err(HttpError::Generic {
                message: format!("unsupported method: {method}"),
            }),
        }
    }
}

/// End-to-end integration test for swapping Safe owners using tx_swap_safe_owner.
///
/// This test:
/// 1. Deploys a Safe with an initial owner
/// 2. Sets up a custom RPC client that intercepts sponsor requests
/// 3. Executes the owner swap using tx_swap_safe_owner
/// 4. Verifies the swap was executed successfully on-chain
#[tokio::test]
async fn test_safe_owner_swap_e2e() -> anyhow::Result<()> {
    let anvil = setup_anvil();

    // Setup initial and new owners
    let initial_owner_signer = PrivateKeySigner::random();
    let initial_owner = initial_owner_signer.address();
    let initial_owner_key_hex = hex::encode(initial_owner_signer.to_bytes());

    let new_owner_signer = PrivateKeySigner::random();
    let new_owner = new_owner_signer.address();

    println!("✓ Initial owner address: {initial_owner}");
    println!("✓ New owner address: {new_owner}");

    let provider = ProviderBuilder::new()
        .wallet(initial_owner_signer.clone())
        .connect_http(anvil.endpoint_url());

    // Deploy Safe with initial owner
    let safe_address = deploy_safe(&provider, initial_owner, U256::ZERO).await?;
    println!("✓ Deployed Safe at: {safe_address}");

    // Fund the Safe for gas
    provider
        .anvil_set_balance(safe_address, U256::from(1e18))
        .await?;

    // Fund EntryPoint deposit for the Safe
    let entry_point = IEntryPoint::new(*ENTRYPOINT_4337, &provider);
    let _deposit_tx = entry_point
        .depositTo(safe_address)
        .value(U256::from(1e18))
        .send()
        .await?;
    println!("✓ Funded Safe and EntryPoint deposit");

    // Verify initial owner
    let safe_contract = IOwnerManager::new(safe_address, &provider);
    let initial_owners = safe_contract.getOwners().call().await?;
    assert_eq!(initial_owners.len(), 1);
    assert_eq!(initial_owners[0], initial_owner);
    assert!(safe_contract.isOwner(initial_owner).call().await?);
    assert!(!safe_contract.isOwner(new_owner).call().await?);
    println!("✓ Verified initial owner");

    // Set up custom HTTP client that intercepts sponsor requests and executes on Anvil
    let anvil_http_client = AnvilBackedHttpClient {
        provider: provider.clone(),
    };
    set_http_client(Arc::new(anvil_http_client));

    // Create SafeSmartAccount instance
    let safe_account =
        SafeSmartAccount::new(initial_owner_key_hex, &safe_address.to_string())
            .expect("Failed to create SafeSmartAccount");

    // Execute the owner swap using tx_swap_safe_owner
    println!("→ Executing tx_swap_safe_owner to swap owners...");
    let tx_hash = safe_account
        .tx_swap_safe_owner(
            &initial_owner.to_string(),
            &new_owner.to_string(),
        )
        .await?;

    println!("✓ Executed owner swap transaction: {}", tx_hash.to_hex_string());
    
    // Wait a bit for the transaction to be processed
    tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

    // Verify the owner swap was successful
    let final_owners = safe_contract.getOwners().call().await?;
    assert_eq!(final_owners.len(), 1, "Should still have exactly 1 owner");
    assert_eq!(final_owners[0], new_owner, "Owner should be the new owner");

    // Verify ownership status
    assert!(
        !safe_contract.isOwner(initial_owner).call().await?,
        "Initial owner should no longer be an owner"
    );
    assert!(
        safe_contract.isOwner(new_owner).call().await?,
        "New owner should be an owner"
    );

    println!("✅ Successfully swapped Safe owner from {initial_owner} to {new_owner}");

    Ok(())
}
