//! Test utilities for unit tests.

use std::collections::HashMap;
use std::str::FromStr;

use alloy::{
    network::Ethereum,
    providers::Provider,
    primitives::Address,
};

use crate::primitives::{
    http_client::{AuthenticatedHttpClient, HttpError, HttpHeader, HttpMethod},
};

/// Mock HTTP client for testing that can provide custom responses for eth_call
#[derive(Clone)]
pub struct AnvilBackedHttpClient<P>
where
    P: Provider<Ethereum> + Clone + Send + Sync + 'static,
{
    /// The underlying Ethereum provider
    pub provider: P,
    /// Custom responses for eth_call based on contract address
    pub custom_eth_call_responses: HashMap<Address, String>,
}

impl<P> AnvilBackedHttpClient<P>
where
    P: Provider<Ethereum> + Clone + Send + Sync + 'static,
{
    /// Creates a new AnvilBackedHttpClient with no custom responses
    pub fn new(provider: P) -> Self {
        Self {
            provider,
            custom_eth_call_responses: HashMap::new(),
        }
    }

    /// Adds a custom response for eth_call to a specific contract address
    pub fn add_eth_call_response(&mut self, to_address: Address, response_hex: String) {
        self.custom_eth_call_responses.insert(to_address, response_hex);
    }

    /// Creates a new client with a custom eth_call response for asset() calls
    /// Returns zero address (useful for ERC-4626 testing)
    pub fn with_zero_asset_response(provider: P, vault_address: Address) -> Self {
        let mut client = Self::new(provider);
        // Asset() returns address(0) - 32 bytes with address in last 20 bytes
        client.add_eth_call_response(vault_address, "0x0000000000000000000000000000000000000000000000000000000000000000".to_string());
        client
    }

    /// Creates a new client with a custom asset address response
    pub fn with_asset_response(provider: P, vault_address: Address, asset_address: Address) -> Self {
        let mut client = Self::new(provider);
        // Convert address to 32-byte padded hex string
        let mut padded_bytes = [0u8; 32];
        padded_bytes[12..32].copy_from_slice(asset_address.as_slice());
        let response = format!("0x{}", hex::encode(padded_bytes));
        client.add_eth_call_response(vault_address, response);
        client
    }
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
                error_message: "unsupported method".into(),
            });
        }

        let body = body.ok_or(HttpError::Generic {
            error_message: "missing body".into(),
        })?;

        let root: serde_json::Value =
            serde_json::from_slice(&body).map_err(|_| HttpError::Generic {
                error_message: "invalid json".into(),
            })?;

        let method =
            root.get("method")
                .and_then(|m| m.as_str())
                .ok_or(HttpError::Generic {
                    error_message: "invalid json".into(),
                })?;
        let id = root.get("id").cloned().unwrap_or(serde_json::Value::Null);
        let params = root
            .get("params")
            .cloned()
            .unwrap_or(serde_json::Value::Null);

        match method {
            // Handle eth_call with custom responses for testing
            "eth_call" => {
                let params = params.as_array().ok_or(HttpError::Generic {
                    error_message: "invalid params".into(),
                })?;

                let call_params = params.first().ok_or(HttpError::Generic {
                    error_message: "missing call params".into(),
                })?;

                let call_obj = call_params.as_object().ok_or(HttpError::Generic {
                    error_message: "call params must be an object".into(),
                })?;

                // Extract the 'to' address from the call parameters
                let to_str = call_obj
                    .get("to")
                    .and_then(|v| v.as_str())
                    .ok_or(HttpError::Generic {
                        error_message: "missing 'to' address in eth_call".into(),
                    })?;

                let to_address = Address::from_str(to_str).map_err(|_| HttpError::Generic {
                    error_message: "invalid 'to' address format".into(),
                })?;

                // Check if we have a custom response for this address
                if let Some(custom_response) = self.custom_eth_call_responses.get(&to_address) {
                    let resp = serde_json::json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "result": custom_response,
                    });
                    return Ok(serde_json::to_vec(&resp).unwrap());
                }

                // If no custom response, forward to the actual provider
                let call_data = call_obj
                    .get("data")
                    .and_then(|v| v.as_str())
                    .ok_or(HttpError::Generic {
                        error_message: "missing 'data' in eth_call".into(),
                    })?;

                // Forward to real provider using simpler call interface
                let result = self
                    .provider
                    .raw_request::<_, alloy::primitives::Bytes>(
                        "eth_call".into(),
                        [
                            serde_json::json!({
                                "to": format!("{to_address:?}"),
                                "data": call_data
                            }),
                            serde_json::json!("latest")
                        ]
                    )
                    .await
                    .map_err(|e| HttpError::Generic {
                        error_message: format!("eth_call failed: {e}"),
                    })?;

                let resp = serde_json::json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "result": format!("0x{}", hex::encode(result)),
                });
                Ok(serde_json::to_vec(&resp).unwrap())
            }
            other => Err(HttpError::Generic {
                error_message: format!("unsupported method {other}"),
            }),
        }
    }
}
