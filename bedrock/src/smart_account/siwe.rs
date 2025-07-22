use alloy::primitives::Address;
use alloy::signers::{local::LocalSigner, Signer};
use http::uri::Uri;
use semaphore_rs_utils::keccak256;
use serde::{Deserialize, Serialize};
use std::{fmt::Write, str::FromStr};
use time::{format_description::well_known::Rfc3339, Duration, OffsetDateTime};

use super::{SafeSmartAccount, SafeSmartAccountError};

// Re-export for external use
pub use self::world_app_auth::WorldAppAuthFlow;

mod format;
mod world_app_auth;

/// Represents a successfully validated SIWE message.
#[derive(Serialize, Deserialize, Debug, uniffi::Record, Clone)]
pub struct ValidationSuccess {
    /// The validated message content
    pub message: String,
}

/// Response containing SIWE validation results.
#[derive(Serialize, Deserialize, Debug, uniffi::Record)]
pub struct SiweValidationResponse {
    /// The statement from the SIWE message
    pub statement: String,
    /// The domain from the SIWE message
    pub domain: String,
    /// The validation result
    pub result: ValidationSuccess,
    /// Hash of the message content
    pub hashed_message: String,
}

/// Response containing a SIWE signature and the signed message.
#[derive(Serialize, Deserialize, Debug, uniffi::Record)]
pub struct SiweSignatureResponse {
    /// The signature of the message
    pub signature: String,
    /// The signed message
    pub message: String,
}

/// Configuration for creating authentication messages
#[derive(Debug, Clone)]
pub enum AuthConfig {
    /// World App authentication configuration
    WorldApp {
        /// The authentication flow type
        flow: WorldAppAuthFlow,
        /// Base URL for the authentication service
        base_url: String,
        /// Optional nonce (auto-generated if not provided)
        nonce: Option<u32>,
        /// Current timestamp in seconds since epoch
        current_time: u64,
    },
    /// Mini App authentication configuration
    MiniApp {
        /// The mini app identifier
        app_id: String,
        /// The integration URL
        integration_url: String,
        /// Optional statement for the message
        statement: Option<String>,
        /// The wallet address
        wallet_address: String,
        /// Current URL where the auth is happening
        current_url: String,
    },
}

/// Trait that extends `SafeSmartAccount` with SIWE capabilities
pub trait SiweCapable {
    /// Parse and validate a SIWE message
    ///
    /// # Errors
    /// Returns an error if the message validation fails
    fn validate_siwe_message(
        &self,
        raw_message: &str,
        wallet_address: &str,
        current_url: &str,
        integration_url: &str,
    ) -> Result<SiweValidationResponse, SafeSmartAccountError>;

    /// Sign a SIWE message using `personal_sign` underneath
    ///
    /// # Errors
    /// Returns an error if signing fails
    fn sign_siwe_message(
        &self,
        message: &ValidationSuccess,
        chain_id: u32,
    ) -> Result<SiweSignatureResponse, SafeSmartAccountError>;

    /// Create a standardized auth message for both World App and Mini Apps
    ///
    /// # Errors
    /// Returns an error if message creation fails
    fn create_auth_message(
        &self,
        auth_config: AuthConfig,
    ) -> Result<String, SafeSmartAccountError>;
}

// Helper functions for SIWE validation
fn tagged<'a>(
    tag: &'static str,
    line: Option<&'a str>,
) -> Result<&'a str, SafeSmartAccountError> {
    line.and_then(|l| l.strip_prefix(tag)).ok_or_else(|| {
        SafeSmartAccountError::InvalidInput {
            attribute: "siwe_message",
            message: format!("Missing '{tag}'"),
        }
    })
}

fn tag_optional<'a>(
    tag: &'static str,
    line: Option<&'a str>,
) -> Result<Option<&'a str>, SafeSmartAccountError> {
    match tagged(tag, line) {
        Ok(value) => Ok(Some(value)),
        Err(SafeSmartAccountError::InvalidInput {
            attribute: _,
            message,
        }) if message == format!("Missing '{tag}'") => Ok(None),
        Err(e) => Err(e),
    }
}

fn extract_domain(uri: &str) -> Result<String, SafeSmartAccountError> {
    Uri::from_str(uri)
        .map_err(|_| SafeSmartAccountError::InvalidInput {
            attribute: "uri",
            message: "Invalid URL".to_string(),
        })?
        .host()
        .map(std::string::ToString::to_string)
        .ok_or_else(|| SafeSmartAccountError::InvalidInput {
            attribute: "uri",
            message: "Missing domain".to_string(),
        })
}

fn extract_scheme(uri: &str) -> Result<String, SafeSmartAccountError> {
    Uri::from_str(uri)
        .map_err(|_| SafeSmartAccountError::InvalidInput {
            attribute: "uri",
            message: "Invalid URL".to_string(),
        })?
        .scheme()
        .map(std::string::ToString::to_string)
        .ok_or_else(|| SafeSmartAccountError::InvalidInput {
            attribute: "uri",
            message: "Missing scheme".to_string(),
        })
}

fn precheck_and_sanitize_message(
    message: &str,
) -> Result<String, SafeSmartAccountError> {
    let cleaned_message = message.replace(['<', '>'], "").trim().to_string();

    if cleaned_message.len() > 5000 {
        return Err(SafeSmartAccountError::InvalidInput {
            attribute: "message",
            message: "Message is too long".to_string(),
        });
    }

    Ok(cleaned_message)
}

impl SiweCapable for SafeSmartAccount {
    fn validate_siwe_message(
        &self,
        raw_message: &str,
        wallet_address: &str,
        current_url: &str,
        integration_url: &str,
    ) -> Result<SiweValidationResponse, SafeSmartAccountError> {
        use format::{
            CHAIN_TAG, EXP_TAG, IAT_TAG, NBF_TAG, NONCE_TAG, PREAMBLE, RES_TAG,
            RID_TAG, URI_TAG, VERSION_TAG,
        };

        let raw_message = precheck_and_sanitize_message(raw_message)?;
        let mut lines = raw_message.lines();

        // Check the preamble
        let preamble =
            lines
                .next()
                .ok_or_else(|| SafeSmartAccountError::InvalidInput {
                    attribute: "preamble",
                    message: "Missing Preamble Line".to_string(),
                })?;

        if !preamble.ends_with(PREAMBLE) {
            return Err(SafeSmartAccountError::InvalidInput {
                attribute: "preamble",
                message: "Missing Preamble Line".to_string(),
            });
        }

        let uri = preamble
            .strip_suffix(PREAMBLE)
            .ok_or_else(|| SafeSmartAccountError::InvalidInput {
                attribute: "preamble",
                message: "Invalid preamble format".to_string(),
            })?
            .to_string();

        // Check domain
        let integration_domain = extract_domain(integration_url)?;
        let current_url_domain = extract_domain(current_url)?;
        let uri_domain = Uri::from_str(&uri)
            .map_err(|_| SafeSmartAccountError::InvalidInput {
                attribute: "uri",
                message: "Invalid URI format".to_string(),
            })?
            .host()
            .ok_or_else(|| SafeSmartAccountError::InvalidInput {
                attribute: "uri",
                message: "URI missing host".to_string(),
            })?
            .to_owned();

        if uri_domain != integration_domain && uri_domain != current_url_domain {
            return Err(SafeSmartAccountError::InvalidInput {
                attribute: "uri",
                message: "URI domain does not match integration or current URL domain"
                    .to_string(),
            });
        }

        // Check scheme
        let uri_parsed =
            Uri::from_str(&uri).map_err(|_| SafeSmartAccountError::InvalidInput {
                attribute: "uri",
                message: "Invalid URI format".to_string(),
            })?;

        if let Some(scheme) = uri_parsed.scheme() {
            if scheme != "https" {
                return Err(SafeSmartAccountError::InvalidInput {
                    attribute: "scheme",
                    message: "Scheme must be HTTPS".to_string(),
                });
            }
        }

        // Check address
        lines
            .next()
            .filter(|&addr| {
                addr.to_lowercase() == wallet_address.to_lowercase()
                    || addr == "{address}"
            })
            .ok_or_else(|| SafeSmartAccountError::InvalidInput {
                attribute: "address",
                message: "Invalid Address".to_string(),
            })?;

        lines.next(); // skip a line

        let mut statement = String::new();
        match lines.next() {
            None => {
                return Err(SafeSmartAccountError::InvalidInput {
                    attribute: "message",
                    message: "No lines found after address".to_string(),
                });
            }
            Some("") => {}
            Some(s) => {
                lines.next(); // new line validation is done by checking URI
                statement = s.to_string();
            }
        };

        let uri = extract_domain(tagged(URI_TAG, lines.next())?)?;
        if uri != current_url_domain {
            return Err(SafeSmartAccountError::InvalidInput {
                attribute: "uri",
                message: "URI does not match current URL".to_string(),
            });
        }

        if tagged(VERSION_TAG, lines.next())? != "1" {
            return Err(SafeSmartAccountError::InvalidInput {
                attribute: "version",
                message: "Version must be 1".to_string(),
            });
        }

        if !["480"].contains(&tagged(CHAIN_TAG, lines.next())?) {
            return Err(SafeSmartAccountError::InvalidInput {
                attribute: "chain_id",
                message: "Chain ID must be 480 (World Chain)".to_string(),
            });
        }

        if tagged(NONCE_TAG, lines.next())?.len() < 8 {
            return Err(SafeSmartAccountError::InvalidInput {
                attribute: "nonce",
                message: "Nonce must be longer than 8 characters".to_string(),
            });
        }

        // Check issued at
        let issued_at = OffsetDateTime::parse(tagged(IAT_TAG, lines.next())?, &Rfc3339)
            .map_err(|_| SafeSmartAccountError::InvalidInput {
                attribute: "issued_at",
                message: "Invalid IAT".to_string(),
            })?;
        let current_time = OffsetDateTime::now_utc();

        if current_time - issued_at > Duration::minutes(5) {
            return Err(SafeSmartAccountError::InvalidInput {
                attribute: "issued_at",
                message: "IAT is more than 5 minutes old".to_string(),
            });
        }

        let mut line = lines.next();

        // Check expiration
        if let Some(exp) = tag_optional(EXP_TAG, line)? {
            line = lines.next();
            let expiration_time =
                OffsetDateTime::parse(exp, &Rfc3339).map_err(|_| {
                    SafeSmartAccountError::InvalidInput {
                        attribute: "expiration",
                        message: "Invalid Expiration format".to_string(),
                    }
                })?;
            if expiration_time - current_time > Duration::days(7) {
                return Err(SafeSmartAccountError::InvalidInput {
                    attribute: "expiration",
                    message: "Expiration time is more than 7 days in the future"
                        .to_string(),
                });
            }
        }

        if let Some(nbf) = tag_optional(NBF_TAG, line)? {
            line = lines.next();
            let nbf_time = OffsetDateTime::parse(nbf, &Rfc3339).map_err(|_| {
                SafeSmartAccountError::InvalidInput {
                    attribute: "not_before",
                    message: "Invalid Not Before format".to_string(),
                }
            })?;
            if nbf_time - current_time > Duration::days(7) {
                return Err(SafeSmartAccountError::InvalidInput {
                    attribute: "not_before",
                    message: "Not before time is more than 7 days in the future"
                        .to_string(),
                });
            }
        }

        if tag_optional(RID_TAG, line)?.is_some() {
            line = lines.next();
        }

        match line {
            Some(RES_TAG) => {
                return Err(SafeSmartAccountError::InvalidInput {
                    attribute: "resources",
                    message: "No resources allowed".to_string(),
                })
            }
            Some(_) => {
                return Err(SafeSmartAccountError::InvalidInput {
                    attribute: "message",
                    message: "Unexpected at end of message".to_string(),
                })
            }
            None => {}
        }

        let current_url_scheme = extract_scheme(current_url)?;
        let content_to_hash = format!(
            "{current_url_scheme}://{current_url_domain}{wallet_address}{statement}"
        );
        let hashed_message = keccak256(content_to_hash.as_bytes()).iter().fold(
            String::new(),
            |mut acc, byte| {
                write!(acc, "{byte:02x}").unwrap();
                acc
            },
        );

        Ok(SiweValidationResponse {
            statement,
            domain: format!("{current_url_scheme}://{current_url_domain}"),
            result: ValidationSuccess {
                message: raw_message,
            },
            hashed_message,
        })
    }

    fn sign_siwe_message(
        &self,
        message: &ValidationSuccess,
        chain_id: u32,
    ) -> Result<SiweSignatureResponse, SafeSmartAccountError> {
        let checksummed_address = Address::from_str(&self.wallet_address.to_string())
            .map_err(|_| SafeSmartAccountError::InvalidInput {
                attribute: "wallet_address",
                message: "Failed to parse wallet address".to_string(),
            })?
            .to_checksum(None);

        let message_with_replaced_address =
            message.message.replace("{address}", &checksummed_address);

        let signature =
            self.personal_sign(chain_id, message_with_replaced_address.clone())?;

        Ok(SiweSignatureResponse {
            signature: signature.to_hex_string(),
            message: message_with_replaced_address,
        })
    }

    fn create_auth_message(
        &self,
        auth_config: AuthConfig,
    ) -> Result<String, SafeSmartAccountError> {
        match auth_config {
            AuthConfig::WorldApp {
                flow,
                base_url,
                nonce,
                current_time,
            } => {
                let current_time = OffsetDateTime::from_unix_timestamp(
                    i64::try_from(current_time).map_err(|_| {
                        SafeSmartAccountError::InvalidInput {
                            attribute: "timestamp",
                            message: "Invalid timestamp".to_string(),
                        }
                    })?,
                )
                .map_err(|_| SafeSmartAccountError::InvalidInput {
                    attribute: "timestamp",
                    message: "Failed to convert timestamp".to_string(),
                })?;

                let nonce = match nonce {
                    Some(n) => n,
                    None => {
                        let mut bytes = [0u8; 4];
                        getrandom::getrandom(&mut bytes).map_err(|_| {
                            SafeSmartAccountError::Generic {
                                message: "Failed to generate random nonce".to_string(),
                            }
                        })?;
                        u32::from_be_bytes(bytes)
                    }
                };

                world_app_auth::create_message(
                    &base_url,
                    flow,
                    &self.wallet_address.to_string(),
                    current_time,
                    nonce,
                )
                .map_err(|e| SafeSmartAccountError::Generic {
                    message: e.to_string(),
                })
            }
            AuthConfig::MiniApp { .. } => {
                // Mini app auth message creation would go here
                // For now, returning an error as this is not implemented yet
                Err(SafeSmartAccountError::Generic {
                    message: "Mini app auth not yet implemented".to_string(),
                })
            }
        }
    }
}

// Additional methods for World App signing (feature-gated for tests)
#[cfg(feature = "tooling_tests")]
impl SafeSmartAccount {
    /// Signs a SIWE message for World App primary authentication using EOA.
    /// This is for compatibility with existing World App auth flow.
    pub async fn sign_world_app_auth_message_async(
        &self,
        message: ValidationSuccess,
        ethereum_key: String,
    ) -> Result<SiweSignatureResponse, SafeSmartAccountError> {
        let signer = LocalSigner::from_slice(
            &hex::decode(ethereum_key)
                .map_err(|e| SafeSmartAccountError::KeyDecoding(e.to_string()))?,
        )
        .map_err(|e| SafeSmartAccountError::KeyDecoding(e.to_string()))?;

        let message_text = message.message;
        let signature = signer
            .sign_message(message_text.as_bytes())
            .await
            .map_err(|err| SafeSmartAccountError::Signing(err))?;

        Ok(SiweSignatureResponse {
            signature: signature.to_string(),
            message: message_text,
        })
    }
}

#[cfg(test)]
impl PartialEq for SiweValidationResponse {
    fn eq(&self, other: &Self) -> bool {
        self.result.message == other.result.message
            && self.statement == other.statement
            && self.domain == other.domain
            && self.hashed_message == other.hashed_message
    }
}

#[cfg(test)]
pub(crate) mod test;
