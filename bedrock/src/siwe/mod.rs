use crate::siwe::world_app_auth::{create_message, WorldAppAuthFlow};
use crate::smart_account::SafeSmartAccount;
use alloy::primitives::Address;
use alloy::signers::local::LocalSigner;
use format::{
    CHAIN_TAG, EXP_TAG, IAT_TAG, NBF_TAG, NONCE_TAG, PREAMBLE, RES_TAG, RID_TAG,
    URI_TAG, VERSION_TAG,
};
use http::uri::Uri;
use semaphore_rs_utils::keccak256;
use serde::{Deserialize, Serialize};
use std::{fmt::Write, str::FromStr, sync::Arc};
use time::{
    format_description::well_known::Rfc3339, OffsetDateTime, PrimitiveDateTime,
};

#[cfg(feature = "tooling_tests")]
use {alloy::signers::Signer, tokio::runtime::Runtime};

mod format;
mod world_app_auth;

/// SIWE message format version.
pub enum Version {
    /// Version 1 of the SIWE message format.
    V1 = 1,
}

/// Errors that can occur when working with SIWE.
#[crate::bedrock_error]
pub enum SiweError {
    /// SIWE validation failed
    #[error("SIWE validation error: {0}")]
    ValidationError(String),
    /// Failed to decode a hex-encoded secret key
    #[error("Failed to decode hex-encoded secret key: {0}")]
    KeyDecoding(String),
    /// Failed to sign message
    #[error("Failed to sign message: {0}")]
    SigningError(String),
    /// Failed to sign message (legacy alias)
    #[error("Failed to sign message: {0}")]
    FailedToSignMessage(String),
    /// Failed to convert timestamp to datetime
    #[error("Failed to convert timestamp to datetime")]
    TimestampConversion,
    /// Failed to get randomness
    #[error("Failed to get randomness")]
    RandomnessError,
    /// Invalid Ethereum key
    #[error("Invalid Ethereum key: {0}")]
    InvalidEthereumKey(String),
    /// Failed to initialize wallet address
    #[error("Failed to initialize wallet address")]
    WalletAddressInit,
    /// Generic error
    #[error("{message}")]
    Generic {
        /// Error message
        message: String,
    },
}

/// Result type for SIWE operations.
pub type SiweResult<T> = Result<T, SiweError>;

fn tagged<'a>(tag: &'static str, line: Option<&'a str>) -> Result<&'a str, SiweError> {
    line.and_then(|l| l.strip_prefix(tag))
        .ok_or_else(|| SiweError::ValidationError(format!("Missing '{tag}'")))
}

fn tag_optional<'a>(
    tag: &'static str,
    line: Option<&'a str>,
) -> Result<Option<&'a str>, SiweError> {
    match tagged(tag, line) {
        Ok(value) => Ok(Some(value)),
        Err(e) => match e {
            SiweError::ValidationError(ref msg)
                if msg == &format!("Missing '{tag}'") =>
            {
                Ok(None)
            }
            _ => Err(e),
        },
    }
}

fn extract_domain(uri: &str) -> SiweResult<String> {
    Uri::from_str(uri)
        .map_err(|_| SiweError::ValidationError("Invalid URL".to_string()))?
        .host()
        .map(std::string::ToString::to_string)
        .ok_or_else(|| SiweError::ValidationError("Missing domain".to_string()))
}

fn extract_scheme(uri: &str) -> SiweResult<String> {
    Uri::from_str(uri)
        .map_err(|_| SiweError::ValidationError("Invalid URL".to_string()))?
        .scheme()
        .map(std::string::ToString::to_string)
        .ok_or_else(|| SiweError::ValidationError("Missing domain".to_string()))
}

fn validate_uri_and_domains(
    lines: &[&str],
    current_url: &str,
    integration_url: &str,
) -> SiweResult<(String, String, String)> {
    let uri: Uri = lines
        .first()
        .and_then(|preamble| preamble.strip_suffix(PREAMBLE))
        .ok_or_else(|| SiweError::ValidationError("Missing Preamble Line".to_string()))?
        .parse()
        .map_err(|_| SiweError::ValidationError("Invalid URI format".to_string()))?;

    let integration_domain = extract_domain(integration_url)?;
    let current_url_domain = extract_domain(current_url)?;
    let uri_domain = uri
        .host()
        .ok_or_else(|| SiweError::ValidationError("URI missing host".to_string()))?
        .to_owned();

    if uri_domain != integration_domain && uri_domain != current_url_domain {
        return Err(SiweError::ValidationError(
            "URI domain does not match integration or current URL domain".to_string(),
        ));
    }

    uri.scheme()
        .is_none_or(|s| s == "https")
        .then_some(())
        .ok_or_else(|| {
            SiweError::ValidationError("Scheme must be HTTPS".to_string())
        })?;

    Ok((uri_domain, integration_domain, current_url_domain))
}

// This function should sanitize the message from <> and check payload length
fn precheck_and_sanitize_message(message: &str) -> SiweResult<String> {
    // We simply escape brackets for now.
    let cleaned_message = message.replace(['<', '>'], "").trim().to_string();

    if cleaned_message.len() > 5000 {
        return Err(SiweError::ValidationError(
            "Message is too long".to_string(),
        ));
    }

    Ok(cleaned_message)
}

fn validate_address_and_statement(
    lines: &[&str],
    wallet_address: &str,
) -> SiweResult<String> {
    lines
        .get(1)
        .filter(|&addr| {
            addr.to_lowercase() == wallet_address.to_lowercase() || *addr == "{address}"
        })
        .ok_or_else(|| SiweError::ValidationError("Invalid Address".to_string()))?;

    let statement = match lines.get(3) {
        None => {
            return Err(SiweError::ValidationError(
                "No lines found after address".to_string(),
            ))
        }
        Some(&"") => String::new(), // World app format - no statement
        Some(&s) => s.to_string(),  // Mini app format - has statement
    };

    Ok(statement)
}

fn validate_siwe_fields(lines: &[&str], current_url_domain: &str) -> SiweResult<()> {
    // Find the URI line - it should start with "URI: "
    let uri_line_idx = lines
        .iter()
        .position(|line| line.starts_with(URI_TAG))
        .ok_or_else(|| SiweError::ValidationError("Missing URI field".to_string()))?;

    let uri = extract_domain(tagged(URI_TAG, lines.get(uri_line_idx).copied())?)?;
    if uri != current_url_domain {
        return Err(SiweError::ValidationError(
            "URI does not match current URL".to_string(),
        ));
    }

    if tagged(VERSION_TAG, lines.get(uri_line_idx + 1).copied())? != "1" {
        return Err(SiweError::ValidationError("Version must be 1".to_string()));
    }

    if !["480"].contains(&tagged(CHAIN_TAG, lines.get(uri_line_idx + 2).copied())?) {
        return Err(SiweError::ValidationError(
            "Chain ID must be 480 (World Chain)".to_string(),
        ));
    }

    if tagged(NONCE_TAG, lines.get(uri_line_idx + 3).copied())?.len() < 8 {
        return Err(SiweError::ValidationError(
            "Nonce must be longer than 8 characters".to_string(),
        ));
    }

    Ok(())
}

fn validate_timestamps(lines: &[&str]) -> SiweResult<()> {
    // Find the IAT line - it should start with "Issued At: "
    let iat_line_idx = lines
        .iter()
        .position(|line| line.starts_with(IAT_TAG))
        .ok_or_else(|| SiweError::ValidationError("Missing IAT field".to_string()))?;

    // Check issued at is valid and not more than 5 minutes old
    let issued_at = PrimitiveDateTime::parse(
        tagged(IAT_TAG, lines.get(iat_line_idx).copied())?,
        &Rfc3339,
    )
    .map_err(|_| SiweError::ValidationError("Invalid IAT".to_string()))?
    .assume_utc();
    let current_time = OffsetDateTime::now_utc();

    if (current_time - issued_at) > time::Duration::minutes(5) {
        return Err(SiweError::ValidationError(
            "IAT is more than 5 minutes old".to_string(),
        ));
    }

    // Check expiration time
    if let Some(exp) = tag_optional(EXP_TAG, lines.get(iat_line_idx + 1).copied())? {
        let expiration_time = PrimitiveDateTime::parse(exp, &Rfc3339)
            .map_err(|_| {
                SiweError::ValidationError("Invalid Expiration format".to_string())
            })?
            .assume_utc();
        if (expiration_time - current_time) > time::Duration::days(7) {
            return Err(SiweError::ValidationError(
                "Expiration time is more than 7 days in the future".to_string(),
            ));
        }
    }

    // Check not before time
    if let Some(nbf) = tag_optional(NBF_TAG, lines.get(iat_line_idx + 2).copied())? {
        let nbf_time = PrimitiveDateTime::parse(nbf, &Rfc3339)
            .map_err(|_| {
                SiweError::ValidationError("Invalid Expiration format".to_string())
            })?
            .assume_utc();
        if (nbf_time - current_time) > time::Duration::days(7) {
            return Err(SiweError::ValidationError(
                "Not before time is more than 7 days in the future".to_string(),
            ));
        }
    }

    // Check for request ID and resources at the end
    let mut check_idx = iat_line_idx + 3;
    if tag_optional(RID_TAG, lines.get(check_idx).copied())?.is_some() {
        check_idx += 1;
    }

    match lines.get(check_idx).copied() {
        Some(line) if line.starts_with(RES_TAG) => Err(SiweError::ValidationError(
            "No resources allowed".to_string(),
        )),
        _ => Ok(()), // Could be additional fields we don't care about or end of message
    }
}

/// Represents a successfully validated SIWE message.
#[derive(Serialize, Deserialize, Debug, uniffi::Record)]
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

#[cfg(test)]
impl PartialEq for SiweValidationResponse {
    fn eq(&self, other: &Self) -> bool {
        self.result.message == other.result.message
            && self.statement == other.statement
            && self.domain == other.domain
            && self.hashed_message == other.hashed_message
    }
}

/// Response containing a SIWE signature and the signed message.
#[derive(Serialize, Deserialize, Debug, uniffi::Record)]
pub struct SiweSignatureResponse {
    /// The cryptographic signature
    pub signature: String,
    /// The message that was signed
    pub message: String,
}

/// SIWE (Sign-In with Ethereum) implementation for authentication flows.
#[derive(uniffi::Object)]
pub struct Siwe {
    /// Base URL to use for World App auth SIWE messages. Use production or staging URLs.
    /// For example, <https://app-backend.toolsforhumanity.com>.
    auth_base_url: String,
}

#[crate::bedrock_export]
impl Siwe {
    /// Creates a new SIWE instance.
    #[must_use]
    #[uniffi::constructor]
    pub fn new(auth_base_url: String) -> Arc<Self> {
        Arc::new(Self { auth_base_url })
    }

    /// ====================================================================
    /// ========================== Mini App Auth ===========================
    /// ====================================================================
    /// Validates a SIWE message for mini app authentication.
    /// Returns a validation response containing the statement, domain, hashed message, and result.
    ///
    /// # Errors
    /// Returns an error if the message is invalid, has expired timestamps, or contains invalid URIs.
    pub fn validate_auth_message(
        &self,
        raw_message: &str,
        wallet_address: &str,
        current_url: &str,
        integration_url: &str,
    ) -> SiweResult<SiweValidationResponse> {
        let raw_message = precheck_and_sanitize_message(raw_message)?;
        let lines: Vec<&str> = raw_message.split('\n').collect();

        // Validate URI and domains
        let (_, _, current_url_domain) =
            validate_uri_and_domains(&lines, current_url, integration_url)?;

        // Validate address and extract statement
        let statement = validate_address_and_statement(&lines, wallet_address)?;

        // Validate SIWE fields
        validate_siwe_fields(&lines, &current_url_domain)?;

        // Validate timestamps
        validate_timestamps(&lines)?;

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

    /// This is a v2 implementation of Wallet Auth for mini apps which uses SafeSmartAccount
    /// And fixes issues with double prefixing by using EIP-712
    ///
    /// # Errors
    /// Returns an error if the wallet address is invalid, smart account creation fails, or signing fails.
    pub fn sign_wallet_auth_message_v2(
        &self,
        message: &ValidationSuccess,
        private_key: String,
        wallet_address: &str,
    ) -> SiweResult<SiweSignatureResponse> {
        let checksummed_address = Address::from_str(wallet_address)
            .map_err(|_| SiweError::WalletAddressInit)?
            .to_checksum(None);
        let message_with_replaced_address =
            message.message.replace("{address}", &checksummed_address);
        let safe = SafeSmartAccount::new(private_key, wallet_address)
            .map_err(|e| SiweError::SigningError(e.to_string()))?;
        let signature = safe
            .personal_sign(480, message_with_replaced_address.clone())
            .map_err(|e| SiweError::SigningError(e.to_string()))?;
        Ok(SiweSignatureResponse {
            signature: signature.to_hex_string(),
            message: message_with_replaced_address,
        })
    }

    /// ====================================================================
    /// ========================== World App Auth ==========================
    /// ====================================================================
    /// Generates a SIWE message to sign for World App primary authentication.
    /// Should be used during token refresh, restore and signup.
    /// Returns raw message to validate and sign.
    ///
    /// # Errors
    /// Returns an error if timestamp conversion fails or random number generation fails.
    pub fn create_world_app_auth_message(
        &self,
        flow: WorldAppAuthFlow,
        wallet_address: &str,
        current_time: u64,
    ) -> SiweResult<String> {
        let current_time = OffsetDateTime::from_unix_timestamp(
            i64::try_from(current_time).map_err(|_| SiweError::TimestampConversion)?,
        )
        .map_err(|_| SiweError::TimestampConversion)?;
        let nonce = {
            let mut bytes = [0u8; 4];
            getrandom::getrandom(&mut bytes).map_err(|_| SiweError::RandomnessError)?;
            u32::from_be_bytes(bytes)
        };
        create_message(
            &self.auth_base_url,
            flow,
            wallet_address,
            current_time,
            nonce,
        )
    }

    /// Signs a SIWE message for World App primary authentication.
    /// Assumes that the message is already validated.
    ///
    /// There are two notable differences from the standard SIWE signing:
    /// 1) We don't double prefix the message with \x19Ethereum Signed Message:\n. It was a bug
    /// in the original implementation, but we can't break compatibility.
    /// 2) We don't need to checksum the address, since it's already checksummed in the message
    /// from create_world_app_auth_message.
    /// 3) Signature is returned as a hex string prefixed with `0x`.
    ///
    /// Note that message will be signed from an EOA address, not a Safe address.
    /// This is because Safe signature should follow a different standard — see
    /// `sign_personal_sign_message` implementation in the Gnosis Safe module.
    ///
    /// # Errors
    /// Returns an error if the Ethereum key is invalid or message signing fails.
    #[cfg(feature = "tooling_tests")]
    pub fn sign_world_app_auth_message(
        &self,
        message: ValidationSuccess,
        ethereum_key: String,
    ) -> SiweResult<SiweSignatureResponse> {
        let rt = Runtime::new().map_err(|e| SiweError::Generic {
            message: format!("Failed to create runtime: {e}"),
        })?;
        rt.block_on(self.sign_world_app_auth_message_async(message, ethereum_key))
    }

    #[cfg(feature = "tooling_tests")]
    async fn sign_world_app_auth_message_async(
        &self,
        message: ValidationSuccess,
        ethereum_key: String,
    ) -> SiweResult<SiweSignatureResponse> {
        let signer = LocalSigner::from_slice(
            &hex::decode(ethereum_key)
                .map_err(|e| SiweError::InvalidEthereumKey(e.to_string()))?,
        )
        .map_err(|e| SiweError::InvalidEthereumKey(e.to_string()))?;

        let message_text = message.message; // We unwrap the message here since we accept ValidationSuccess

        let signature = signer
            .sign_message(message_text.as_bytes())
            .await
            .map_err(|err| SiweError::FailedToSignMessage(err.to_string()))?;

        Ok(SiweSignatureResponse {
            signature: signature.to_string(),
            message: message_text,
        })
    }
}

#[cfg(test)]
mod test;
