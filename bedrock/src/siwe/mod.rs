use std::fmt::{self, Display};
use std::str::FromStr;

use alloy::primitives::{keccak256, Address};
use chrono::{DateTime, Duration, Utc};
use http::uri::{Authority, Scheme};
use http::Uri;
use rand::rngs::OsRng;
use rand::RngCore;

use crate::primitives::ntp::now_with_ntp;
use crate::primitives::{HexEncodedData, ParseFromForeignBinding, PrimitiveError};
use crate::smart_account::SafeSmartAccount;
use crate::smart_account::SafeSmartAccountSigner;

/// Contains World App-specific logic for Sign in with Ethereum
mod world_app;
pub use world_app::WorldAppAuthFlow;

// EIP-4361 line tags
const PREAMBLE: &str = " wants you to sign in with your Ethereum account:";
const URI_TAG: &str = "URI: ";
const VERSION_TAG: &str = "Version: ";
const CHAIN_TAG: &str = "Chain ID: ";
const NONCE_TAG: &str = "Nonce: ";
const IAT_TAG: &str = "Issued At: ";
const EXP_TAG: &str = "Expiration Time: ";
const NBF_TAG: &str = "Not Before: ";
const RID_TAG: &str = "Request ID: ";
const RES_TAG: &str = "Resources:";

/// Minimum nonce length per EIP-4361 (8 alphanumeric characters).
const MIN_NONCE_LEN: usize = 8;

/// Maximum raw message length accepted by the parser.
const MAX_MESSAGE_LEN: usize = 4096;

const DEFAULT_CHAIN_ID: u32 = 480;

/// EIP-4361 version.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Version {
    /// V1
    V1 = 1,
}

impl Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::V1 => f.write_str("1"),
        }
    }
}

impl FromStr for Version {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "1" => Ok(Self::V1),
            other => Err(ParseError::Field(format!("unsupported version: {other}"))),
        }
    }
}

/// Errors that can occur when parsing a SIWE message from a string.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ParseError {
    /// A required line or tag is missing from the message.
    #[error("missing {0}")]
    Missing(&'static str),
    /// A field value is malformed or does not satisfy the spec.
    #[error("{0}")]
    Field(String),
}

/// Errors raised by SIWE operations (parsing, signing, message construction).
#[crate::bedrock_error]
pub enum SiweError {
    /// The SIWE message could not be parsed from the input string.
    #[error("failed to parse SIWE message: {0}")]
    Parse(String),
    /// The base URL could not be parsed into a valid URI or authority.
    #[error("invalid base URL: {0}")]
    InvalidBaseUrl(String),
    /// Signing the message failed.
    #[error("signing failed: {0}")]
    Signing(String),
    /// The requested messaged is not authorized. This could me a mismatched with the
    /// pre-authorized URL, the current integration URL or the requested resource in
    /// the message.
    #[error("unauthorized_host")]
    UnauthorizedHost,
    /// A provided raw input could not be parsed, is incorrectly formatted, incorrectly encoded or otherwise invalid.
    #[error("invalid input on {attribute}: {error_message}")]
    InvalidInput {
        /// The name of the attribute that was invalid.
        attribute: String,
        /// Explicit failure message for the attribute validation.
        error_message: String,
    },
}

impl From<ParseError> for SiweError {
    fn from(err: ParseError) -> Self {
        Self::Parse(err.to_string())
    }
}

impl From<PrimitiveError> for SiweError {
    fn from(err: PrimitiveError) -> Self {
        match err {
            PrimitiveError::InvalidInput {
                attribute,
                error_message,
            } => Self::InvalidInput {
                attribute,
                error_message,
            },
            _ => Self::Generic {
                error_message: err.to_string(),
            },
        }
    }
}

/// An [EIP-4361](https://eips.ethereum.org/EIPS/eip-4361) Sign-In with Ethereum message.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Object)]
pub struct SiweMessage {
    /// RFC 3986 scheme for the authority which is requesting the signing.
    pub scheme: Option<Scheme>,
    /// RFC 3986 authority that is requesting the signing.
    pub domain: Authority,
    /// EIP-55 checksummed Ethereum address performing the signing.
    pub address: Address,
    /// Optional human-readable ASCII assertion (must not contain `\n`).
    pub statement: Option<String>,
    /// RFC 3986 URI referring to the resource that is the subject of the signing.
    pub uri: Uri,
    /// Current version of the SIWE message (must be 1).
    pub version: Version,
    /// EIP-155 Chain ID to which the session is bound.
    pub chain_id: u32,
    /// Randomized token for replay protection (>= 8 alphanumeric chars).
    pub nonce: String,
    /// ISO 8601 datetime string of the current time.
    pub issued_at: DateTime<Utc>,
    /// When the signed authentication message is no longer valid.
    pub expiration_time: Option<DateTime<Utc>>,
    /// When the signed authentication message will become valid.
    pub not_before: Option<DateTime<Utc>>,
    /// System-specific identifier for the sign-in request.
    pub request_id: Option<String>,
    /// List of RFC 3986 URIs the user wishes to have resolved.
    pub resources: Vec<Uri>,
}

impl Display for SiweMessage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}{PREAMBLE}", self.domain)?;
        write!(f, "\n{}", self.address.to_checksum(None))?;
        f.write_str("\n")?;

        match &self.statement {
            Some(stmt) => write!(f, "\n{stmt}\n")?,
            None => f.write_str("\n")?,
        }

        write!(f, "\n{URI_TAG}{}", self.uri)?;
        write!(f, "\n{VERSION_TAG}{}", self.version)?;
        write!(f, "\n{CHAIN_TAG}{}", self.chain_id)?;
        write!(f, "\n{NONCE_TAG}{}", self.nonce)?;
        write!(f, "\n{IAT_TAG}{}", self.issued_at.to_rfc3339())?;

        if let Some(exp) = &self.expiration_time {
            write!(f, "\n{EXP_TAG}{}", exp.to_rfc3339())?;
        }
        if let Some(nbf) = &self.not_before {
            write!(f, "\n{NBF_TAG}{}", nbf.to_rfc3339())?;
        }
        if let Some(rid) = &self.request_id {
            write!(f, "\n{RID_TAG}{rid}")?;
        }
        if !self.resources.is_empty() {
            write!(f, "\n{RES_TAG}")?;
            for res in &self.resources {
                write!(f, "\n- {res}")?;
            }
        }

        Ok(())
    }
}

/// Extracts the value after a tag prefix, or returns a `Missing` error.
fn tagged<'a>(tag: &'static str, line: Option<&'a str>) -> Result<&'a str, ParseError> {
    line.and_then(|l| l.strip_prefix(tag))
        .ok_or(ParseError::Missing(tag))
}

/// Like [`tagged`] but returns `None` when the line does not
/// start with `tag` (instead of erroring).
fn tag_optional<'a>(tag: &str, line: Option<&'a str>) -> Option<&'a str> {
    line.and_then(|l| l.strip_prefix(tag))
}

fn parse_datetime(s: &str, label: &str) -> Result<DateTime<Utc>, ParseError> {
    DateTime::parse_from_rfc3339(s)
        .map(|dt| dt.with_timezone(&Utc))
        .map_err(|_| ParseError::Field(format!("invalid {label} datetime")))
}

/// Sanitizes raw input: strips `<>` brackets, trims whitespace, enforces max length.
fn sanitize(s: &str) -> Result<String, ParseError> {
    let cleaned = s.replace(['<', '>'], "");
    let cleaned = cleaned.trim();
    if cleaned.len() > MAX_MESSAGE_LEN {
        return Err(ParseError::Field("message too long".into()));
    }
    Ok(cleaned.to_owned())
}

/// Parses an `Authority` (host + port) from a full URL or bare authority
/// string, preserving origin semantics where different ports are distinct.
fn to_authority(s: &str) -> Result<Authority, http::uri::InvalidUri> {
    let after_scheme = s
        .strip_prefix("https://")
        .or_else(|| s.strip_prefix("http://"))
        .unwrap_or(s);
    let authority_str = after_scheme.split('/').next().unwrap_or(after_scheme);
    authority_str.parse()
}

impl FromStr for SiweMessage {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let sanitized = sanitize(s)?;
        let mut lines = sanitized.split('\n');

        let preamble = lines.next().ok_or(ParseError::Missing("preamble"))?;
        let domain_str = preamble
            .strip_suffix(PREAMBLE)
            .ok_or(ParseError::Missing("preamble"))?;

        let uri: Uri = Uri::from_str(domain_str)
            .map_err(|_| ParseError::Field("invalid domain".into()))?;

        let scheme = uri.scheme().cloned();

        let domain = uri
            .authority()
            .cloned()
            .ok_or_else(|| ParseError::Field("invalid domain".into()))?;

        let address_str = lines.next().ok_or(ParseError::Missing("address"))?;
        let address = Address::from_str(address_str)
            .map_err(|_| ParseError::Field("invalid address".into()))?;

        lines.next(); // blank line

        let statement = match lines.next() {
            None => {
                return Err(ParseError::Missing("body after address"));
            }
            Some("") => None,
            Some(s) => {
                lines.next(); // trailing blank line after statement
                Some(s.to_owned())
            }
        };

        let uri: Uri = tagged(URI_TAG, lines.next())?
            .parse()
            .map_err(|_| ParseError::Field("invalid URI".into()))?;

        let version = Version::from_str(tagged(VERSION_TAG, lines.next())?)?;

        let chain_id: u32 = tagged(CHAIN_TAG, lines.next())?
            .parse()
            .map_err(|_| ParseError::Field("invalid chain ID".into()))?;

        let nonce = tagged(NONCE_TAG, lines.next())?.to_owned();
        if nonce.len() < MIN_NONCE_LEN {
            return Err(ParseError::Field(format!(
                "nonce must be at least {MIN_NONCE_LEN} characters"
            )));
        }
        if !nonce.chars().all(|c| c.is_ascii_alphanumeric()) {
            return Err(ParseError::Field("nonce must be alphanumeric".into()));
        }

        let issued_at = parse_datetime(tagged(IAT_TAG, lines.next())?, "issued-at")?;

        let mut next = lines.next();

        let expiration_time = if let Some(val) = tag_optional(EXP_TAG, next) {
            next = lines.next();
            Some(parse_datetime(val, "expiration-time")?)
        } else {
            None
        };

        let not_before = if let Some(val) = tag_optional(NBF_TAG, next) {
            next = lines.next();
            Some(parse_datetime(val, "not-before")?)
        } else {
            None
        };

        let request_id = tag_optional(RID_TAG, next).map(|val| {
            next = lines.next();
            val.to_owned()
        });

        let mut resources = Vec::new();
        match next {
            None => {}
            Some(RES_TAG) => {
                for line in lines.by_ref() {
                    let res_str = line.strip_prefix("- ").ok_or_else(|| {
                        ParseError::Field("resource line must start with '- '".into())
                    })?;
                    let res_uri: Uri = res_str.parse().map_err(|_| {
                        ParseError::Field("invalid resource URI".into())
                    })?;
                    resources.push(res_uri);
                }
            }
            Some(unexpected) => {
                return Err(ParseError::Field(format!(
                    "unexpected trailing content: {unexpected}"
                )));
            }
        }

        Ok(Self {
            scheme,
            domain,
            address,
            statement,
            uri,
            version,
            chain_id,
            nonce,
            issued_at,
            expiration_time,
            not_before,
            request_id,
            resources,
        })
    }
}

impl Default for SiweMessage {
    fn default() -> Self {
        let now = now_with_ntp();
        // the minimum length according to spec is 8 alphanumeric chars; so 4 bytes hex-encoded would be enough,
        // but we deliberately use 8 to reduce collision risk
        let mut nonce = [0u8; 8];
        OsRng.fill_bytes(&mut nonce);
        let nonce = hex::encode(nonce);
        Self {
            scheme: None,
            domain: Authority::from_static("localhost"),
            address: Address::ZERO,
            statement: None,
            uri: Uri::from_static("https://localhost"),
            version: Version::V1,
            chain_id: DEFAULT_CHAIN_ID,
            nonce,
            issued_at: now,
            expiration_time: Some(now + Duration::minutes(10)),
            not_before: Some(now),
            request_id: None,
            resources: Vec::new(),
        }
    }
}

#[uniffi::export]
impl SiweMessage {
    /// Parses a SIWE message string, substituting the smart account's
    /// checksummed wallet address for the first `{address}` placeholder.
    ///
    /// # Arguments
    /// - `s`: The SIWE Message string.
    /// - `smart_account`: The user's smart account which is used to authenticate.
    /// - `authorized_url`: The expected pre-registered and authorized URL for SIWE
    ///   messages. In practical terms this is the URL registered in the Developer Portal
    ///   for the specific Mini App requesting authentication.
    /// - `querying_url`: The current URL from which the request is being made. In practical
    ///   terms this is the current URL to which the webview is pointing.
    ///
    /// # Errors
    /// - [`SiweError::Parse`] if the message string is not valid EIP-4361.
    /// - [`SiweError::UnauthorizedHost`] if the different host validations don't match expected values.
    #[uniffi::constructor]
    pub fn from_str_with_account(
        s: &str,
        smart_account: &SafeSmartAccount,
        authorized_url: &str,
        querying_url: &str,
    ) -> Result<Self, SiweError> {
        let s = s.replacen("{address}", &Address::ZERO.to_checksum(None), 1);

        let expected_authority =
            to_authority(authorized_url).map_err(|e| PrimitiveError::InvalidInput {
                attribute: "authorized_url".to_string(),
                error_message: e.to_string(),
            })?;
        let current_authority =
            to_authority(querying_url).map_err(|e| PrimitiveError::InvalidInput {
                attribute: "querying_url".to_string(),
                error_message: e.to_string(),
            })?;

        if expected_authority != current_authority {
            return Err(SiweError::UnauthorizedHost);
        }

        let mut msg = Self::from_str(&s)?;
        msg.address = smart_account.wallet_address;

        if msg.domain != expected_authority {
            return Err(SiweError::UnauthorizedHost);
        }

        let uri_authority = msg.uri.authority().ok_or(SiweError::UnauthorizedHost)?;
        if *uri_authority != expected_authority {
            return Err(SiweError::UnauthorizedHost);
        }

        Ok(msg)
    }

    /// Creates a SIWE message for World App authentication flows.
    ///
    /// Importantly, SIWE messages for World App auth uses the EOA address,
    /// not the wallet address for authentication.
    ///
    /// # Errors
    /// - [`SiweError::InvalidBaseUrl`] if the base URL cannot be parsed.
    #[uniffi::constructor]
    pub fn from_world_app_auth_request(
        flow: WorldAppAuthFlow,
        base_url: &str,
        smart_account: &SafeSmartAccount,
    ) -> Result<Self, SiweError> {
        let now = now_with_ntp();

        let uri: Uri = flow.as_siwe_uri(base_url).parse().map_err(
            |e: http::uri::InvalidUri| SiweError::InvalidBaseUrl(e.to_string()),
        )?;

        let domain: Authority = to_authority(base_url)
            .map_err(|e| SiweError::InvalidBaseUrl(e.to_string()))?;

        let expiration = now + Duration::minutes(5);

        Ok(Self {
            domain,
            address: smart_account.eoa_address(),
            uri,
            issued_at: now,
            expiration_time: Some(expiration),
            not_before: Some(now),
            ..Default::default()
        })
    }

    /// Computes a hash of the key attributes of the message for caching purposes.
    ///
    /// This is used for the "login automatically" feature where the client auto-signs
    /// for subsequent Mini Apps if the user approved it.
    ///
    /// # Errors
    /// - If the provided `current_url` is not valid
    pub fn to_cache_hash(
        &self,
        current_url: &str,
    ) -> Result<HexEncodedData, SiweError> {
        let current_url = Uri::parse_from_ffi(current_url, "current_url")?;

        let scheme = current_url
            .scheme()
            .ok_or_else(|| SiweError::InvalidInput {
                attribute: "current_url".to_string(),
                error_message: "does not have a valid scheme".to_string(),
            })?;

        let host = current_url.host().ok_or_else(|| SiweError::InvalidInput {
            attribute: "current_url".to_string(),
            error_message: "does not have a valid host".to_string(),
        })?;

        let address = self.address.to_checksum(None);
        let statement = self.statement.as_deref().unwrap_or("");
        let input = format!("{scheme}://{host}{address}{statement}");
        Ok(hex::encode(keccak256(input.as_bytes())).try_into()?)
    }

    /// Signs this SIWE message with the given Safe smart account (EIP-191).
    ///
    /// # Errors
    /// - [`SiweError::Signing`] if the signing operation fails.
    pub fn sign(
        &self,
        smart_account: &SafeSmartAccount,
    ) -> Result<HexEncodedData, SiweError> {
        let message_str = self.to_string();
        let signature = smart_account
            .sign_message_eip_191_prefixed(message_str, self.chain_id)
            .map_err(|e| SiweError::Signing(e.to_string()))?;
        Ok(signature.into())
    }

    /// Returns the serialized EIP-4361 message string.
    #[must_use]
    pub fn to_message_string(&self) -> String {
        self.to_string()
    }
}

#[cfg(test)]
mod test;
