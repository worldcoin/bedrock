use std::str::FromStr;

use alloy::primitives::Address;
use chrono::{DateTime, Utc};
use http::{uri::Authority, Uri};

use crate::{primitives::HexEncodedData, smart_account::SafeSmartAccount};

/// Contains World App-specific logic for Sign in with Ethereum
mod world_app;
pub use world_app::WorldAppAuthFlow;

/// EIP-4361 version.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Version {
    /// V1
    V1 = 1,
}

#[derive(Debug, PartialEq, Eq, uniffi::Object)]
pub struct Message {
    /// The RFC 3986 authority that is requesting the signing.
    pub domain: Authority,
    /// The Ethereum address performing the signing conformant to capitalization encoded checksum specified in EIP-55 where applicable.
    pub address: Address,
    /// A human-readable ASCII assertion that the user will sign, and it must not contain '\n' (the byte 0x0a).
    pub statement: Option<String>,
    /// An RFC 3986 URI referring to the resource that is the subject of the signing (as in the subject of a claim).
    pub uri: Uri,
    /// The current version of the message, which MUST be 1 for this specification.
    pub version: Version,
    /// The EIP-155 Chain ID to which the session is bound, and the network where Contract Accounts MUST be resolved.
    pub chain_id: u64,
    /// A randomized token typically chosen by the relying party and used to prevent replay attacks, at least 8 alphanumeric characters.
    pub nonce: String,
    /// The ISO 8601 datetime string of the current time.
    pub issued_at: DateTime<Utc>,
    /// The ISO 8601 datetime string that, if present, indicates when the signed authentication message is no longer valid.
    pub expiration_time: Option<DateTime<Utc>>,
    /// The ISO 8601 datetime string that, if present, indicates when the signed authentication message will become valid.
    pub not_before: Option<DateTime<Utc>>,
    /// An system-specific identifier that may be used to uniquely refer to the sign-in request.
    pub request_id: Option<String>,
    /// A list of information or references to information the user wishes to have resolved as part of authentication by the relying party. They are expressed as RFC 3986 URIs separated by "\n- " where \n is the byte 0x0a.
    pub resources: Vec<Uri>,
}

#[uniffi::export]
impl Message {
    #[uniffi::constructor]
    pub fn from_str_with_account(
        s: String,
        smart_account: &SafeSmartAccount,
    ) -> Result<Self, String> {
        // FIXME: typed errors
        // temporarily set a zero address for initial parsing
        let s = s.replace("{address}", &Address::ZERO.to_checksum(None));
        let mut msg = Self::from_str(&s)?;
        msg.address = smart_account.wallet_address.to_checksum(msg.chain_id);
        msg
    }

    #[uniffi::constructor]
    pub fn from_world_app_auth_request(flow: WorldAppAuthFlow) -> Self {
        // use now_with_ntp
        todo!("todo");
    }

    pub fn to_cache_hash(&self) -> String {
        todo!("todo");
    }

    pub fn sign(&self, smart_account: &SafeSmartAccount) -> HexEncodedData {
        todo!("todo");
    }
}

impl FromStr for Message {
    /// Parses a SIWE Message from a raw message as string
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // full parsing with typed errors
        todo!("todo");
    }
}

impl Default for Message {
    // sensible defaults (e.g. iat now; exp in 10 minutes; random nonce; world chain chain id, ...)
}
