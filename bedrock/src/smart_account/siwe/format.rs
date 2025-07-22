/// Constants for SIWE message format

/// Preamble suffix for SIWE messages
pub const PREAMBLE: &str = " wants you to sign in with your Ethereum account:";

/// URI tag prefix
pub const URI_TAG: &str = "URI: ";

/// Version tag prefix
pub const VERSION_TAG: &str = "Version: ";

/// Chain ID tag prefix
pub const CHAIN_TAG: &str = "Chain ID: ";

/// Nonce tag prefix
pub const NONCE_TAG: &str = "Nonce: ";

/// Issued At tag prefix
pub const IAT_TAG: &str = "Issued At: ";

/// Expiration Time tag prefix
pub const EXP_TAG: &str = "Expiration Time: ";

/// Not Before tag prefix
pub const NBF_TAG: &str = "Not Before: ";

/// Request ID tag prefix
pub const RID_TAG: &str = "Request ID: ";

/// Resources tag prefix
pub const RES_TAG: &str = "Resources:";
