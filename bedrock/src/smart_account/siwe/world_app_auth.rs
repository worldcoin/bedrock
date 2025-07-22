use super::format::{
    CHAIN_TAG, EXP_TAG, IAT_TAG, NBF_TAG, NONCE_TAG, PREAMBLE, URI_TAG, VERSION_TAG,
};
use crate::smart_account::SafeSmartAccountError;
use alloy::primitives::Address;
use std::ops::Add;
use std::str::FromStr;
use time::format_description::well_known::Rfc3339;
use time::{Duration, OffsetDateTime};

const TOKEN_EXPIRES_IN: Duration = Duration::minutes(5);

/// Represents the different authentication flows for World App
#[derive(Debug, Clone, Copy, uniffi::Enum)]
pub enum WorldAppAuthFlow {
    /// User has a valid and non-expired refresh token
    Refresh,
    /// No refresh token, just access to wallet
    Restore,
    /// New account
    SignUp,
}

impl WorldAppAuthFlow {
    /// Converts the authentication flow to its corresponding SIWE URI path
    pub fn to_siwe_uri(self, base_url: &str) -> String {
        let path = match self {
            Self::Refresh => "/public/v1/auth/refresh",
            Self::Restore => "/public/v1/auth/restore",
            Self::SignUp => "/public/v1/auth/sign-up",
        };
        format!("{base_url}{path}")
    }
}

/// Creates a message for the World App authentication flow using nonce and current time.
/// See tests for example message.
pub fn create_message(
    base_url: &str,
    flow: WorldAppAuthFlow,
    wallet_address: &str,
    current_time: OffsetDateTime,
    nonce: u32,
) -> Result<String, SafeSmartAccountError> {
    let uri = flow.to_siwe_uri(base_url);
    let wallet_address = Address::from_str(wallet_address)
        .map_err(|_| SafeSmartAccountError::InvalidInput {
            attribute: "wallet_address",
            message: "Failed to parse wallet address".to_string(),
        })?
        .to_checksum(None);

    let version = 1;
    let chain_id = 480; // World Chain ID;
    let issued_at = current_time
        .format(&Rfc3339)
        .expect("failed to format time");
    let expires_at = current_time
        .add(TOKEN_EXPIRES_IN)
        .format(&Rfc3339)
        .expect("failed to format time");
    let not_before = &issued_at;

    Ok(format!(
        "{base_url}{PREAMBLE}\n\
        {wallet_address}\n\n\n\
        {URI_TAG}{uri}\n\
        {VERSION_TAG}{version}\n\
        {CHAIN_TAG}{chain_id}\n\
        {NONCE_TAG}{nonce}\n\
        {IAT_TAG}{issued_at}\n\
        {EXP_TAG}{expires_at}\n\
        {NBF_TAG}{not_before}",
    ))
}

#[cfg(test)]
mod test {
    use super::*;
    use time::macros::datetime;

    #[test]
    fn test_create_message_signup() {
        let base_url = "https://app-backend.toolsforhumanity.com";
        let flow = WorldAppAuthFlow::SignUp;
        let wallet_address = "0x11a1801863e1f0941a663f0338aea395be1ec8a4";
        let current_time = datetime!(2025-01-15 23:23:25.608083 UTC);
        let nonce = 1_469_020_534;

        let message =
            create_message(base_url, flow, wallet_address, current_time, nonce)
                .unwrap();

        let expected = "https://app-backend.toolsforhumanity.com wants you to sign in with your Ethereum account:\n\
        0x11A1801863e1F0941A663f0338aEa395Be1Ec8A4\n\n\n\
        URI: https://app-backend.toolsforhumanity.com/public/v1/auth/sign-up\n\
        Version: 1\n\
        Chain ID: 480\n\
        Nonce: 1469020534\n\
        Issued At: 2025-01-15T23:23:25.608083Z\n\
        Expiration Time: 2025-01-15T23:28:25.608083Z\n\
        Not Before: 2025-01-15T23:23:25.608083Z";

        assert_eq!(message, expected);
    }
}
