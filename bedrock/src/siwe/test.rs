use std::str::FromStr;

use alloy::dyn_abi::DynSolValue;
use alloy::primitives::{
    eip191_hash_message, fixed_bytes, keccak256, Address, FixedBytes,
};
use alloy::signers::local::PrivateKeySigner;
use alloy::signers::Signature;
use chrono::{Duration, Utc};
use ruint::aliases::U256;

use super::*;
use crate::smart_account::SafeSmartAccount;

fn now_rfc3339() -> String {
    Utc::now().to_rfc3339()
}

const TEST_KEY: &str =
    "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
const TEST_WALLET: &str = "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045";

fn test_smart_account() -> SafeSmartAccount {
    SafeSmartAccount::new(TEST_KEY.into(), TEST_WALLET).unwrap()
}

fn make_valid_message(datetime: &str) -> String {
    format!(
        "example.com{PREAMBLE}\n\
         0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045\n\n\n\
         URI: https://example.com\n\
         Version: 1\n\
         Chain ID: 480\n\
         Nonce: 12345678\n\
         Issued At: {datetime}"
    )
}

#[test]
fn roundtrip_minimal() {
    let now = Utc::now();
    let msg = SiweMessage {
        scheme: Some(Scheme::from_str("https").unwrap()),
        domain: Authority::from_static("example.com"),
        address: Address::from_str(TEST_WALLET).unwrap(),
        statement: None,
        uri: "https://example.com".parse().unwrap(),
        version: Version::V1,
        chain_id: 480,
        nonce: "12345678".into(),
        issued_at: now,
        expiration_time: None,
        not_before: None,
        request_id: None,
        resources: vec![],
    };
    let serialized = msg.to_string();
    let parsed = SiweMessage::from_str(&serialized).unwrap();
    assert_eq!(parsed.domain, msg.domain);
    assert_eq!(parsed.address, msg.address);
    assert_eq!(parsed.statement, msg.statement);
    assert_eq!(parsed.version, msg.version);
    assert_eq!(parsed.chain_id, msg.chain_id);
    assert_eq!(parsed.nonce, msg.nonce);
    assert_eq!(parsed.expiration_time, msg.expiration_time);
    assert_eq!(parsed.not_before, msg.not_before);
    assert_eq!(parsed.request_id, msg.request_id);
    assert!(parsed.resources.is_empty());
}

#[test]
fn roundtrip_all_optional_fields() {
    let now = Utc::now();
    let msg = SiweMessage {
        scheme: None,
        domain: Authority::from_static("example.com"),
        address: Address::from_str(TEST_WALLET).unwrap(),
        statement: Some("I accept the Terms of Service".into()),
        uri: "https://example.com/login".parse().unwrap(),
        version: Version::V1,
        chain_id: 1,
        nonce: "abcdefgh".into(),
        issued_at: now,
        expiration_time: Some(now + Duration::hours(1)),
        not_before: Some(now),
        request_id: Some("req-123".into()),
        resources: vec![
            "https://example.com/tos".parse().unwrap(),
            "https://example.com/privacy".parse().unwrap(),
        ],
    };
    let serialized = msg.to_string();
    let parsed = SiweMessage::from_str(&serialized).unwrap();
    assert_eq!(
        parsed.statement.as_deref(),
        Some("I accept the Terms of Service")
    );
    assert_eq!(parsed.request_id.as_deref(), Some("req-123"));
    assert_eq!(parsed.resources.len(), 2);
    assert_eq!(&parsed.domain, "example.com");

    // IMPORTANT: note the lack of schema; schema is OPTIONAL per ERC-4361
    assert!(serialized.starts_with("example.com wants you to sign in"));
}

#[test]
fn parse_missing_preamble() {
    let err = SiweMessage::from_str("garbage line\n0xabc").unwrap_err();
    assert!(matches!(err, ParseError::Missing("preamble")), "got: {err}");
}

#[test]
fn parse_invalid_version() {
    let datetime = now_rfc3339();
    let raw = format!(
        "example.com{PREAMBLE}\n\
         0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045\n\n\n\
         URI: https://example.com\n\
         Version: 2\n\
         Chain ID: 480\n\
         Nonce: 12345678\n\
         Issued At: {datetime}"
    );
    let err = SiweMessage::from_str(&raw).unwrap_err();
    assert!(
        matches!(err, ParseError::Field(ref msg) if msg.contains("version")),
        "got: {err}"
    );
}

#[test]
fn parse_short_nonce() {
    let datetime = now_rfc3339();
    let raw = format!(
        "example.com{PREAMBLE}\n\
         0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045\n\n\n\
         URI: https://example.com\n\
         Version: 1\n\
         Chain ID: 480\n\
         Nonce: abc\n\
         Issued At: {datetime}"
    );
    let err = SiweMessage::from_str(&raw).unwrap_err();
    assert!(
        matches!(err, ParseError::Field(ref msg) if msg.contains("nonce")),
        "got: {err}"
    );
}

#[test]
fn parse_with_statement() {
    let datetime = now_rfc3339();
    let raw = format!(
        "example.com{PREAMBLE}\n\
         0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045\n\n\
         Sign in to the app\n\n\
         URI: https://example.com\n\
         Version: 1\n\
         Chain ID: 480\n\
         Nonce: 12345678\n\
         Issued At: {datetime}"
    );
    let msg = SiweMessage::from_str(&raw).unwrap();
    assert_eq!(msg.statement.as_deref(), Some("Sign in to the app"));
}

#[test]
fn parse_without_statement() {
    let msg = SiweMessage::from_str(&make_valid_message(&now_rfc3339())).unwrap();
    assert_eq!(msg.statement, None);
}

#[test]
fn parse_with_resources() {
    let datetime = now_rfc3339();
    let raw = format!(
        "example.com{PREAMBLE}\n\
         0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045\n\n\n\
         URI: https://example.com\n\
         Version: 1\n\
         Chain ID: 1\n\
         Nonce: 12345678\n\
         Issued At: {datetime}\n\
         Resources:\n\
         - https://example.com/tos\n\
         - https://example.com/privacy"
    );
    let msg = SiweMessage::from_str(&raw).unwrap();
    assert_eq!(msg.resources.len(), 2);
}

#[test]
fn display_format_matches_spec() {
    let now = Utc::now();
    let exp = now + Duration::hours(1);
    let msg = SiweMessage {
        scheme: Some(Scheme::HTTPS),
        domain: Authority::from_static("example.com"),
        address: Address::from_str(TEST_WALLET).unwrap(),
        statement: Some("hello".into()),
        uri: "https://example.com".parse().unwrap(),
        version: Version::V1,
        chain_id: 480,
        nonce: "abcdefgh".into(),
        issued_at: now,
        expiration_time: Some(exp),
        not_before: None,
        request_id: None,
        resources: vec![],
    };
    let s = msg.to_string();
    // note the schema is preserved
    assert!(s.starts_with("https://example.com wants you to sign in"));
    assert!(s.contains("0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045"));
    assert!(s.contains("hello"));
    assert!(s.contains("URI: https://example.com"));
    assert!(s.contains("Version: 1"));
    assert!(s.contains("Chain ID: 480"));
    assert!(s.contains("Nonce: abcdefgh"));
}

#[test]
fn cache_hash_deterministic() {
    let msg = SiweMessage {
        scheme: Some(Scheme::HTTPS),
        domain: Authority::from_static("test.com"),
        address: Address::from_str(TEST_WALLET).unwrap(),
        statement: Some("statement".into()),
        ..SiweMessage::default()
    };
    let h1 = msg.to_cache_hash("https://test.com").unwrap();
    let h2 = msg.to_cache_hash("https://test.com").unwrap();
    assert_eq!(h1, h2);
    assert_eq!(h1.to_hex_string().len(), 66); // "0x" + 64 hex chars
}

#[test]
fn default_produces_valid_message() {
    let msg = SiweMessage::default();
    assert_eq!(msg.version, Version::V1);
    assert_eq!(msg.chain_id, DEFAULT_CHAIN_ID);
    assert!(msg.nonce.len() >= MIN_NONCE_LEN);
    assert!(msg.expiration_time.is_some());
    assert!(msg.not_before.is_some());

    let serialized = msg.to_string();
    let parsed = SiweMessage::from_str(&serialized).unwrap();
    assert_eq!(parsed.chain_id, DEFAULT_CHAIN_ID);
}

#[test]
fn version_display_and_parse() {
    assert_eq!(Version::V1.to_string(), "1");
    assert_eq!(Version::from_str("1").unwrap(), Version::V1);
    assert!(Version::from_str("2").is_err());
}

#[test]
fn world_app_auth_message_creation() {
    let before = Utc::now();
    let account = test_smart_account();
    let msg = SiweMessage::from_world_app_auth_request(
        WorldAppAuthFlow::SignUp,
        "https://app-backend.toolsforhumanity.com",
        &account,
    )
    .unwrap();
    let after = Utc::now();

    assert_eq!(msg.chain_id, DEFAULT_CHAIN_ID);
    assert_eq!(msg.version, Version::V1);
    assert_eq!(msg.domain, "app-backend.toolsforhumanity.com");
    assert_eq!(msg.address, account.eoa_address()); // important: ensure world app auth uses EOA
    assert!(msg.statement.is_none());

    let uri_str = msg.uri.to_string();
    assert!(
        uri_str.contains("/public/v1/auth/sign-up"),
        "got: {uri_str}"
    );

    assert_eq!(msg.nonce.len(), 16);
    assert!(msg.nonce.chars().all(|c| c.is_ascii_alphanumeric()));

    assert!(msg.issued_at >= before && msg.issued_at <= after);
    let nbf = msg.not_before.expect("not_before should be set");
    assert_eq!(nbf, msg.issued_at);

    let exp = msg.expiration_time.expect("expiration_time should be set");
    let delta = exp - msg.issued_at;
    assert_eq!(delta, Duration::minutes(5));

    let serialized = msg.to_string();
    let parsed = SiweMessage::from_str(&serialized).unwrap();
    assert_eq!(parsed.chain_id, msg.chain_id);
    assert_eq!(parsed.address, msg.address);

    // important: app backend enforces the scheme
    assert!(serialized.starts_with("https://app-backend.toolsforhumanity.com"));
}

#[test]
fn world_app_auth_flow_uris() {
    let base = "https://app-backend.toolsforhumanity.com";
    assert!(WorldAppAuthFlow::Refresh
        .as_siwe_uri(base)
        .ends_with("/public/v1/auth/refresh"));
    assert!(WorldAppAuthFlow::Restore
        .as_siwe_uri(base)
        .ends_with("/public/v1/auth/restore"));
    assert!(WorldAppAuthFlow::SignUp
        .as_siwe_uri(base)
        .ends_with("/public/v1/auth/sign-up"));
}

#[test]
fn address_placeholder_replaced_in_address_line() {
    let account = test_smart_account();
    let datetime = now_rfc3339();
    let raw_msg = format!(
        "example.com{PREAMBLE}\n\
         {{address}}\n\n\
         statement mentioning {{address}} literally\n\n\
         URI: https://example.com\n\
         Version: 1\n\
         Chain ID: 480\n\
         Nonce: 12345678\n\
         Issued At: {datetime}"
    );
    let msg = SiweMessage::from_str_with_account(
        &raw_msg,
        &account,
        "https://example.com",
        "https://example.com",
    )
    .unwrap();

    // Address line is the smart account's wallet address
    assert_eq!(msg.address, account.wallet_address);

    // Second occurrence in the statement is NOT replaced
    assert_eq!(
        msg.statement.as_deref(),
        Some("statement mentioning {address} literally")
    );
}

#[test]
fn address_placeholder_only_first_occurrence() {
    let account = test_smart_account();
    let datetime = now_rfc3339();
    // Two {address} in the raw string: one in the address line, one in request_id
    let raw_msg = format!(
        "example.com{PREAMBLE}\n\
         {{address}}\n\n\n\
         URI: https://example.com\n\
         Version: 1\n\
         Chain ID: 480\n\
         Nonce: 12345678\n\
         Issued At: {datetime}\n\
         Request ID: {{address}}"
    );
    let msg = SiweMessage::from_str_with_account(
        &raw_msg,
        &account,
        "https://example.com",
        "https://example.com",
    )
    .unwrap();
    assert_eq!(msg.address, account.wallet_address);
    // request_id should still have the literal {address}
    assert_eq!(msg.request_id.as_deref(), Some("{address}"));
}

#[test]
fn no_placeholder_still_parses() {
    let account = test_smart_account();
    let datetime = now_rfc3339();
    let raw_msg = format!(
        "example.com{PREAMBLE}\n\
         0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045\n\n\n\
         URI: https://example.com\n\
         Version: 1\n\
         Chain ID: 480\n\
         Nonce: 12345678\n\
         Issued At: {datetime}"
    );
    let msg = SiweMessage::from_str_with_account(
        &raw_msg,
        &account,
        "https://example.com",
        "https://example.com",
    )
    .unwrap();
    // Address is overwritten to the smart account's wallet address regardless
    assert_eq!(msg.address, account.wallet_address);
}

#[test]
fn parse_strips_angle_brackets() {
    let datetime = now_rfc3339();
    let raw = format!(
        "<https://example.com>{PREAMBLE}\n\
         0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045\n\n\n\
         URI: https://example.com\n\
         Version: 1\n\
         Chain ID: 480\n\
         Nonce: 12345678\n\
         Issued At: {datetime}"
    );
    let msg = SiweMessage::from_str(&raw).unwrap();
    assert_eq!(msg.domain, "example.com");
}

#[test]
fn parse_trims_whitespace() {
    let datetime = now_rfc3339();
    let raw = format!(
        "\n  example.com{PREAMBLE}\n\
         0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045\n\n\n\
         URI: https://example.com\n\
         Version: 1\n\
         Chain ID: 480\n\
         Nonce: 12345678\n\
         Issued At: {datetime}\n  "
    );
    let msg = SiweMessage::from_str(&raw).unwrap();
    assert_eq!(msg.domain, "example.com");
}

#[test]
fn parse_rejects_oversized_message() {
    let huge = "x".repeat(MAX_MESSAGE_LEN + 1);
    let err = SiweMessage::from_str(&huge).unwrap_err();
    assert!(
        matches!(err, ParseError::Field(ref msg) if msg.contains("too long")),
        "got: {err}"
    );
}

#[test]
fn parse_accepts_message_at_max_length() {
    // Build a valid message, then pad the nonce to bring total length
    // right up to MAX_MESSAGE_LEN
    let datetime = now_rfc3339();
    let prefix = format!(
        "example.com{PREAMBLE}\n\
         0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045\n\n\n\
         URI: https://example.com\n\
         Version: 1\n\
         Chain ID: 480\n\
         Nonce: "
    );
    let suffix = format!("\nIssued At: {datetime}");
    let nonce_len = MAX_MESSAGE_LEN - prefix.len() - suffix.len();
    let nonce = "a".repeat(nonce_len);
    let raw = format!("{prefix}{nonce}{suffix}");
    assert_eq!(raw.len(), MAX_MESSAGE_LEN);
    let msg = SiweMessage::from_str(&raw).unwrap();
    assert_eq!(msg.nonce.len(), nonce_len);
}

/// Recomputes the Safe `getSiweMessageHashForSafe` digest to verify the signature
/// produced by `SiweMessage::sign`.
#[test]
fn sign_produces_verifiable_signature() {
    let signer = PrivateKeySigner::from_str(TEST_KEY).unwrap();
    let eoa_address = signer.address();
    let account = SafeSmartAccount::new(TEST_KEY.into(), TEST_WALLET).unwrap();

    let msg = SiweMessage {
        scheme: Some(Scheme::HTTPS),
        domain: Authority::from_static("example.com"),
        address: account.wallet_address,
        statement: Some("hello".into()),
        uri: "https://example.com".parse().unwrap(),
        version: Version::V1,
        chain_id: DEFAULT_CHAIN_ID,
        nonce: "12345678".into(),
        issued_at: Utc::now(),
        expiration_time: None,
        not_before: None,
        request_id: None,
        resources: vec![],
    };

    let sig_hex = msg.sign(&account).unwrap();
    let sig = Signature::from_str(sig_hex.as_str()).unwrap();

    // Recompute the exact digest the Safe signer produces:
    // 1) EIP-191 hash of the message string
    let message_str = msg.to_string();
    let eip191_hash = eip191_hash_message(message_str);

    // 2) Safe message hash: keccak256(SAFE_MSG_TYPEHASH ++ keccak256(eip191_hash))
    let safe_msg_typehash: FixedBytes<32> = fixed_bytes!(
        "0x60b3cbf8b4a223d68d641b3b6ddf9a298e7f33710cf3d3a9d1146b5a6150fbca"
    );

    let message_hash = keccak256(
        DynSolValue::Tuple(vec![
            DynSolValue::FixedBytes(safe_msg_typehash, 32),
            DynSolValue::FixedBytes(keccak256(eip191_hash), 32),
        ])
        .abi_encode(),
    );

    // 3) Domain separator: keccak256(DOMAIN_SEPARATOR_TYPEHASH ++ chain_id ++ wallet_address)
    let domain_separator_typehash: FixedBytes<32> = fixed_bytes!(
        "0x47e79534a245952e8b16893a336b85a3d9ea9fa8c573f3d803afb92a79469218"
    );
    let domain_separator = keccak256(
        DynSolValue::Tuple(vec![
            DynSolValue::FixedBytes(domain_separator_typehash, 32),
            DynSolValue::Uint(U256::from(DEFAULT_CHAIN_ID), 256),
            DynSolValue::Address(account.wallet_address),
        ])
        .abi_encode(),
    );

    // 4) EIP-712 final digest: keccak256(0x19 0x01 ++ domain_separator ++ message_hash)
    let mut buf = [0u8; 66];
    buf[0] = 0x19;
    buf[1] = 0x01;
    buf[2..34].copy_from_slice(domain_separator.as_slice());
    buf[34..66].copy_from_slice(message_hash.as_slice());
    let digest = keccak256(buf);

    // Recover signer from the signature over the digest
    let recovered = sig.recover_address_from_prehash(&digest).unwrap();
    assert_eq!(recovered, eoa_address);
}

#[test]
fn sign_is_deterministic() {
    let account = test_smart_account();
    let msg = SiweMessage {
        scheme: Some(Scheme::HTTP),
        domain: Authority::from_static("example.com"),
        address: account.wallet_address,
        ..SiweMessage::default()
    };
    let sig1 = msg.sign(&account).unwrap();
    let sig2 = msg.sign(&account).unwrap();
    assert_eq!(sig1, sig2);
}

#[test]
fn parse_rejects_non_alphanumeric_nonce() {
    let datetime = now_rfc3339();
    let raw = format!(
        "example.com{PREAMBLE}\n\
         0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045\n\n\n\
         URI: https://example.com\n\
         Version: 1\n\
         Chain ID: 480\n\
         Nonce: abcdefg!\n\
         Issued At: {datetime}"
    );
    let err = SiweMessage::from_str(&raw).unwrap_err();
    assert!(
        matches!(err, ParseError::Field(ref msg) if msg.contains("alphanumeric")),
        "got: {err}"
    );
}

#[test]
fn parse_accepts_alphanumeric_nonce() {
    let datetime = now_rfc3339();
    let raw = format!(
        "example.com{PREAMBLE}\n\
         0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045\n\n\n\
         URI: https://example.com\n\
         Version: 1\n\
         Chain ID: 480\n\
         Nonce: aBcD1234\n\
         Issued At: {datetime}"
    );
    let msg = SiweMessage::from_str(&raw).unwrap();
    assert_eq!(msg.nonce, "aBcD1234");
}

#[test]
fn parse_rejects_trailing_garbage() {
    let datetime = now_rfc3339();
    let raw = format!(
        "example.com{PREAMBLE}\n\
         0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045\n\n\n\
         URI: https://example.com\n\
         Version: 1\n\
         Chain ID: 480\n\
         Nonce: 12345678\n\
         Issued At: {datetime}\n\
         some unexpected line"
    );
    let err = SiweMessage::from_str(&raw).unwrap_err();
    assert!(
        matches!(err, ParseError::Field(ref msg) if msg.contains("unexpected trailing")),
        "got: {err}"
    );
}

#[test]
fn parse_rejects_typo_tag_after_iat() {
    let datetime = now_rfc3339();
    let raw = format!(
        "example.com{PREAMBLE}\n\
         0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045\n\n\n\
         URI: https://example.com\n\
         Version: 1\n\
         Chain ID: 480\n\
         Nonce: 12345678\n\
         Issued At: {datetime}\n\
         Expiratoin Time: 2030-01-01T00:00:00Z"
    );
    let err = SiweMessage::from_str(&raw).unwrap_err();
    assert!(
        matches!(err, ParseError::Field(ref msg) if msg.contains("unexpected trailing")),
        "got: {err}"
    );
}

#[test]
fn world_app_auth_trailing_slash_base_url() {
    let account = test_smart_account();
    let msg = SiweMessage::from_world_app_auth_request(
        WorldAppAuthFlow::Refresh,
        "https://app-backend.example.com/",
        &account,
    )
    .unwrap();
    assert_eq!(msg.domain, "app-backend.example.com");
    assert_eq!(msg.scheme.clone().unwrap().to_string(), "https");

    assert!(msg
        .to_string()
        .starts_with("https://app-backend.example.com wants"));
}

#[test]
fn parse_domain_trailing_slash_stripped() {
    let datetime = now_rfc3339();
    let raw = format!(
        "https://example.com/{PREAMBLE}\n\
         0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045\n\n\n\
         URI: https://example.com\n\
         Version: 1\n\
         Chain ID: 480\n\
         Nonce: 12345678\n\
         Issued At: {datetime}"
    );
    let msg = SiweMessage::from_str(&raw).unwrap();
    assert_eq!(msg.domain, "example.com");
    assert_eq!(msg.scheme.unwrap().to_string(), "https");
}

fn make_siwe_raw(domain: &str, uri: &str, datetime: &str) -> String {
    format!(
        "{domain}{PREAMBLE}\n\
         {{address}}\n\n\n\
         URI: {uri}\n\
         Version: 1\n\
         Chain ID: 480\n\
         Nonce: 12345678\n\
         Issued At: {datetime}"
    )
}

#[test]
fn authorized_host_matches_domain_and_uri() {
    let account = test_smart_account();
    let raw_msg = make_siwe_raw(
        "app.example.com",
        "https://app.example.com/callback",
        &now_rfc3339(),
    );
    let msg = SiweMessage::from_str_with_account(
        &raw_msg,
        &account,
        "https://app.example.com/registered",
        "https://app.example.com/current",
    )
    .unwrap();
    assert_eq!(msg.domain, "app.example.com");
}

#[test]
fn rejects_mismatched_authorized_and_querying_hosts() {
    let account = test_smart_account();
    let raw_msg =
        make_siwe_raw("app.example.com", "https://app.example.com", &now_rfc3339());
    let err = SiweMessage::from_str_with_account(
        &raw_msg,
        &account,
        "https://app.example.com",
        "https://evil.com",
    )
    .unwrap_err();
    assert!(matches!(err, SiweError::UnauthorizedHost), "got: {err}");
}

#[test]
fn rejects_message_domain_not_matching_authorized_host() {
    let account = test_smart_account();
    let raw_msg = make_siwe_raw("evil.com", "https://evil.com", &now_rfc3339());
    let err = SiweMessage::from_str_with_account(
        &raw_msg,
        &account,
        "https://app.example.com",
        "https://app.example.com",
    )
    .unwrap_err();
    assert!(matches!(err, SiweError::UnauthorizedHost), "got: {err}");
}

#[test]
fn rejects_message_uri_not_matching_authorized_host() {
    let account = test_smart_account();
    let raw_msg =
        make_siwe_raw("app.example.com", "https://evil.com/steal", &now_rfc3339());
    let err = SiweMessage::from_str_with_account(
        &raw_msg,
        &account,
        "https://app.example.com",
        "https://app.example.com",
    )
    .unwrap_err();
    assert!(matches!(err, SiweError::UnauthorizedHost), "got: {err}");
}

#[test]
fn domain_with_port_matches_authorized_authority() {
    let account = test_smart_account();
    let raw_msg = make_siwe_raw(
        "app.example.com:8080",
        "https://app.example.com:8080/cb",
        &now_rfc3339(),
    );
    let msg = SiweMessage::from_str_with_account(
        &raw_msg,
        &account,
        "https://app.example.com:8080",
        "https://app.example.com:8080",
    )
    .unwrap();
    assert_eq!(msg.domain, "app.example.com:8080");
}

#[test]
fn rejects_different_port_on_same_host() {
    let account = test_smart_account();
    let raw_msg = make_siwe_raw(
        "app.example.com:9090",
        "https://app.example.com:9090",
        &now_rfc3339(),
    );
    let err = SiweMessage::from_str_with_account(
        &raw_msg,
        &account,
        "https://app.example.com:8080",
        "https://app.example.com:8080",
    )
    .unwrap_err();
    assert!(matches!(err, SiweError::UnauthorizedHost), "got: {err}");
}

#[test]
fn rejects_querying_url_with_different_port() {
    let account = test_smart_account();
    let raw_msg = make_siwe_raw(
        "app.example.com:8080",
        "https://app.example.com:8080",
        &now_rfc3339(),
    );
    let err = SiweMessage::from_str_with_account(
        &raw_msg,
        &account,
        "https://app.example.com:8080",
        "https://app.example.com:9090",
    )
    .unwrap_err();
    assert!(matches!(err, SiweError::UnauthorizedHost), "got: {err}");
}

/// Verifies that the World App backend auth flow produces a valid EIP-191
/// signature recoverable to the EOA address (no Safe wrapping).
#[test]
fn world_app_auth_eoa_signature_is_verifiable() {
    let signer = PrivateKeySigner::from_str(TEST_KEY).unwrap();
    let eoa_address = signer.address();
    let account = test_smart_account();
    let eoa_signer = crate::smart_account::EoaSigner::new(TEST_KEY.into()).unwrap();

    let msg = SiweMessage::from_world_app_auth_request(
        WorldAppAuthFlow::SignUp,
        "https://app-backend.toolsforhumanity.com",
        &account,
    )
    .unwrap();

    assert_eq!(msg.address, eoa_address);

    let sig_hex = msg.sign(&eoa_signer).unwrap();
    let sig = Signature::from_str(sig_hex.as_str()).unwrap();

    // EoaSigner does plain EIP-191: recover from personal_sign hash
    let message_str = msg.to_string();
    let digest = eip191_hash_message(message_str);
    let recovered = sig.recover_address_from_prehash(&digest).unwrap();
    assert_eq!(recovered, eoa_address);
}
