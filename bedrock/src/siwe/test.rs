use super::*;
use chrono::{DateTime, Duration, Utc};
use ethers::types::{Address, Signature};
use pretty_assertions::assert_eq;
use sha2::{Digest, Sha256};
use siwe::{Message, VerificationOpts};
use std::time::{SystemTime, UNIX_EPOCH};

fn create_siwe_service() -> Arc<Siwe> {
    Siwe::new("https://app-backend.toolsforhumanity.com".to_string())
}

fn get_current_time() -> String {
    let now = SystemTime::now();
    let datetime: DateTime<Utc> = now.into();
    datetime.to_rfc3339()
}

#[test]
fn test_siwe_validation() {
    let siwe = create_siwe_service();
    let datetime = get_current_time();
    let raw_message = format!(
        "https://test.com wants you to sign in with your Ethereum account:\n\
        {{address}}\n\n\
        statement\n\n\
        URI: https://test.com\n\
        Version: 1\n\
        Chain ID: 480\n\
        Nonce: 12345678\n\
        Issued At: {datetime}\n\
        Expiration Time: 2024-05-03T00:00:00Z\n\
        Not Before: 2024-05-03T00:00:00Z\n\
        Request ID: 0"
    );
    let wallet_address = "0x19c96ab".to_string();
    let current_url = "https://test.com".to_string();
    let integration_url = "https://test.com".to_string();
    let response = siwe.validate_auth_message(
        &raw_message,
        &wallet_address,
        &current_url,
        &integration_url,
    );
    assert_eq!(
        response.unwrap(),
        SiweValidationResponse {
            result: ValidationSuccess {
                message: raw_message
            },
            statement: "statement".to_string(),
            domain: "https://test.com".to_string(),
            hashed_message:
                "4a323ef883fb4a4f021fabeb520d23d52070061a9db0d8a10543a6b8e058ac21"
                    .to_string(),
        }
    );
}

#[test]
fn test_siwe_validation_trim() {
    let siwe = create_siwe_service();
    let datetime = get_current_time();
    let raw_message = format!(
        "\nhttps://test.com wants you to sign in with your Ethereum account:\n\
        {{address}}\n\n\
        statement\n\n\
        URI: https://test.com\n\
        Version: 1\n\
        Chain ID: 480\n\
        Nonce: 12345678\n\
        Issued At: {datetime}\n\
        Expiration Time: 2024-05-03T00:00:00Z\n\
        Not Before: 2024-05-03T00:00:00Z\n\
        Request ID: 0\n"
    );
    let wallet_address = "0x19c96ab".to_string();
    let current_url = "https://test.com".to_string();
    let integration_url = "https://test.com".to_string();
    let response = siwe.validate_auth_message(
        &raw_message,
        &wallet_address,
        &current_url,
        &integration_url,
    );
    assert_eq!(
        response.unwrap(),
        SiweValidationResponse {
            result: ValidationSuccess {
                message: raw_message.trim().to_string()
            },
            statement: "statement".to_string(),
            domain: "https://test.com".to_string(),
            hashed_message:
                "4a323ef883fb4a4f021fabeb520d23d52070061a9db0d8a10543a6b8e058ac21"
                    .to_string(),
        }
    );
}

#[test]
fn test_siwe_validation_missing_optional() {
    let siwe = create_siwe_service();
    let datetime = get_current_time();
    let raw_message = format!(
        "https://test.com wants you to sign in with your Ethereum account:\n\
        {{address}}\n\n\n\
        URI: https://test.com\n\
        Version: 1\n\
        Chain ID: 480\n\
        Nonce: 12345678\n\
        Issued At: {datetime}"
    );
    let wallet_address = "0x19c96ab".to_string();
    let current_url = "https://test.com".to_string();
    let integration_url = "https://test.com".to_string();
    let response = siwe.validate_auth_message(
        &raw_message,
        &wallet_address,
        &current_url,
        &integration_url,
    );
    assert_eq!(
        response.unwrap(),
        SiweValidationResponse {
            result: ValidationSuccess {
                message: raw_message
            },
            statement: String::new(),
            domain: "https://test.com".to_string(),
            hashed_message:
                "7ee9eaa18d0ad9b3b291749e84097f8da904a115257fc65c07bfc2d5e788e357"
                    .to_string(),
        }
    );
}

#[test]
fn test_siwe_sanitization() {
    let siwe = create_siwe_service();
    let datetime = get_current_time();
    let raw_message = format!(
        "<https://test.com> wants you to sign in with your Ethereum account:\n\
        {{address}}\n\n\
        statement\n\n\
        URI: https://test.com\n\
        Version: 1\n\
        Chain ID: 480\n\
        Nonce: 12345678\n\
        Issued At: {datetime}\n\
        Expiration Time: 2024-05-03T00:00:00Z\n\
        Not Before: 2024-05-03T00:00:00Z\n\
        Request ID: 0"
    );
    let wallet_address = "0x19c96ab".to_string();
    let current_url = "https://test.com".to_string();
    let integration_url = "https://test.com".to_string();
    let response = siwe.validate_auth_message(
        &raw_message,
        &wallet_address,
        &current_url,
        &integration_url,
    );
    assert_eq!(
        response.unwrap(),
        SiweValidationResponse {
            result: ValidationSuccess {
                message: raw_message.replace("<https://test.com>", "https://test.com")
            },
            statement: "statement".to_string(),
            domain: "https://test.com".to_string(),
            hashed_message:
                "4a323ef883fb4a4f021fabeb520d23d52070061a9db0d8a10543a6b8e058ac21"
                    .to_string(),
        }
    );
}

#[test]
fn test_siwe_validation_with_url_path() {
    let siwe = create_siwe_service();
    let datetime = get_current_time();
    let raw_message = format!(
        "https://test.com wants you to sign in with your Ethereum account:\n\
        {{address}}\n\n\
        statement\n\n\
        URI: https://test.com/test/hello?query=1231\n\
        Version: 1\n\
        Chain ID: 480\n\
        Nonce: 12345678\n\
        Issued At: {datetime}\n\
        Expiration Time: 2024-05-03T00:00:00Z\n\
        Not Before: 2024-05-03T00:00:00Z\n\
        Request ID: 0"
    );
    let wallet_address = "0x19c96ab".to_string();
    let current_url = "https://test.com/random/url?with-params".to_string();
    let integration_url = "https://test.com".to_string();
    let response = siwe.validate_auth_message(
        &raw_message,
        &wallet_address,
        &current_url,
        &integration_url,
    );
    assert_eq!(
        response.unwrap(),
        SiweValidationResponse {
            result: ValidationSuccess {
                message: raw_message
            },
            statement: "statement".to_string(),
            domain: "https://test.com".to_string(),
            hashed_message:
                "4a323ef883fb4a4f021fabeb520d23d52070061a9db0d8a10543a6b8e058ac21"
                    .to_string(),
        }
    );
}

#[test]
fn test_siwe_message_too_long() {
    let siwe = create_siwe_service();
    let datetime = get_current_time();
    let raw_message = format!(
        "<https://test.com> wants you to sign in with your Ethereum account:<https://test.com> wants you to sign in with your Ethereum account:<https://test.com> wants you to sign in with your Ethereum account:<https://test.com> wants you to sign in with your Ethereum account:<https://test.com> wants you to sign in with your Ethereum account:<https://test.com> wants you to sign in with your Ethereum account:<https://test.com> wants you to sign in with your Ethereum account:<https://test.com> wants you to sign in with your Ethereum account:<https://test.com> wants you to sign in with your Ethereum account:<https://test.com> wants you to sign in with your Ethereum account:<https://test.com> wants you to sign in with your Ethereum account:<https://test.com> wants you to sign in with your Ethereum account:<https://test.com> wants you to sign in with your Ethereum account:<https://test.com> wants you to sign in with your Ethereum account:<https://test.com> wants you to sign in with your Ethereum account:<https://test.com> wants you to sign in with your Ethereum account:<https://test.com> wants you to sign in with your Ethereum account:<https://test.com> wants you to sign in with your Ethereum account:<https://test.com> wants you to sign in with your Ethereum account:<https://test.com> wants you to sign in with your Ethereum account:<https://test.com> wants you to sign in with your Ethereum account:<https://test.com> wants you to sign in with your Ethereum account:<https://test.com> wants you to sign in with your Ethereum account:<https://test.com> wants you to sign in with your Ethereum account:<https://test.com> wants you to sign in with your Ethereum account:<https://test.com> wants you to sign in with your Ethereum account:<https://test.com> wants you to sign in with your Ethereum account:
        <https://test.com> wants you to sign in with your Ethereum account:<https://test.com> wants you to sign in with your Ethereum account:<https://test.com> wants you to sign in with your Ethereum account:<https://test.com> wants you to sign in with your Ethereum account:<https://test.com> wants you to sign in with your Ethereum account:<https://test.com> wants you to sign in with your Ethereum account:<https://test.com> wants you to sign in with your Ethereum account:<https://test.com> wants you to sign in with your Ethereum account:<https://test.com> wants you to sign in with your Ethereum account:<https://test.com> wants you to sign in with your Ethereum account:<https://test.com> wants you to sign in with your Ethereum account:<https://test.com> wants you to sign in with your Ethereum account:<https://test.com> wants you to sign in with your Ethereum account:<https://test.com> wants you to sign in with your Ethereum account:<https://test.com> wants you to sign in with your Ethereum account:<https://test.com> wants you to sign in with your Ethereum account:<https://test.com> wants you to sign in with your Ethereum account:<https://test.com> wants you to sign in with your Ethereum account:<https://test.com> wants you to sign in with your Ethereum account:<https://test.com> wants you to sign in with your Ethereum account:<https://test.com> wants you to sign in with your Ethereum account:<https://test.com> wants you to sign in with your Ethereum account:<https://test.com> wants you to sign in with your Ethereum account:<https://test.com> wants you to sign in with your Ethereum account:<https://test.com> wants you to sign in with your Ethereum account:<https://test.com> wants you to sign in with your Ethereum account:<https://test.com> wants you to sign in with your Ethereum account:<https://test.com> wants you to sign in with your Ethereum account:<https://test.com> wants you to sign in with your Ethereum account:<https://test.com> wants you to sign in with your Ethereum account:<https://test.com> wants you to sign in with your Ethereum account:<https://test.com> wants you to sign in with your Ethereum account:<https://test.com> wants you to sign in with your Ethereum account:<https://test.com> wants you to sign in with your Ethereum account:<https://test.com> wants you to sign in with your Ethereum account:<https://test.com> wants you to sign in with your Ethereum account:<https://test.com> wants you to sign in with your Ethereum account:<https://test.com> wants you to sign in with your Ethereum account:<https://test.com> wants you to sign in with your Ethereum account:<https://test.com> wants you to sign in with your Ethereum account:
        <https://test.com> wants you to sign in with your Ethereum account:<https://test.com> wants you to sign in with your Ethereum account:<https://test.com> wants you to sign in with your Ethereum account:<https://test.com> wants you to sign in with your Ethereum account:\n\
        <https://test.com> wants you to sign in with your Ethereum account:<https://test.com> wants you to sign in with your Ethereum account:<https://test.com> wants you to sign in with your Ethereum account:<https://test.com> wants you to sign in with your Ethereum account:\n
        {{address}}\n\n\
        statement\n\n\
        URI: https://test.com\n\
        Version: 1\n\
        Chain ID: 480\n\
        Nonce: 12345678\n\
        Issued At: {datetime}\n\
        Expiration Time: 2024-05-03T00:00:00Z\n\
        Not Before: 2024-05-03T00:00:00Z\n\
        Request ID: 0"
    );
    let wallet_address = "0x19c96ab".to_string();
    let current_url = "https://test.com".to_string();
    let integration_url = "https://test.com".to_string();
    let response = siwe.validate_auth_message(
        &raw_message,
        &wallet_address,
        &current_url,
        &integration_url,
    );
    assert!(
        matches!(response, Err(SiweError::ValidationError(msg)) if msg == "Message is too long"),
        "Expected 'Message is too long' error"
    );
}

#[test]
fn test_siwe_with_invalid_domain_subdomains() {
    let siwe = create_siwe_service();
    let datetime = get_current_time();
    let raw_message = format!(
        "https://invalid.test.com wants you to sign in with your Ethereum account:\n\
        0x123\n\n\
        statement\n\n\
        URI: https://test.com\n\
        Version: 1\n\
        Chain ID: 480\n\
        Nonce: 12345678\n\
        Issued At: {datetime}\n\
        Expiration Time: 2024-05-03T00:00:00Z\n\
        Not Before: 2024-05-03T00:00:00Z\n\
        Request ID: 0"
    );
    let wallet_address = "0x123".to_string();
    let current_url = "https://test.com/test/one".to_string();
    let integration_url = "https://test.com".to_string();
    let response = siwe.validate_auth_message(
        &raw_message,
        &wallet_address,
        &current_url,
        &integration_url,
    );
    assert!(
        matches!(response, Err(SiweError::ValidationError(msg)) if msg == "URI domain does not match integration or current URL domain"),
        "Expected 'URI domain does not match integration or current URL domain' error"
    );
}

#[test]
fn test_siwe_with_invalid_subdomains() {
    let siwe = create_siwe_service();
    let datetime = get_current_time();
    let raw_message = format!(
        "https://test.com wants you to sign in with your Ethereum account:\n\
        0x123\n\n\
        statement\n\n\
        URI: https://test.com\n\
        Version: 1\n\
        Chain ID: 480\n\
        Nonce: 12345678\n\
        Issued At: {datetime}\n\
        Expiration Time: 2024-05-03T00:00:00Z\n\
        Not Before: 2024-05-03T00:00:00Z\n\
        Request ID: 0"
    );
    let wallet_address = "0x123".to_string();
    let current_url = "https://hello.test.com/test/one".to_string();
    let integration_url = "https://test.com".to_string();
    let response = siwe.validate_auth_message(
        &raw_message,
        &wallet_address,
        &current_url,
        &integration_url,
    );
    assert!(
        matches!(response, Err(SiweError::ValidationError(msg)) if msg == "URI does not match current URL"),
        "Expected 'URI does not match current URL' error"
    );
}

#[test]
fn test_siwe_with_invalid_scheme() {
    let siwe = create_siwe_service();
    let datetime = get_current_time();
    let raw_message = format!(
        "http://test.com wants you to sign in with your Ethereum account:\n\
        0x123\n\n\
        statement\n\n\
        URI: https://test.com\n\
        Version: 1\n\
        Chain ID: 480\n\
        Nonce: 12345678\n\
        Issued At: {datetime}\n\
        Expiration Time: 2024-05-03T00:00:00Z\n\
        Not Before: 2024-05-03T00:00:00Z\n\
        Request ID: 0"
    );
    let wallet_address = "0x123".to_string();
    let current_url = "https://test.com".to_string();
    let integration_url = "https://test.com".to_string();
    let response = siwe.validate_auth_message(
        &raw_message,
        &wallet_address,
        &current_url,
        &integration_url,
    );
    assert!(
        matches!(response, Err(SiweError::ValidationError(msg)) if msg == "Scheme must be HTTPS"),
        "Expected 'Scheme must be HTTPS' error"
    );
}

#[test]
fn test_siwe_with_invalid_domain() {
    let siwe = create_siwe_service();
    let datetime = get_current_time();
    let raw_message = format!(
        " wants you to sign in with your Ethereum account:\n\
        {{address}}\n\n\
        statement\n\n\
        URI: https://test.com\n\
        Version: 1\n\
        Chain ID: 480\n\
        Nonce: 12345678\n\
        Issued At: {datetime}\n\
        Expiration Time: 2024-05-03T00:00:00Z\n\
        Not Before: 2024-05-03T00:00:00Z\n\
        Request ID: 0"
    );
    let wallet_address = "0x19c96ab".to_string();
    let current_url = "https://test.com".to_string();
    let integration_url = "https://test.com".to_string();
    let response = siwe.validate_auth_message(
        &raw_message,
        &wallet_address,
        &current_url,
        &integration_url,
    );

    assert!(
        matches!(response, Err(SiweError::ValidationError(msg)) if msg == "Missing Preamble Line"),
        "Expected 'Missing Preamble Line' error"
    );
}

#[test]
fn test_siwe_with_mismatched_domain() {
    let siwe = create_siwe_service();
    let datetime = get_current_time();
    let raw_message = format!(
        "random.com wants you to sign in with your Ethereum account:\n\
        {{address}}\n\n\
        statement\n\n\
        URI: https://test.com\n\
        Version: 1\n\
        Chain ID: 480\n\
        Nonce: 12345678\n\
        Issued At: {datetime}\n\
        Expiration Time: 2024-05-03T00:00:00Z\n\
        Not Before: 2024-05-03T00:00:00Z\n\
        Request ID: 0"
    );
    let wallet_address = "0x19c96ab".to_string();
    let current_url = "https://test.com".to_string();
    let integration_url = "https://test.com".to_string();
    let response = siwe.validate_auth_message(
        &raw_message,
        &wallet_address,
        &current_url,
        &integration_url,
    );

    assert!(
        matches!(response, Err(SiweError::ValidationError(msg)) if msg == "URI domain does not match integration or current URL domain"),
        "Expected 'URI domain does not match integration or current URL domain' error"
    );
}

#[test]
fn test_siwe_with_mismatched_current_url() {
    let siwe = create_siwe_service();
    let datetime = get_current_time();
    let raw_message = format!(
        "https://test.com wants you to sign in with your Ethereum account:\n\
        {{address}}\n\n\
        statement\n\n\
        URI: https://test.com\n\
        Version: 1\n\
        Chain ID: 480\n\
        Nonce: 12345678\n\
        Issued At: {datetime}\n\
        Expiration Time: 2024-05-03T00:00:00Z\n\
        Not Before: 2024-05-03T00:00:00Z\n\
        Request ID: 0"
    );
    let wallet_address = "0x19c96ab".to_string();
    let current_url = "https://common.com".to_string();
    let integration_url = "https://test.com".to_string();
    let response = siwe.validate_auth_message(
        &raw_message,
        &wallet_address,
        &current_url,
        &integration_url,
    );
    assert!(
        matches!(response, Err(SiweError::ValidationError(msg)) if msg == "URI does not match current URL"),
        "Expected 'URI does not match current URL' error"
    );
}

#[test]
fn test_siwe_mismatched_uri() {
    let siwe = create_siwe_service();
    let datetime = get_current_time();
    let raw_message = format!(
        "https://test.com wants you to sign in with your Ethereum account:\n\
        {{address}}\n\n\
        statement\n\n\
        URI: https://test1.com\n\
        Version: 1\n\
        Chain ID: 480\n\
        Nonce: 12345678\n\
        Issued At: {datetime}\n\
        Expiration Time: 2024-05-03T00:00:00Z\n\
        Not Before: 2024-05-03T00:00:00Z\n\
        Request ID: 0"
    );
    let wallet_address = "0x19c96ab".to_string();
    let current_url = "https://test.com".to_string();
    let integration_url = "https://test.com".to_string();
    let response = siwe.validate_auth_message(
        &raw_message,
        &wallet_address,
        &current_url,
        &integration_url,
    );

    assert!(
        matches!(response, Err(SiweError::ValidationError(msg)) if msg == "URI does not match current URL"),
        "Expected 'URI does not match current URL' error"
    );
}

#[test]
fn test_siwe_with_invalid_statement() {
    let siwe = create_siwe_service();
    let datetime = get_current_time();
    let raw_message = format!(
        "https://test.com wants you to sign in with your Ethereum account:\n\
        {{address}}\n\
        statement\n\n\n\
        URI: https://test.com\n\
        Version: 1\n\
        Chain ID: 480\n\
        Nonce: 12345678\n\
        Issued At: {datetime}\n\
        Expiration Time: 2024-05-03T00:00:00Z\n\
        Not Before: 2024-05-03T00:00:00Z\n\
        Request ID: 0"
    );
    let wallet_address = "0x19c96ab".to_string();
    let current_url = "https://test.com".to_string();
    let integration_url = "https://test.com".to_string();
    let response = siwe.validate_auth_message(
        &raw_message,
        &wallet_address,
        &current_url,
        &integration_url,
    );

    // if statement is \n it will cause a line mismatch
    assert!(
        matches!(response, Err(SiweError::ValidationError(msg)) if msg == "Missing 'URI: '"),
        "Expected 'Missing 'URI: '' error"
    );
}

#[test]
fn test_siwe_with_invalid_version() {
    let siwe = create_siwe_service();
    let datetime = get_current_time();
    let raw_message = format!(
        "https://test.com wants you to sign in with your Ethereum account:\n\
        {{address}}\n\n\
        statement\n\n\
        URI: https://test.com\n\
        Version: 2\n\
        Chain ID: 480\n\
        Nonce: 12345678\n\
        Issued At: {datetime}\n\
        Expiration Time: 2024-05-03T00:00:00Z\n\
        Not Before: 2024-05-03T00:00:00Z\n\
        Request ID: 0"
    );
    let wallet_address = "0x19c96ab".to_string();
    let current_url = "https://test.com".to_string();
    let integration_url = "https://test.com".to_string();
    let response = siwe.validate_auth_message(
        &raw_message,
        &wallet_address,
        &current_url,
        &integration_url,
    );

    assert!(
        matches!(response, Err(SiweError::ValidationError(msg)) if msg == "Version must be 1"),
        "Expected 'Version must be 1' error"
    );
}

#[test]
fn test_siwe_with_invalid_chain_id() {
    let siwe = create_siwe_service();
    let datetime = get_current_time();
    let raw_message = format!(
        "https://test.com wants you to sign in with your Ethereum account:\n\
        {{address}}\n\n\
        statement\n\n\
        URI: https://test.com\n\
        Version: 1\n\
        Chain ID: 1\n\
        Nonce: 12345678\n\
        Issued At: {datetime}\n\
        Expiration Time: 2024-05-03T00:00:00Z\n\
        Not Before: 2024-05-03T00:00:00Z\n\
        Request ID: 0"
    );
    let wallet_address = "0x19c96ab".to_string();
    let current_url = "https://test.com".to_string();
    let integration_url = "https://test.com".to_string();
    let response = siwe.validate_auth_message(
        &raw_message,
        &wallet_address,
        &current_url,
        &integration_url,
    );

    assert!(
        matches!(response, Err(SiweError::ValidationError(msg)) if msg == "Chain ID must be 480 (World Chain)"),
        "Expected 'Chain ID must be 480 (World Chain)' error"
    );
}

#[test]
fn test_siwe_with_invalid_wallet_address() {
    let siwe = create_siwe_service();
    let datetime = get_current_time();
    let raw_message = format!(
        "https://test.com wants you to sign in with your Ethereum account:\n\
        0x123\n\n\
        statement\n\n\
        URI: https://test.com\n\
        Version: 1\n\
        Chain ID: 480\n\
        Nonce: 12345678\n\
        Issued At: {datetime}\n\
        Expiration Time: 2024-05-03T00:00:00Z\n\
        Not Before: 2024-05-03T00:00:00Z\n\
        Request ID: 0"
    );
    let wallet_address = "0x1213213213".to_string(); // Invalid address
    let current_url = "https://test.com".to_string();
    let integration_url = "https://test.com".to_string();
    let response = siwe.validate_auth_message(
        &raw_message,
        &wallet_address,
        &current_url,
        &integration_url,
    );
    assert!(
        matches!(response, Err(SiweError::ValidationError(msg)) if msg == "Invalid Address"),
        "Expected 'Invalid Address' error"
    );
}

#[test]
fn test_siwe_with_invalid_nonce() {
    let siwe = create_siwe_service();
    let datetime = get_current_time();
    let raw_message = format!(
        "https://test.com wants you to sign in with your Ethereum account:\n\
        {{address}}\n\n\
        statement\n\n\
        URI: https://test.com\n\
        Version: 1\n\
        Chain ID: 480\n\
        Nonce: 125678\n\
        Issued At: {datetime}\n\
        Expiration Time: 2024-05-03T00:00:00Z\n\
        Not Before: 2024-05-03T00:00:00Z\n\
        Request ID: 0"
    );
    let wallet_address = "0x19c96ab".to_string();
    let current_url = "https://test.com".to_string();
    let integration_url = "https://test.com".to_string();
    let response = siwe.validate_auth_message(
        &raw_message,
        &wallet_address,
        &current_url,
        &integration_url,
    );

    assert!(
        matches!(response, Err(SiweError::ValidationError(msg)) if msg == "Nonce must be longer than 8 characters"),
        "Expected 'Nonce must be longer than 8 characters' error"
    );
}

#[test]
fn test_siwe_with_past_issued_at_date() {
    let siwe = create_siwe_service();
    let datetime = "2000-01-01T00:00:00Z".to_string(); // Past date
    let raw_message = format!(
        "https://test.com wants you to sign in with your Ethereum account:\n\
        {{address}}\n\n\
        statement\n\n\
        URI: https://test.com\n\
        Version: 1\n\
        Chain ID: 480\n\
        Nonce: 12345678\n\
        Issued At: {datetime}\n\
        Expiration Time: 2024-05-03T00:00:00Z\n\
        Not Before: 2024-05-03T00:00:00Z\n\
        Request ID: 0"
    );
    let wallet_address = "0x19c96ab".to_string();
    let current_url = "https://test.com".to_string();
    let integration_url = "https://test.com".to_string();
    let response = siwe.validate_auth_message(
        &raw_message,
        &wallet_address,
        &current_url,
        &integration_url,
    );
    assert!(
        matches!(response, Err(SiweError::ValidationError(msg)) if msg == "IAT is more than 5 minutes old"),
        "Expected 'IAT is more than 5 minutes old' error"
    );
}

#[test]
fn test_siwe_with_invalid_expiration() {
    let siwe = create_siwe_service();
    let datetime = get_current_time();
    let raw_message = format!(
        "https://test.com wants you to sign in with your Ethereum account:\n\
        {{address}}\n\n\
        statement\n\n\
        URI: https://test.com\n\
        Version: 1\n\
        Chain ID: 480\n\
        Nonce: 12345678\n\
        Issued At: {datetime}\n\
        Expiration Time: 2030-05-03T00:00:00Z\n\
        Not Before: 2024-05-03T00:00:00Z\n\
        Request ID: 0"
    );
    let wallet_address = "0x19c96ab".to_string();
    let current_url = "https://test.com".to_string();
    let integration_url = "https://test.com".to_string();
    let response = siwe.validate_auth_message(
        &raw_message,
        &wallet_address,
        &current_url,
        &integration_url,
    );

    assert!(
        matches!(response, Err(SiweError::ValidationError(msg)) if msg == "Expiration time is more than 7 days in the future"),
        "Expected 'Expiration time is more than 7 days in the future' error"
    );
}

#[test]
fn test_siwe_with_invalid_nbf() {
    let siwe = create_siwe_service();
    let datetime = get_current_time();
    let raw_message = format!(
        "https://test.com wants you to sign in with your Ethereum account:\n\
        {{address}}\n\n\
        statement\n\n\
        URI: https://test.com\n\
        Version: 1\n\
        Chain ID: 480\n\
        Nonce: 12345678\n\
        Issued At: {datetime}\n\
        Expiration Time: 2024-05-03T00:00:00Z\n\
        Not Before: 2030-05-03T00:00:00Z\n\
        Request ID: 0"
    );
    let wallet_address = "0x19c96ab".to_string();
    let current_url = "https://test.com".to_string();
    let integration_url = "https://test.com".to_string();
    let response = siwe.validate_auth_message(
        &raw_message,
        &wallet_address,
        &current_url,
        &integration_url,
    );

    assert!(
        matches!(response, Err(SiweError::ValidationError(msg)) if msg == "Not before time is more than 7 days in the future"),
        "Expected 'Not before time is more than 7 days in the future' error"
    );
}

#[test]
fn test_siwe_no_resources() {
    let siwe = create_siwe_service();
    let datetime = get_current_time();
    let raw_message = format!(
        "https://test.com wants you to sign in with your Ethereum account:\n\
        {{address}}\n\n\
        statement\n\n\
        URI: https://test.com\n\
        Version: 1\n\
        Chain ID: 480\n\
        Nonce: 12345678\n\
        Issued At: {datetime}\n\
        Expiration Time: 2024-05-03T00:00:00Z\n\
        Not Before: 2024-05-03T00:00:00Z\n\
        Request ID: 0\n\
        Resources:
        "
    );
    let wallet_address = "0x19c96ab".to_string();
    let current_url = "https://test.com".to_string();
    let integration_url = "https://test.com".to_string();
    let response = siwe.validate_auth_message(
        &raw_message,
        &wallet_address,
        &current_url,
        &integration_url,
    );
    assert!(
        matches!(response, Err(SiweError::ValidationError(msg)) if msg == "No resources allowed"),
        "Expected 'No resources allowed' error"
    );
}

#[test]
fn test_siwe_no_extraneous_text() {
    let siwe = create_siwe_service();
    let datetime = get_current_time();
    let raw_message = format!(
        "https://test.com wants you to sign in with your Ethereum account:\n\
        {{address}}\n\n\
        statement\n\n\
        URI: https://test.com\n\
        Version: 1\n\
        Chain ID: 480\n\
        Nonce: 12345678\n\
        Issued At: {datetime}\n\
        Expiration Time: 2024-05-03T00:00:00Z\n\
        Not Before: 2024-05-03T00:00:00Z\n\
        Request ID: 0\n\
        random extra text\n
        "
    );
    let wallet_address = "0x19c96ab".to_string();
    let current_url = "https://test.com".to_string();
    let integration_url = "https://test.com".to_string();
    let response = siwe.validate_auth_message(
        &raw_message,
        &wallet_address,
        &current_url,
        &integration_url,
    );
    assert!(
        matches!(response, Err(SiweError::ValidationError(msg)) if msg == "Unexpected at end of message"),
        "Expected 'Unexpected at end of message' error"
    );
}

#[tokio::test]
async fn test_siwe_sign_message_v2() {
    // World Chain Safe instead of EOA
    let wallet_address = "0x619525ED4E862B62cFEDACCc4dA5a9864D6f4A97".to_string();
    let siwe = create_siwe_service();
    let message: ValidationSuccess = ValidationSuccess {
        message: generate_valid_payload(),
    };
    let seed = "0xdeadbeef".to_string();

    // Minimal inline Ethereum key derivation, mimicking OxideKey::ethereum_key()
    let mut hasher = Sha256::new();
    hasher.update(&seed);
    let key_bytes = hasher.finalize();
    let ethereum_key = hex::encode(key_bytes);
    let signature = siwe
        .sign_wallet_auth_message_v2(&message, ethereum_key, &wallet_address)
        .unwrap();

    let message: Message = signature.message.parse().unwrap();
    let rpc: ethers::providers::Provider<ethers::providers::Http> =
        ethers::providers::Provider::try_from(
            "https://worldchain-mainnet.g.alchemy.com/public",
        )
        .unwrap();
    let sig_bytes = hex::decode(
        signature
            .signature
            .strip_prefix("0x")
            .unwrap_or(&signature.signature),
    )
    .unwrap();
    let verification_opts = VerificationOpts {
        rpc_provider: Some(rpc),
        ..Default::default()
    };
    let result = message.verify(&sig_bytes, &verification_opts).await;
    assert!(result.is_ok());
}

#[test]
fn test_siwe_create_world_app_auth_message() {
    let siwe = create_siwe_service();
    let wallet_address = "0x11a1801863e1f0941a663f0338aea395be1ec8a4".to_string();
    let key = r#"{"key":"db547ff3ded25c60e791917584090eafd8efceba61d6e73946b89b7d6fc04725","version":"V1"}"#;

    let message = siwe
        .create_world_app_auth_message(
            WorldAppAuthFlow::SignUp,
            &wallet_address,
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        )
        .expect("Failed to create World App auth message");

    let response = siwe
        .validate_auth_message(
            &message,
            &wallet_address,
            "https://app-backend.toolsforhumanity.com/auth/sign-up",
            "https://app-backend.toolsforhumanity.com/",
        )
        .expect("Failed to validate World App auth message");
    assert_eq!(
        response,
        SiweValidationResponse {
            statement: String::new(),
            domain: "https://app-backend.toolsforhumanity.com".to_string(),
            result: ValidationSuccess {
                message: message.clone(),
            },
            hashed_message:
                "7cf0eb7cac02e5512e002d9b181827de22bad14044435d21e7368ce497f9cf82"
                    .to_string(),
        }
    );

    // Minimal replacement for OxideKey::decode + .ethereum_key()
    // The key is a JSON string: {"key":"<hex>","version":"V1"}
    // We'll parse it and extract the hex string for the key, which is the Ethereum key.
    let key_json: serde_json::Value = serde_json::from_str(key).unwrap();
    let ethereum_key = key_json
        .get("key")
        .and_then(|v| v.as_str())
        .expect("Missing key field")
        .to_string();

    let signed_response = siwe
        .sign_world_app_auth_message(response.result, ethereum_key)
        .unwrap();
    assert_eq!(signed_response.message, message);

    // verify signature was signed by the correct address, doesn't validate what was signed
    let sig_obj = Signature::from_str(&signed_response.signature)
        .expect("Invalid signature format");
    let address = Address::from_str(&wallet_address).unwrap();
    assert!(Signature::verify(&sig_obj, message, address).is_ok());

    // Compatibility with SIWE was checked using this script:
    // dbg!(signed_response);
    // ///
    // import * as siwe from 'siwe';
    //
    // const message = "https://app-backend.toolsforhumanity.com wants you to sign in with your Ethereum account:\n0x11A1801863e1F0941A663f0338aEa395Be1Ec8A4\n\n\nURI: https://app-backend.toolsforhumanity.com/auth/sign-up\nVersion: 1\nChain ID: 480\nNonce: 1469020534\nIssued At: 2025-01-15T23:23:25.608083Z\nExpiration Time: 2025-01-15T23:28:25.608083Z\nNot Before: 2025-01-15T23:23:25.608083Z";
    // const m = new siwe.SiweMessage(message);
    //
    // try {
    //     await m.verify({
    //         signature: "0xd7c37fb39306ae5813178a7cad3629fc25dc6f87348898658e2ddfe66fd19db16ab6743bd7dbfa0e33e0940983fb9db2eb9e54753e8ce34bae7be4ea6e459ce11b",
    //         domain: "app-backend.toolsforhumanity.com",
    //         scheme: "https",
    //     })
    // } catch (e) {
    //     console.error(e);
    // }
}

fn generate_valid_payload() -> String {
    let now = Utc::now();
    let expiration = now + Duration::days(7);
    format!(
        "test.com wants you to sign in with your Ethereum account:\n\
        {{address}}\n\n\
        statement\n\n\
        URI: https://test.com\n\
        Version: 1\n\
        Chain ID: 480\n\
        Nonce: 12345678\n\
        Issued At: {now}\n\
        Expiration Time: {expiration}\n\
        Not Before: {now}\n\
        Request ID: 0",
        now = now.format("%Y-%m-%dT%H:%M:%SZ"),
        expiration = expiration.format("%Y-%m-%dT%H:%M:%SZ")
    )
}
