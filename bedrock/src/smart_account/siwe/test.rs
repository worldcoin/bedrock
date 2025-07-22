use super::*;
use crate::smart_account::SafeSmartAccount;
use chrono::{DateTime, Duration as ChronoDuration, Utc};
use pretty_assertions::assert_eq;
use std::time::{SystemTime, UNIX_EPOCH};

// For compatibility tests
#[cfg(feature = "tooling_tests")]
use siwe::Message;

const TEST_PRIVATE_KEY: &str = "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
const TEST_WALLET_ADDRESS: &str = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266";

fn get_current_time() -> String {
    let now = SystemTime::now();
    let datetime: DateTime<Utc> = now.into();
    datetime.to_rfc3339()
}

fn create_test_account() -> SafeSmartAccount {
    SafeSmartAccount::new(TEST_PRIVATE_KEY.to_string(), TEST_WALLET_ADDRESS).unwrap()
}

#[test]
fn test_siwe_validation() {
    let safe = create_test_account();
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
    let response = safe.validate_siwe_message(
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
    let safe = create_test_account();
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
    let response = safe.validate_siwe_message(
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
    let safe = create_test_account();
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
    let response = safe.validate_siwe_message(
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
    let safe = create_test_account();
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
    let response = safe.validate_siwe_message(
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
    let safe = create_test_account();
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
    let response = safe.validate_siwe_message(
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
    let safe = create_test_account();
    let datetime = get_current_time();
    let long_preamble = "<https://test.com> wants you to sign in with your Ethereum account:".repeat(100);
    let raw_message = format!(
        "{long_preamble}
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
    let response = safe.validate_siwe_message(
        &raw_message,
        &wallet_address,
        &current_url,
        &integration_url,
    );
    assert!(
        matches!(response, Err(SafeSmartAccountError::InvalidInput { attribute, message }) 
            if attribute == "message" && message == "Message is too long"),
        "Expected 'Message is too long' error"
    );
}

#[test]
fn test_siwe_with_invalid_domain_subdomains() {
    let safe = create_test_account();
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
    let response = safe.validate_siwe_message(
        &raw_message,
        &wallet_address,
        &current_url,
        &integration_url,
    );
    assert!(
        matches!(response, Err(SafeSmartAccountError::InvalidInput { attribute, message }) 
            if attribute == "uri" && message == "URI domain does not match integration or current URL domain"),
        "Expected 'URI domain does not match integration or current URL domain' error"
    );
}

#[test]
fn test_siwe_with_invalid_subdomains() {
    let safe = create_test_account();
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
    let response = safe.validate_siwe_message(
        &raw_message,
        &wallet_address,
        &current_url,
        &integration_url,
    );
    assert!(
        matches!(response, Err(SafeSmartAccountError::InvalidInput { attribute, message }) 
            if attribute == "uri" && message == "URI does not match current URL"),
        "Expected 'URI does not match current URL' error"
    );
}

#[test]
fn test_siwe_with_invalid_scheme() {
    let safe = create_test_account();
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
    let response = safe.validate_siwe_message(
        &raw_message,
        &wallet_address,
        &current_url,
        &integration_url,
    );
    assert!(
        matches!(response, Err(SafeSmartAccountError::InvalidInput { attribute, message }) 
            if attribute == "scheme" && message == "Scheme must be HTTPS"),
        "Expected 'Scheme must be HTTPS' error"
    );
}

#[test]
fn test_siwe_with_invalid_domain() {
    let safe = create_test_account();
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
    let response = safe.validate_siwe_message(
        &raw_message,
        &wallet_address,
        &current_url,
        &integration_url,
    );

    assert!(
        matches!(response, Err(SafeSmartAccountError::InvalidInput { attribute, message }) 
            if attribute == "preamble" && message == "Missing Preamble Line"),
        "Expected 'Missing Preamble Line' error"
    );
}

#[test]
fn test_siwe_with_mismatched_domain() {
    let safe = create_test_account();
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
    let response = safe.validate_siwe_message(
        &raw_message,
        &wallet_address,
        &current_url,
        &integration_url,
    );

    assert!(
        matches!(response, Err(SafeSmartAccountError::InvalidInput { attribute, message }) 
            if attribute == "uri" && message == "URI domain does not match integration or current URL domain"),
        "Expected 'URI domain does not match integration or current URL domain' error"
    );
}

#[test]
fn test_siwe_with_mismatched_current_url() {
    let safe = create_test_account();
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
    let response = safe.validate_siwe_message(
        &raw_message,
        &wallet_address,
        &current_url,
        &integration_url,
    );
    assert!(
        matches!(response, Err(SafeSmartAccountError::InvalidInput { attribute, message }) 
            if attribute == "uri" && message == "URI does not match current URL"),
        "Expected 'URI does not match current URL' error"
    );
}

#[test]
fn test_siwe_mismatched_uri() {
    let safe = create_test_account();
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
    let response = safe.validate_siwe_message(
        &raw_message,
        &wallet_address,
        &current_url,
        &integration_url,
    );

    assert!(
        matches!(response, Err(SafeSmartAccountError::InvalidInput { attribute, message }) 
            if attribute == "uri" && message == "URI does not match current URL"),
        "Expected 'URI does not match current URL' error"
    );
}

#[test]
fn test_siwe_with_invalid_statement() {
    let safe = create_test_account();
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
    let response = safe.validate_siwe_message(
        &raw_message,
        &wallet_address,
        &current_url,
        &integration_url,
    );

    // if statement is \n it will cause a line mismatch
    assert!(
        matches!(response, Err(SafeSmartAccountError::InvalidInput { attribute, message }) 
            if attribute == "siwe_message" && message == "Missing 'URI: '"),
        "Expected 'Missing 'URI: '' error"
    );
}

#[test]
fn test_siwe_with_invalid_version() {
    let safe = create_test_account();
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
    let response = safe.validate_siwe_message(
        &raw_message,
        &wallet_address,
        &current_url,
        &integration_url,
    );

    assert!(
        matches!(response, Err(SafeSmartAccountError::InvalidInput { attribute, message }) 
            if attribute == "version" && message == "Version must be 1"),
        "Expected 'Version must be 1' error"
    );
}

#[test]
fn test_siwe_with_invalid_chain_id() {
    let safe = create_test_account();
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
    let response = safe.validate_siwe_message(
        &raw_message,
        &wallet_address,
        &current_url,
        &integration_url,
    );

    assert!(
        matches!(response, Err(SafeSmartAccountError::InvalidInput { attribute, message }) 
            if attribute == "chain_id" && message == "Chain ID must be 480 (World Chain)"),
        "Expected 'Chain ID must be 480 (World Chain)' error"
    );
}

#[test]
fn test_siwe_with_invalid_wallet_address() {
    let safe = create_test_account();
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
    let response = safe.validate_siwe_message(
        &raw_message,
        &wallet_address,
        &current_url,
        &integration_url,
    );
    assert!(
        matches!(response, Err(SafeSmartAccountError::InvalidInput { attribute, message }) 
            if attribute == "address" && message == "Invalid Address"),
        "Expected 'Invalid Address' error"
    );
}

#[test]
fn test_siwe_with_invalid_nonce() {
    let safe = create_test_account();
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
    let response = safe.validate_siwe_message(
        &raw_message,
        &wallet_address,
        &current_url,
        &integration_url,
    );

    assert!(
        matches!(response, Err(SafeSmartAccountError::InvalidInput { attribute, message }) 
            if attribute == "nonce" && message == "Nonce must be longer than 8 characters"),
        "Expected 'Nonce must be longer than 8 characters' error"
    );
}

#[test]
fn test_siwe_with_past_issued_at_date() {
    let safe = create_test_account();
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
    let response = safe.validate_siwe_message(
        &raw_message,
        &wallet_address,
        &current_url,
        &integration_url,
    );
    assert!(
        matches!(response, Err(SafeSmartAccountError::InvalidInput { attribute, message }) 
            if attribute == "issued_at" && message == "IAT is more than 5 minutes old"),
        "Expected 'IAT is more than 5 minutes old' error"
    );
}

#[test]
fn test_siwe_with_invalid_expiration() {
    let safe = create_test_account();
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
    let response = safe.validate_siwe_message(
        &raw_message,
        &wallet_address,
        &current_url,
        &integration_url,
    );

    assert!(
        matches!(response, Err(SafeSmartAccountError::InvalidInput { attribute, message }) 
            if attribute == "expiration" && message == "Expiration time is more than 7 days in the future"),
        "Expected 'Expiration time is more than 7 days in the future' error"
    );
}

#[test]
fn test_siwe_with_invalid_nbf() {
    let safe = create_test_account();
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
    let response = safe.validate_siwe_message(
        &raw_message,
        &wallet_address,
        &current_url,
        &integration_url,
    );

    assert!(
        matches!(response, Err(SafeSmartAccountError::InvalidInput { attribute, message }) 
            if attribute == "not_before" && message == "Not before time is more than 7 days in the future"),
        "Expected 'Not before time is more than 7 days in the future' error"
    );
}

#[test]
fn test_siwe_no_resources() {
    let safe = create_test_account();
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
    let response = safe.validate_siwe_message(
        &raw_message,
        &wallet_address,
        &current_url,
        &integration_url,
    );
    assert!(
        matches!(response, Err(SafeSmartAccountError::InvalidInput { attribute, message }) 
            if attribute == "resources" && message == "No resources allowed"),
        "Expected 'No resources allowed' error"
    );
}

#[test]
fn test_siwe_no_extraneous_text() {
    let safe = create_test_account();
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
    let response = safe.validate_siwe_message(
        &raw_message,
        &wallet_address,
        &current_url,
        &integration_url,
    );

    assert!(
        matches!(response, Err(SafeSmartAccountError::InvalidInput { attribute, message }) 
            if attribute == "message" && message == "Unexpected at end of message"),
        "Expected 'Unexpected at end of message' error"
    );
}

#[cfg(feature = "tooling_tests")]
#[tokio::test]
async fn test_siwe_sign_message_v2() {
    // World Chain Safe
    let wallet_address = "0x619525ED4E862B62cFEDACCc4dA5a9864D6f4A97";
    let private_key = "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
    let safe = SafeSmartAccount::new(private_key.to_string(), wallet_address).unwrap();
    
    let message = ValidationSuccess {
        message: generate_valid_payload(),
    };
    
    // Use SafeSmartAccount to sign the message
    let signature = safe.sign_siwe_message(&message, 480).unwrap();

    // Verify the signature format
    assert!(signature.signature.starts_with("0x"));
    assert!(!signature.message.contains("{address}")); // Address should be replaced
    assert!(signature.message.contains(wallet_address)); // Should contain actual address
    
    // Full verification against RPC would require the message to be signed by the actual Safe
    // which involves the 4337 module, so we just verify the signature format here
    let message_parsed: Message = signature.message.parse().unwrap();
    // Verify the parsed address matches (comparing checksummed address)
    let parsed_address = format!("0x{}", hex::encode(message_parsed.address));
    assert_eq!(parsed_address.to_lowercase(), wallet_address.to_lowercase());
}

#[test]
fn test_siwe_create_world_app_auth_message() {
    let wallet_address = "0x11a1801863e1f0941a663f0338aea395be1ec8a4";
    let private_key = "db547ff3ded25c60e791917584090eafd8efceba61d6e73946b89b7d6fc04725";
    let safe = SafeSmartAccount::new(private_key.to_string(), wallet_address).unwrap();

    let message = safe.create_auth_message(AuthConfig::WorldApp {
        flow: WorldAppAuthFlow::SignUp,
        base_url: "https://app-backend.toolsforhumanity.com".to_string(),
        nonce: Some(1_469_020_534),
        current_time: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    }).expect("Failed to create World App auth message");

    // Validate the message
    let validation_response = safe.validate_siwe_message(
        &message,
        wallet_address,
        "https://app-backend.toolsforhumanity.com/auth/sign-up",
        "https://app-backend.toolsforhumanity.com/",
    ).expect("Failed to validate World App auth message");
    
    assert_eq!(validation_response.statement, String::new());
    assert_eq!(validation_response.domain, "https://app-backend.toolsforhumanity.com");

    // Test signing with SafeSmartAccount directly
    let signed_response = safe.sign_siwe_message(&validation_response.result, 480).unwrap();
    
    // Verify the message content
    assert_eq!(signed_response.message, message);
    assert!(signed_response.signature.starts_with("0x"));
    
    // Verify the message has the correct format and contains expected values
    assert!(signed_response.message.contains(&wallet_address.to_lowercase()));
    assert!(signed_response.message.contains("https://app-backend.toolsforhumanity.com/public/v1/auth/sign-up"));
    assert!(signed_response.message.contains("Chain ID: 480"));
}

fn generate_valid_payload() -> String {
    let now = Utc::now();
    let expiration = now + ChronoDuration::days(7);
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