use super::*;
use pretty_assertions::assert_eq;
use std::time::{SystemTime, UNIX_EPOCH};

fn create_siwe_service() -> Arc<Siwe> {
    Siwe::new("https://app-backend.toolsforhumanity.com".to_string())
}

fn get_current_time() -> String {
    let now = SystemTime::now();
    let datetime = time::OffsetDateTime::from(now);
    datetime
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap()
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
        Request ID: 0",
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
        Request ID: 0",
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
fn test_siwe_create_world_app_auth_message() {
    let siwe = create_siwe_service();
    let wallet_address = "0x11a1801863e1f0941a663f0338aea395be1ec8a4".to_string();

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
            "https://app-backend.toolsforhumanity.com/public/v1/auth/sign-up",
            "https://app-backend.toolsforhumanity.com/",
        )
        .expect("Failed to validate World App auth message");

    assert_eq!(response.result.message, message);
}

#[test]
fn test_siwe_sign_wallet_auth_message_v2() {
    let siwe = create_siwe_service();
    let wallet_address = "0x619525ED4E862B62cFEDACCc4dA5a9864D6f4A97".to_string();
    let private_key =
        "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef";

    let message = ValidationSuccess {
        message: "test.com wants you to sign in with your Ethereum account:\n{address}\n\nstatement\n\nURI: https://test.com\nVersion: 1\nChain ID: 480\nNonce: 12345678\nIssued At: 2025-05-28T20:56:07Z\nExpiration Time: 2025-06-04T20:56:07Z\nNot Before: 2025-05-28T20:56:07Z\nRequest ID: 0".to_string()
    };

    let signature = siwe
        .sign_wallet_auth_message_v2(&message, private_key.to_string(), &wallet_address)
        .unwrap();

    // Verify the signature contains the expected structure
    assert!(signature.signature.starts_with("0x"));
    assert!(signature.message.contains(&wallet_address));
}

#[cfg(feature = "tooling_tests")]
#[test]
fn test_siwe_sign_world_app_auth_message() {
    let siwe = create_siwe_service();
    let wallet_address = "0x11a1801863e1f0941a663f0338aea395be1ec8a4";
    let private_key =
        "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef";

    let message = siwe
        .create_world_app_auth_message(
            WorldAppAuthFlow::SignUp,
            wallet_address,
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        )
        .expect("Failed to create World App auth message");

    let validation_result = ValidationSuccess { message };

    let signature = siwe
        .sign_world_app_auth_message(validation_result, private_key.to_string())
        .unwrap();

    // Verify the signature contains the expected structure
    assert!(signature.signature.starts_with("0x"));
    // The message should contain the checksummed address, not the original
    assert!(signature
        .message
        .contains("0x11A1801863e1F0941A663f0338aEa395Be1Ec8A4"));
}
