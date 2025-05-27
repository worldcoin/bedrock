use alloy::signers::local::PrivateKeySigner;

use super::*;

#[test]
fn test_cannot_initialize_with_invalid_hex_secret() {
    let invalid_hex = "invalid_hex";
    let result = SafeSmartAccount::new(
        invalid_hex.to_string(),
        "0x0000000000000000000000000000000000000042",
    );
    assert!(result.is_err());
    assert_eq!(
        result.unwrap_err().to_string(),
        format!("failed to decode hex-encoded secret into k256 signer: Odd number of digits")
    );
}

#[test]
fn test_cannot_initialize_with_invalid_curve_point() {
    let invalid_hex = "2a"; // `42` is not a valid point on the curve
    let result = SafeSmartAccount::new(
        invalid_hex.to_string(),
        "0x0000000000000000000000000000000000000042",
    );
    assert!(result.is_err());
    assert_eq!(
        result.unwrap_err().to_string(),
        format!(
            "failed to decode hex-encoded secret into k256 signer: signature error"
        )
    );
}

#[test]
fn test_cannot_initialize_with_invalid_wallet_address() {
    let invalid_addresses = [
        "0x000000000000000000000000000000000000001", // not 32 bytes
        "my_string",
        &"1".repeat(32),
    ];

    for invalid_address in invalid_addresses {
        let result = SafeSmartAccount::new(
            hex::encode(PrivateKeySigner::random().to_bytes()),
            invalid_address,
        );
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().to_string(),
            format!("failed to parse address: {invalid_address}")
        );
    }
}
