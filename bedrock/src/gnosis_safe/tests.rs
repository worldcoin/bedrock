use super::*;

#[test]
fn test_cannot_initialize_with_invalid_hex_secret() {
    let invalid_hex = "invalid_hex";
    let result = GnosisSafe::new(invalid_hex.to_string());
    assert!(result.is_err());
    assert_eq!(
        result.unwrap_err().to_string(),
        format!("failed to decode hex-encoded secret into k256 signer: Odd number of digits")
    );
}

#[test]
fn test_cannot_initialize_with_invalid_curve_point() {
    let invalid_hex = "2a"; // `42` is not a valid point on the curve
    let result = GnosisSafe::new(invalid_hex.to_string());
    assert!(result.is_err());
    assert_eq!(
        result.unwrap_err().to_string(),
        format!(
            "failed to decode hex-encoded secret into k256 signer: signature error"
        )
    );
}
