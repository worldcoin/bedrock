use super::*;

#[test]
fn test_decode_from_json() {
    // not properly encoded
    let seed = "1111111111111111111111111111111111111111111111111111111111111111";
    assert_eq!(
        RootKey::from_json(seed).unwrap_err().to_string(),
        "failed to parse key"
    );

    // properly encoded
    let key = r#"{"key":"1111111111111111111111111111111111111111111111111111111111111111","version":"V0"}"#;
    let key = RootKey::from_json(key).unwrap();
    assert_eq!(
        key.danger_to_json().unwrap(),
        r#"{"version":"V0","key":"1111111111111111111111111111111111111111111111111111111111111111"}"#
    );

    // properly encoded - V1
    let key = r#"{"key":"1111111111111111111111111111111111111111111111111111111111111111","version":"V1"}"#;
    let key = RootKey::from_json(key).unwrap();
    assert_eq!(
        key.danger_to_json().unwrap(),
        r#"{"version":"V1","key":"1111111111111111111111111111111111111111111111111111111111111111"}"#
    );
    assert!(!key.is_v0());
}

#[test]
fn test_decode_invalid_length() {
    let key = r#"{"key":"123","version":"V1"}"#;
    assert_eq!(
        RootKey::from_json(key).unwrap_err().to_string(),
        "failed to parse key"
    );
}

// FIXME: new_random tests
