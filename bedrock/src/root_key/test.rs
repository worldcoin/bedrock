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

#[test]
fn test_new_random_v1_and_roundtrip() {
    let key = RootKey::new_random();
    assert!(!key.is_v0());

    // Serialize and validate structure
    let json = key.danger_to_json().unwrap();
    let v: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(v["version"], "V1");
    let key_hex = v["key"].as_str().unwrap();
    assert_eq!(key_hex.len(), 64); // 32 bytes hex-encoded
    let decoded = hex::decode(key_hex).unwrap();
    assert_eq!(decoded.len(), KEY_LENGTH);

    // Round-trip back into RootKey and ensure equality
    let roundtrip = RootKey::from_json(&json).unwrap();
    assert_eq!(key, roundtrip);
}

#[test]
fn test_new_random_uniqueness_basic() {
    let a = RootKey::new_random();
    let b = RootKey::new_random();
    assert_ne!(a, b);
}
