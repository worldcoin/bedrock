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

/// Generate multiple keys and verify they are all different
/// We use a simple statistical test to verify that the keys look random. Note this is just a sanity check,
/// ultimately the randomness depends on the OS's source of randomness. Not on how it's implemented here.
#[test]
fn test_new_generates_seemingly_random_keys() {
    const NUM_KEYS: usize = 100;
    let mut keys = Vec::with_capacity(NUM_KEYS);

    for _ in 0..NUM_KEYS {
        let key = RootKey::new_random();
        let encoded = key.danger_to_json().unwrap();
        keys.push(encoded);
    }

    // Check that all keys are unique
    for i in 0..keys.len() {
        for j in (i + 1)..keys.len() {
            assert_ne!(
                keys[i], keys[j],
                "Generated duplicate keys at indices {i} and {j}"
            );
        }
    }

    for encoded in &keys {
        let parsed: serde_json::Value = serde_json::from_str(encoded).unwrap();
        let hex_key = parsed["key"].as_str().unwrap();
        let key_bytes = hex::decode(hex_key).unwrap();

        #[allow(clippy::naive_bytecount)] // this is a test, naive byte count is fine
        let zero_count = key_bytes.iter().filter(|b| **b == 0).count();

        assert!(zero_count < 4); // following a binomial distribution X ~ Bin(32, 1/256), P(X <= 4) = 0.99999+
    }
}
