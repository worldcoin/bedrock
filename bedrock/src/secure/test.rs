use std::collections::HashMap;

use super::*;
use alloy::signers::local::LocalSigner;
use serde_json;

#[test]
fn test_key_versions() {
    // Version 1
    let seed = "1111111111111111111111111111111111111111111111111111111111111111";
    let ethereum_key = RootKey::decode(seed.to_owned()).ethereum_key().unwrap();
    let worldid_key = RootKey::decode(seed.to_owned()).worldid_key().unwrap();
    assert_eq!(
        ethereum_key,
        "3138bb9bc78df27c473ecfd1410f7bd45ebac1f59cf3ff9cfe4db77aab7aedd3" // sha256(seed)
    );
    assert_eq!(ethereum_key, worldid_key);

    // Version 2
    let key = r#"{"key":"db547ff3ded25c60e791917584090eafd8efceba61d6e73946b89b7d6fc04725","version":"V1"}"#;
    let ethereum_key = RootKey::decode(key.to_owned()).ethereum_key().unwrap();
    let worldid_key = RootKey::decode(key.to_owned()).worldid_key().unwrap();
    assert_eq!(
        ethereum_key,
        "1d9e07a98fdabdb092789870e0b8fabda28e0092deeee840cc4a5af20dcefdd3"
    );
    assert_ne!(ethereum_key, worldid_key);
}

#[test]
fn test_ethereum_key_with_index() {
    // Version 0
    let seed = "1111111111111111111111111111111111111111111111111111111111111111";
    let ethereum_key = RootKey::decode(seed.to_owned()).ethereum_key().unwrap();
    let ethereum_key0 = RootKey::decode(seed.to_owned())
        .ethereum_key_with_index(0)
        .unwrap();
    let ethereum_key1 = RootKey::decode(seed.to_owned())
        .ethereum_key_with_index(1)
        .unwrap();
    assert_eq!(ethereum_key, ethereum_key0);
    assert_eq!(
        ethereum_key1,
        "cc8e0e804409f55be4435cad241875e66d00b7e03eb9f3bd54a4587fabfddcc0"
    );
    assert_ne!(ethereum_key0, ethereum_key1);

    // Version 1
    let key = r#"{"key":"db547ff3ded25c60e791917584090eafd8efceba61d6e73946b89b7d6fc04725","version":"V1"}"#;
    let ethereum_key = RootKey::decode(key.to_owned()).ethereum_key().unwrap();
    let ethereum_key0 = RootKey::decode(key.to_owned())
        .ethereum_key_with_index(0)
        .unwrap();
    let ethereum_key1 = RootKey::decode(key.to_owned())
        .ethereum_key_with_index(1)
        .unwrap();
    assert_eq!(ethereum_key, ethereum_key0);
    assert_eq!(
        ethereum_key1,
        "7afcb7694443d30c97e1243df14bbb51c75d564d15f5f6973bcdaa26534406cb"
    );
    assert_ne!(ethereum_key0, ethereum_key1);
}

#[test]
fn test_encode_v2() {
    let key = RootKey::new_random();
    assert_eq!(
        key.ethereum_key().unwrap(),
        RootKey::decode(key.encode().unwrap())
            .ethereum_key()
            .unwrap()
    );
}

#[test]
fn test_encode_v1_wallet() {
    let key = "19c96ab440adf075647ada1402d69c25a87886a1933cf313e15b55c95ee04b99";
    let key = RootKey::decode(key.to_owned());

    let signer =
        LocalSigner::from_slice(&hex::decode(key.ethereum_key().unwrap()).unwrap())
            .unwrap();

    assert_eq!(
        format!("{:?}", signer.address()),
        "0x38a62de0f80edb030f100fdc6854dea484553764"
    );
}

#[test]
fn test_encode_v1_odd_length() {
    let key = "be1c98a32231f6bb1edb0bc0a5ef08f5c1f917923aadedb2399b648117c1d8d";
    let key = RootKey::decode(key.to_owned());

    let signer =
        LocalSigner::from_slice(&hex::decode(key.ethereum_key().unwrap()).unwrap())
            .unwrap();

    assert_eq!(
        format!("{:?}", signer.address()),
        "0xd91bb818cd577b787b8d8c0e527cdb75f4449aa6"
    );
}

#[test]
fn test_encode_v1_zero_byte() {
    let key = "e1c98a32231f6bb1edb0bc0a5ef08f5c1f917923aadedb2399b648117c1d8d";
    let key = RootKey::decode(key.to_owned());

    let signer =
        LocalSigner::from_slice(&hex::decode(key.ethereum_key().unwrap()).unwrap())
            .unwrap();

    assert_eq!(
        format!("{:?}", signer.address()),
        "0x30be550c605631d30f26113a8bbcaabf1175244a"
    );
}

#[test]
fn test_legacy_world_id_keys() {
    let test_cases: HashMap<&str, &str> = [
        (
            "187e5a82988b0b1fa3a04a0d2e137ab665e09f9b1674a237b15635a8feff1132",
            "e3c0fd0470a6813d536f263f61974ca15e01413203507996673108600a4f4752",
        ),
        (
            "13ffc88cc9d7bd9d0f9d04a94a45c97050aea9ed54a80bbead22446789d6c3a0",
            "e8012e120fb493b2a9fe3404b0b60e66fe0421b2b4d2e848b4ccd5b0267bbb8b",
        ),
        (
            "015189353509361377d41ff466788471792efa24da8f5dafbd495e46defb9979",
            "ce5a5875d622e4057f2f468ac9ed880fc4468b16c2dccb49b7b8b307b348b98e",
        ),
        (
            "15189353509361377d41ff466788471792efa24da8f5dafbd495e46defb9979",
            "4e6a79320e53f2a85ab6eb5e4319b42126ac56c570ca1b7bc8f41bef5168f0ee",
        ),
        (
            "1107990a851c6e2f1f7e12049a540ed5c5035581760d50a684ceaae4cfb9e436",
            "e24249f4e4d409ff34b1dcb38ae335cbe145e02e00bd8149549e7f3c16d3ab01",
        ),
        (
            "0000000a851c6e2f1f7e12049a540ed5c5035581760d50a684ceaae4c0000000",
            "403b198cd5e27902374f132ca9c217663c7f85b635020edcffa7c591d89f9bb4",
        ),
        (
            "be1c98a32231f6bb1edb0bc0a5ef08f5c1f917923aadedb2399b648117c1d8d",
            "5fe4f39e2bedfff6067c3d3d1cb5b877c4514d2efcc565f2fb468e1e4981b3eb",
        ),
    ]
    .iter()
    .copied()
    .collect();

    for (key, expected_value) in &test_cases {
        let oxide_key = RootKey::decode((*key).to_string());
        let result = oxide_key.worldid_key().unwrap();

        // Assert that the result is equal to the expected value
        assert_eq!(result, *expected_value, "Failed for key: {key}");
    }
}

#[test]
fn test_marble_seeds_v0() {
    let test_cases: HashMap<&str, &str> = [
        (
            "058a9692d42d0fab1d1eb5d68aaa2a69bd23aad9f6202182597d8e618cebe348",
            "21920802484908456411291850228002216716697129127007002185160905266643553441597",
        ),
        (
            "1c0a2cc29e2aeef9194bfeaa573ac8ba13febc58c1e603caf2a5b5a0c069d986",
            "53806506973277240841485906476227342088978234388400173369677626237229778903802",
        ),
        (
            "2190ad5ab68130247a756ccce2e420c939de12537c92009e535ae59961b8deeb",
            "56815594880343578330602428941509826938993470282466547190354758930942182058169",
        ),
        (
            "471275eafd416d19ea427f6dd4077b90af59ea9cc38212de6f5a72ce1663af81",
            "86567661472270501657663953094494940474168848105763613251752287627070942522784",
        ),
    ]
    .iter()
    .copied()
    .collect();

    for (key, expected_value) in &test_cases {
        let oxide_key = RootKey::decode((*key).to_string());
        let result = oxide_key.marble_seed().unwrap();

        // Assert that the result is equal to the expected value
        assert_eq!(result, *expected_value, "Failed for key: {key}");
    }
}

#[test]
fn test_marble_seeds_v1() {
    assert_eq!(
        RootKey::decode(
            r#"{"version":"V1","key":"986d08cca33ace012f3535afb2c05cd837b1ce1d23cca2f7a212ec167767fe8c"}"#.to_string()
        )
        .marble_seed()
        .unwrap(),
        "9081281641792454201454131898848142078681374923150837189982423566347662375261"
    );

    assert_eq!(
        RootKey::decode(
            r#"{"version":"V1","key":"123d08cca33ace012f3535afb2c05cd837b1ce1d23cca2f7a212ec167767fe8c"}"#.to_string()
        )
        .marble_seed()
        .unwrap(),
        "96523958675186709461517373255547493454740849409325281479206100781440769066489"
    );

    assert_eq!(
        RootKey::decode(
            r#"{"version":"V1","key":"123d08cca33ace012f3535afb2c05cd837b1ce1d23cca2f7a212ec167767f123"}"#.to_string()
        )
        .marble_seed()
        .unwrap(),
        "74302716087323764483607543760597674985807739506253046190599707253113397054672"
    );
}

#[test]
fn test_v0_encode() {
    assert_eq!(
        RootKey {
            key: VersionedKey::V0("1234".to_string())
        }
        .encode()
        .unwrap(),
        r#"{"version":"V0","key":"1234"}"#
    );
}

#[test]
fn test_v1_encode() {
    let slice =
        hex::decode("471275eafd416d19ea427f6dd4077b90af59ea9cc38212de6f5a72ce1663af81")
            .unwrap();
    let mut key = [0u8; KEY_LENGTH];
    key.copy_from_slice(&slice);

    assert_eq!(
        serde_json::to_string(&RootKey {
            key: VersionedKey::V1(key)
        })
        .unwrap(),
        r#"{"version":"V1","key":"471275eafd416d19ea427f6dd4077b90af59ea9cc38212de6f5a72ce1663af81"}"#
    );
}

// FIXME: Not yet implemented
// #[test]
// fn test_seed_derivation() {
//     let key = [42; 32];
//     // Hardcoded values derived from the above seed with curve25519xsalsa20poly1305::keypair_from_seed(&Seed(key))
//     let (sodiumoxide_public_key, sodiumoxide_private_key) = (
//         "55c0506c70233f01c32633ba683b9099c4d4adb209a046c3470b78788ec3c13f",
//         "f20a2613bdbcce990d0a124d6fc4bf97319d0cccf3f67a2c3fe575b5b99864d2",
//     );
//     let personal_custody_keypair = PersonalCustodyKeypair::derive_from_seed(&key);

//     assert_eq!(
//         hex::decode(sodiumoxide_public_key).unwrap(),
//         personal_custody_keypair.pk().as_bytes()
//     );
//     assert_eq!(
//         hex::decode(sodiumoxide_private_key).unwrap(),
//         personal_custody_keypair.sk().to_bytes()
//     );
// }

#[test]
fn test_key_versions_decode_from_json() {
    // Version 1 - should not be parsed with decode_from_json_enforced function,
    // as it expects a JSON string.
    let seed = "1111111111111111111111111111111111111111111111111111111111111111";
    assert_eq!(
        RootKey::decode_from_json_enforced(seed)
            .unwrap_err()
            .to_string(),
        "Failed to parse RootKey."
    );
    // Should be able to be parsed after being decoded with decode function and re-encoded
    let seed_after_re_encode = RootKey::decode(seed.to_owned()).encode().unwrap();
    let ethereum_key = RootKey::decode_from_json_enforced(&seed_after_re_encode)
        .unwrap()
        .ethereum_key()
        .unwrap();
    let worldid_key = RootKey::decode_from_json_enforced(&seed_after_re_encode)
        .unwrap()
        .worldid_key()
        .unwrap();
    assert_eq!(
        ethereum_key,
        "3138bb9bc78df27c473ecfd1410f7bd45ebac1f59cf3ff9cfe4db77aab7aedd3" // sha256(seed)
    );
    assert_eq!(ethereum_key, worldid_key);

    // Version 2 - should be parsed with decode_from_json_enforced function
    let key = r#"{"key":"db547ff3ded25c60e791917584090eafd8efceba61d6e73946b89b7d6fc04725","version":"V1"}"#;
    let ethereum_key = RootKey::decode_from_json_enforced(key)
        .unwrap()
        .ethereum_key()
        .unwrap();
    let worldid_key = RootKey::decode_from_json_enforced(key)
        .unwrap()
        .worldid_key()
        .unwrap();
    assert_eq!(
        ethereum_key,
        "1d9e07a98fdabdb092789870e0b8fabda28e0092deeee840cc4a5af20dcefdd3"
    );
    assert_ne!(ethereum_key, worldid_key);
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
        let encoded = key.encode().unwrap();
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

        #[allow(clippy::naive_bytecount)]
        // it's a test and we know the size is 32 bytes so no performance concerns
        let zero_count = key_bytes.iter().filter(|&b| *b == 0).count();

        assert!(zero_count < 4); // following a binomial distribution X ~ Bin(32, 1/256), P(X <= 4) = 0.99999+
    }
}

#[test]
fn test_world_chat_push_id() {
    // Test with V0 key
    let seed = "1111111111111111111111111111111111111111111111111111111111111111";
    let oxide_key_v0 = RootKey::decode(seed.to_owned());

    let push_id_1 = oxide_key_v0.world_chat_push_id_public(1).unwrap();
    let push_id_2 = oxide_key_v0.world_chat_push_id_public(2).unwrap();
    let push_id_1_duplicate = oxide_key_v0.world_chat_push_id_public(1).unwrap();

    // Verify results are hex strings of expected length (64 chars for 32 bytes)
    assert_eq!(push_id_1.len(), 64);
    assert_eq!(push_id_2.len(), 64);

    // Verify deterministic behavior - same signal produces same ID
    assert_eq!(push_id_1, push_id_1_duplicate);

    // Verify different signals produce different IDs
    assert_ne!(push_id_1, push_id_2);

    // Test with V1 key
    let key_v1 = r#"{"key":"db547ff3ded25c60e791917584090eafd8efceba61d6e73946b89b7d6fc04725","version":"V1"}"#;
    let oxide_key_v1 = RootKey::decode(key_v1.to_owned());

    let public_push_id_v1 = oxide_key_v1.world_chat_push_id_public(1).unwrap();

    // Verify V1 key produces different ID than V0 for same signal
    assert_ne!(push_id_1, public_push_id_v1);
    assert_eq!(public_push_id_v1.len(), 64);
}
