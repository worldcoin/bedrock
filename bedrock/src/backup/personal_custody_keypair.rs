use std::sync::Arc;

use crate::backup::utils::{base64_decode, base64_encode};
use crate::backup::BackupError;
use crypto_box::SecretKey;
use sha2::{Digest, Sha512};
use zeroize::Zeroize;

#[derive(uniffi::Object, Clone, Debug)]
pub struct PersonalCustodyKeypair {
    pk: crypto_box::PublicKey,
    sk: crypto_box::SecretKey,
}

impl PersonalCustodyKeypair {
    pub fn from_private_key(private_key: SecretKey) -> Self {
        Self {
            pk: private_key.public_key(),
            sk: private_key,
        }
    }

    pub fn from_private_key_bytes(private_key_bytes: Vec<u8>) -> Self {
        let private_key = SecretKey::from_slice(&private_key_bytes).unwrap();
        Self::from_private_key(private_key)
    }

    pub fn pk(&self) -> crypto_box::PublicKey {
        self.pk.clone()
    }

    pub fn sk(&self) -> crypto_box::SecretKey {
        self.sk.clone()
    }

    /// This is backwards compatible with libsodium's `crypto_box_curve25519xsalsa20poly1305_seed_keypair`
    /// https://github.com/jedisct1/libsodium/blob/59a98bc7f9d507175f551a53bfc0b2081f06e3ba/src/libsodium/crypto_box/curve25519xsalsa20poly1305/box_curve25519xsalsa20poly1305.c#L18
    pub fn derive_from_seed(seed: &[u8]) -> Self {
        let mut hasher = Sha512::new();
        hasher.update(seed);
        let seed_hash = hasher.finalize();
        let secret_key = SecretKey::from_slice(&seed_hash[..32]).unwrap();
        let public_key = secret_key.public_key();
        Self {
            pk: public_key,
            sk: secret_key,
        }
    }
}

#[uniffi::export]
impl PersonalCustodyKeypair {
    #[uniffi::constructor]
    pub fn new() -> Result<Arc<Self>, BackupError> {
        let private_key = SecretKey::generate(&mut rand::thread_rng());

        Ok(Arc::new(Self {
            pk: private_key.public_key(),
            sk: private_key,
        }))
    }

    pub fn pk_as_bytes(&self) -> Vec<u8> {
        self.pk.as_bytes().to_vec()
    }

    pub fn sk_as_bytes(&self) -> Vec<u8> {
        self.sk.to_bytes().to_vec()
    }

    pub fn pk_as_base64(&self) -> String {
        base64_encode(self.pk_as_bytes())
    }

    pub fn pk_as_pem(&self) -> String {
        let base64_key = self.pk_as_base64();

        let pem = format!(
            "-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----",
            base64_key
        );

        pem
    }
}

impl Zeroize for PersonalCustodyKeypair {
    fn zeroize(&mut self) {
        self.pk = crypto_box::PublicKey::from_bytes([0; 32]);
        self.sk = crypto_box::SecretKey::from_bytes([0; 32]);
    }
}

impl PersonalCustodyKeypair {
    #[cfg(test)]
    pub fn test_keypair() -> Self {
        let private_key = SecretKey::generate(&mut rand::thread_rng());
        PersonalCustodyKeypair {
            pk: private_key.public_key(),
            sk: private_key,
        }
    }
}

#[test]
fn test_print_keys() {
    let keypair = PersonalCustodyKeypair::new().unwrap();
    let pk_as_string = base64_encode(keypair.pk_as_bytes());
    let sk_as_string = base64_encode(keypair.sk_as_bytes());

    println!("Public Key: {}", pk_as_string);
    println!("Secret Key: {}", sk_as_string);

    let pk_base64 = "MCowBQYDK2VuAyEA2boNBmJX4lGkA9kjthS5crXOBxu2BPycKRMakpzgLG4=";
    let pk_bytes = base64_decode(pk_base64).unwrap();
    println!("The public key is {} bytes long.", pk_bytes.len());
}
