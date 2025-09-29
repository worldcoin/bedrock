//! This module allows interactions with the Turnkey API for the user's backup.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use bedrock_macros::bedrock_export;
use hpke::kem::DhP256HkdfSha256;
use hpke::{Deserializable, Kem as KemTrait};
use p256::ecdsa::signature::Signer;
use p256::ecdsa::Signature;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use serde_json::json;
use thiserror::Error;
use turnkey_enclave_encrypt::client::EnclaveEncryptClient;
use turnkey_enclave_encrypt::QuorumPublicKey;

/// Allows interactions with Turnkey API.
#[derive(uniffi::Object, Clone, Debug, Default)]
pub struct Turnkey {}

#[bedrock_export]
impl Turnkey {
    #[uniffi::constructor]
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Derive a public key from the API private key for use with Turnkey's API.
    ///
    /// The public key is a hex-encoded SEC1 `EncodedPoint` representation with compression enabled
    /// of the P256 public key. This is the same implementation as Turnkey SDK.
    ///
    /// # Arguments
    /// - `api_private_key`: A P256 private key encoded in hex. 32 random bytes.
    ///
    /// # Errors
    /// - `DecodeApiPrivateKeyError`: Failed to decode the API private key as hex.
    /// - `InvalidApiPrivateKeyLength`: The API private key is not 32 bytes long.
    #[allow(clippy::unused_self)] // Uniffi doesn't support associated functions
    pub fn derive_public_key(
        &self,
        api_private_key: String,
    ) -> Result<String, TurnkeyError> {
        let private_key = hex::decode(api_private_key)
            .map_err(|_| TurnkeyError::DecodeApiPrivateKeyError)?;
        if private_key.len() != 32 {
            return Err(TurnkeyError::InvalidApiPrivateKeyLength);
        }
        let private_key = p256::SecretKey::from_slice(&private_key)
            .map_err(|_| TurnkeyError::DecodeApiPrivateKeyError)?;
        Ok(hex::encode(
            private_key.public_key().to_encoded_point(true).as_bytes(),
        ))
    }

    /// Generate "a stamp" that should be passed in a header to Turnkey
    /// which is used to sign the request body with the ephemeral API private key.
    ///
    /// <https://docs.turnkey.com/developer-reference/api-overview/stamps#stamps>
    ///
    /// Reference implementation: <https://github.com/tkhq/rust-sdk/blob/10b9b90cc219034782b2f9a948b342a44638061f/api_key_stamper/src/lib.rs#L29>
    ///
    /// # Arguments
    /// - `body`: The request body to be signed. Must be formatted in JSON.
    /// - `api_private_key`: A P256 private key encoded in hex. The public key of this key should be
    ///   a Turnkey API key, e.g. as a long-lived token (for iCloud Keychain) or short-lived
    ///   token (for temporary update sessions).
    ///
    /// # Errors
    /// - `DecodeApiPrivateKeyError`: Failed to decode the API private key as hex.
    /// - `InvalidApiPrivateKeyLength`: The API private key is not 32 bytes long.
    /// - `DecodeBodyError`: Failed to parse the request body as JSON.
    /// - `SignBodyError`: Failed to sign the request body with the private key.
    ///
    /// # Returns
    /// Base64url-encoded string that contains the signature of the request body. Should be passed in
    /// the `X-Stamp` header of the request.
    #[allow(clippy::unused_self)] // Uniffi doesn't support associated functions
    pub fn stamp(
        &self,
        body: &str,
        api_private_key: &str,
    ) -> Result<String, TurnkeyError> {
        // Decode the private key as a P256 private scalar
        let private_key = hex::decode(api_private_key)
            .map_err(|_| TurnkeyError::DecodeApiPrivateKeyError)?;
        if private_key.len() != 32 {
            return Err(TurnkeyError::InvalidApiPrivateKeyLength);
        }
        let private_key = p256::SecretKey::from_slice(&private_key)
            .map_err(|_| TurnkeyError::DecodeApiPrivateKeyError)?;
        let signing_key = p256::ecdsa::SigningKey::from(private_key.clone());

        // Validate that the body is valid JSON, but discard the result of parsing. We should sign
        // the raw body to prevent issues with JSON formatting.
        let _json: serde_json::Value =
            serde_json::from_str(body).map_err(|_| TurnkeyError::DecodeBodyError)?;

        // Sign the body with the private key
        let signature: Signature = signing_key.sign(body.as_bytes());

        // Convert the signature to the expected header format
        let json_stamp = json!({
            "publicKey": hex::encode(private_key.public_key().to_encoded_point(true).as_bytes()),
            "signature": hex::encode(signature.to_der()),
            "scheme": "SIGNATURE_SCHEME_TK_API_P256",
        });
        let json_stamp = serde_json::to_string(&json_stamp)
            .map_err(|_| TurnkeyError::SerializeStampError)?;

        Ok(URL_SAFE_NO_PAD.encode(json_stamp.as_bytes()))
    }

    /// Encrypts the factor secret using Turnkey's enclave public key.
    ///
    /// This function should be called after `INIT_IMPORT` Turnkey operation,
    /// which produces the target public key and the signature of it by Turnkey's enclave,
    /// called import bundle. This function will create an "encrypted bundle", which client app needs
    /// send to Turnkey API to be decrypted by Turnkey's enclave as part of the `IMPORT` operation.
    ///
    /// Reference: <https://docs.turnkey.com/wallets/import-wallets>
    ///
    /// # Arguments
    /// - `factor_secret`: The factor secret to be encrypted. Must be a hex-encoded 32-byte string.
    /// - `import_bundle`: The import bundle received from the Turnkey enclave. Must be a valid JSON string.
    /// - `turnkey_organization_id`: The organization ID of the Turnkey account.
    /// - `turnkey_user_id`: The user ID of the Turnkey account.
    ///
    /// # Errors
    /// - `DecodeEnclaveAuthKeyError`: Failed to decode the Turnkey enclave public key.
    /// - `DeserializeImportBundleError`: Failed to deserialize the import bundle as JSON.
    /// - `InvalidFactorSecret`: The factor secret is not a valid hex-encoded 32-byte string.
    /// - `EncryptFactorSecretError`: Failed to encrypt the factor secret using the import bundle.
    /// - `SerializeEncryptedBundleError`: Failed to serialize the encrypted bundle to a JSON string.
    #[allow(clippy::unused_self)] // Uniffi doesn't support associated functions
    pub fn generate_import_bundle_for_factor_secret(
        &self,
        factor_secret: &str,
        import_bundle: &str,
        turnkey_organization_id: &str,
        turnkey_user_id: &str,
    ) -> Result<String, TurnkeyError> {
        // Check that import bundle is valid JSON
        let _value: serde_json::Value = serde_json::from_str(import_bundle)
            .map_err(|_| TurnkeyError::DeserializeImportBundleError)?;
        // Check that factor secret is a hex-encoded 32-byte string
        let factor_secret = hex::decode(factor_secret)
            .map_err(|_| TurnkeyError::InvalidFactorSecret)?;
        if factor_secret.len() != 32 {
            return Err(TurnkeyError::InvalidFactorSecret);
        }

        // Create the encryption client using Turnkey's library
        let client = EnclaveEncryptClient::from_enclave_auth_key(
            QuorumPublicKey::production_signer()
                .verifying_key()
                .map_err(|_| {
                    TurnkeyError::ConvertEnclavePublicKeyToVerifyingKeyError
                })?,
        );

        // Encrypt the factor secret using the import bundle, which includes target public key
        // signed by Turnkey's enclave
        let encrypted_bundle = client
            .encrypt(
                &factor_secret,
                import_bundle.as_bytes(),
                turnkey_organization_id,
                turnkey_user_id,
            )
            .map_err(|err| {
                log::error!("Failed to encrypt factor secret: {err:?}");
                TurnkeyError::EncryptFactorSecretError
            })?;

        // Convert encrypted bundle to JSON string
        let encrypted_bundle = serde_json::to_string(&encrypted_bundle)
            .map_err(|_| TurnkeyError::SerializeEncryptedBundleError)?;

        Ok(encrypted_bundle)
    }

    /// Decrypts the factor secret from an export bundle.
    ///
    /// The export bundle is a JSON, which contains the factor secret encrypted with the target
    /// ephemeral session key (corresponding to `session_secret_key`). The resulting factor secret is
    /// a hex-encoded 32-byte string.
    ///
    /// The export bundle is obtained from a `ACTIVITY_TYPE_EXPORT_PRIVATE_KEY` activity.
    ///
    /// Reference: <https://docs.turnkey.com/wallets/export-wallets>
    ///
    /// # Arguments
    /// - `session_secret_key`: The API private key to which the factor secret is encrypted. Corresponding
    ///   P256 SEC1 non-compressed public key should've been passed in the `targetPublicKey`
    ///   parameter of the "export private key" operation.
    /// - `turnkey_organization_id`: The organization ID of the Turnkey account. During recovery,
    ///   it can be retrieved from backup metadata in the backup service.
    /// - `export_bundle`: The export bundle received from the Turnkey enclave.
    ///   Must be a valid JSON string.
    ///
    /// # Errors
    /// - `DecodeEnclaveAuthKeyError`: Failed to decode the Turnkey enclave public key.
    /// - `DecodeApiPrivateKeyError`: Failed to decode the API private key as hex.
    /// - `InvalidApiPrivateKeyLength`: The API private key is not 32 bytes long.
    /// - `ConvertP256KeypairToHpkeKeypairError`: Failed to convert the P256 keypair to HPKE keypair.
    /// - `DecryptFactorSecretError`: Failed to decrypt the factor secret using the Turnkey enclave.
    #[allow(clippy::unused_self)] // Uniffi doesn't support associated functions
    pub fn decrypt_factor_secret(
        &self,
        session_secret_key: &str,
        turnkey_organization_id: &str,
        export_bundle: &str,
    ) -> Result<String, TurnkeyError> {
        let session_key_pair = SessionKeyPair::from_hex(session_secret_key)?;
        let _value: serde_json::Value = serde_json::from_str(export_bundle)
            .map_err(|_| TurnkeyError::DeserializeExportBundleError)?;

        let mut client = EnclaveEncryptClient::from_enclave_auth_key_and_target_key(
            QuorumPublicKey::production_signer()
                .verifying_key()
                .map_err(|_| {
                    TurnkeyError::ConvertEnclavePublicKeyToVerifyingKeyError
                })?,
            session_key_pair.public_key,
            session_key_pair.secret_key,
        );
        let factor_secret = client
            .decrypt(export_bundle.as_bytes(), turnkey_organization_id)
            .map_err(|_| TurnkeyError::DecryptFactorSecretError)?;

        Ok(hex::encode(factor_secret))
    }
}

struct SessionKeyPair {
    secret_key: <DhP256HkdfSha256 as KemTrait>::PrivateKey,
    public_key: <DhP256HkdfSha256 as KemTrait>::PublicKey,
}

impl SessionKeyPair {
    fn from_hex(secret_key: &str) -> Result<Self, TurnkeyError> {
        let private_key = hex::decode(secret_key)
            .map_err(|_| TurnkeyError::DecodeApiPrivateKeyError)?;

        if private_key.len() != 32 {
            return Err(TurnkeyError::InvalidApiPrivateKeyLength);
        }

        let secret_key = p256::SecretKey::from_slice(&private_key)
            .map_err(|_| TurnkeyError::DecodeApiPrivateKeyError)?;
        let public_key = secret_key.public_key();

        let secret_key = <DhP256HkdfSha256 as KemTrait>::PrivateKey::from_bytes(
            private_key.as_slice(),
        )
        .map_err(|_| TurnkeyError::ConvertP256KeypairToHpkeKeypairError)?;

        let public_key = <DhP256HkdfSha256 as KemTrait>::PublicKey::from_bytes(
            public_key.to_encoded_point(false).as_bytes(),
        )
        .map_err(|_| TurnkeyError::ConvertP256KeypairToHpkeKeypairError)?;

        Ok(Self {
            secret_key,
            public_key,
        })
    }
}

#[derive(Debug, Error, uniffi::Error)]
#[uniffi(flat_error)]
pub enum TurnkeyError {
    #[error("Failed to decode API private key as hex")]
    DecodeApiPrivateKeyError,
    #[error("Invalid length of API private key")]
    InvalidApiPrivateKeyLength,
    #[error("Failed to decode request body as JSON")]
    DecodeBodyError,
    #[error("Failed to serialize the stamp value to JSON")]
    SerializeStampError,
    #[error("Failed to deserialize import bundle as JSON")]
    DeserializeImportBundleError,
    #[error("Failed to deserialize export bundle as JSON")]
    DeserializeExportBundleError,
    #[error("Invalid factor secret")]
    InvalidFactorSecret,
    #[error("Failed to encrypt the factor secret to the import bundle")]
    EncryptFactorSecretError,
    #[error("Failed to serialize encrypted bundle to json string")]
    SerializeEncryptedBundleError,
    #[error("Failed to decrypt the factor secret")]
    DecryptFactorSecretError,
    #[error("Failed to convert P256 keypair to HPKE keypair")]
    ConvertP256KeypairToHpkeKeypairError,
    #[error("Failed to convert enclave public key to verifying key")]
    ConvertEnclavePublicKeyToVerifyingKeyError,
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::prelude::BASE64_URL_SAFE_NO_PAD;
    use base64::Engine;
    use p256::ecdsa::signature::Verifier;
    use p256::ecdsa::VerifyingKey;
    use p256::PublicKey;
    use serde_json::json;

    #[test]
    fn test_derive_public_key() {
        let client = Turnkey::new();
        // 32 bytes in hex, generated randomly
        let api_private_key =
            "8b380767b1947c1c67da42dbc6929a9137202bab770bca2ddcdeaa1dbdd505b8";

        let public_key = client
            .derive_public_key(api_private_key.to_string())
            .unwrap();
        // Expected public key has been calculated using Turnkey SDK library, see test_stamp() for details.
        assert_eq!(
            public_key,
            "032c5e01c8659d3399143d89f243f01245c7185575b3c73254b17ecbaa9bcad113"
        );

        // Test with invalid API private key
        let api_private_key =
            "8b380767b1947c1c67da42dbc6929a9137202bab770bca2ddcdeaa1dbdd505b";
        let result = client.derive_public_key(api_private_key.to_string());
        assert_eq!(
            result.unwrap_err().to_string(),
            "Failed to decode API private key as hex"
        );

        // Test with API private key of incorrect size
        let api_private_key = hex::encode([0u8; 31]);
        let result = client.derive_public_key(api_private_key);
        assert_eq!(
            result.unwrap_err().to_string(),
            "Invalid length of API private key"
        );
    }

    #[test]
    fn test_stamp() {
        let client = Turnkey::new();
        // 32 bytes in hex, generated randomly
        let api_private_key =
            "8b380767b1947c1c67da42dbc6929a9137202bab770bca2ddcdeaa1dbdd505b8";

        let stamp = client
            .stamp(&json!({"example": 123}).to_string(), api_private_key)
            .unwrap();

        // decode and inspect the stamp
        let decoded_stamp = BASE64_URL_SAFE_NO_PAD.decode(&stamp).unwrap();
        let decoded_stamp: serde_json::Value =
            serde_json::from_slice(&decoded_stamp).unwrap();

        // Check that the decoded stamp contains the expected fields
        assert_eq!(decoded_stamp["signature"].as_str().unwrap().len(), 140);
        assert_eq!(
            decoded_stamp["scheme"].as_str().unwrap(),
            "SIGNATURE_SCHEME_TK_API_P256"
        );

        // Expected public key has been calculated using Turnkey SDK library:
        // import {generateP256KeyPair} from "@turnkey/crypto";
        // let kp = generateP256KeyPair();
        // console.log(kp.privateKey);
        // console.log(kp.publicKey);
        assert_eq!(
            decoded_stamp["publicKey"].as_str().unwrap(),
            "032c5e01c8659d3399143d89f243f01245c7185575b3c73254b17ecbaa9bcad113"
        );

        // Validate the signature
        let signature =
            hex::decode(decoded_stamp["signature"].as_str().unwrap()).unwrap();
        let signature = p256::ecdsa::Signature::from_der(&signature).unwrap();
        let public_key = PublicKey::from_sec1_bytes(
            &hex::decode(decoded_stamp["publicKey"].as_str().unwrap()).unwrap(),
        )
        .unwrap();
        let verifying_key = VerifyingKey::from(public_key);
        let body = json!({"example": 123}).to_string();
        assert!(verifying_key.verify(body.as_bytes(), &signature).is_ok());
    }

    #[test]
    fn test_stamp_invalid_request_body() {
        let client = Turnkey::new();
        let api_private_key =
            "8b380767b1947c1c67da42dbc6929a9137202bab770bca2ddcdeaa1dbdd505b8";

        let result = client.stamp("invalid_json", api_private_key);
        assert_eq!(
            result.unwrap_err().to_string(),
            "Failed to decode request body as JSON"
        );
    }

    #[test]
    fn test_stamp_invalid_api_private_key() {
        let client = Turnkey::new();
        let api_private_key =
            "8b380767b1947c1c67da42dbc6929a9137202bab770bca2ddcdeaa1dbdd505b";

        let result =
            client.stamp(&json!({"example": 123}).to_string(), api_private_key);
        assert_eq!(
            result.unwrap_err().to_string(),
            "Failed to decode API private key as hex"
        );
    }

    #[test]
    fn test_stamp_api_private_key_of_incorrect_size() {
        let client = Turnkey::new();
        let api_private_key = hex::encode([0u8; 31]);

        let result =
            client.stamp(&json!({"example": 123}).to_string(), &api_private_key);
        assert_eq!(
            result.unwrap_err().to_string(),
            "Invalid length of API private key"
        );
    }

    #[test]
    fn test_import_private_key() {
        let client = Turnkey::new();
        // 32 bytes in hex, generated randomly
        let factor_secret =
            "8b380767b1947c1c67da42dbc6929a9137202bab770bca2ddcdeaa1dbdd505b8";
        // sample import bundle from Turnkey API
        let import_bundle = r#"{"version":"v1.0.0","data":"7b227461726765745075626c6963223a2230343962386233366462353538653533356565316161663631303162396561623734383065396439383861636331663666323636613935393266393562643562626236616436613838383565303364346139353934636263646231323363306538623337326265666536666563643235346234666230353836343236306532646366222c226f7267616e697a6174696f6e4964223a2265396537653436362d663638372d343861322d396539352d623930393761343735663336222c22757365724964223a2234646536303165642d383332652d346339662d383735642d666437396364323166356133227d","dataSignature":"3046022100cfe48f3c7a91d4a56439866c8167f8b775873a4ef17c2eac4b42f7e999c9b0e5022100f680ec21a03b21a12182fd955bc2c2fa05d5065e198f7bff9e150e703b9ca0f9","enclaveQuorumPublic":"04cf288fe433cc4e1aa0ce1632feac4ea26bf2f5a09dcfe5a42c398e06898710330f0572882f4dbdf0f5304b8fc8703acd69adca9a4bbf7f5d00d20a5e364b2569"}"#;
        // sample organization ID and user ID from the request of import bundle above
        let organization_id = "e9e7e466-f687-48a2-9e95-b9097a475f36";
        let user_id = "4de601ed-832e-4c9f-875d-fd79cd21f5a3";
        let encrypted_bundle = client
            .generate_import_bundle_for_factor_secret(
                factor_secret,
                import_bundle,
                organization_id,
                user_id,
            )
            .unwrap();

        let encrypted_bundle: serde_json::Value =
            serde_json::from_str(&encrypted_bundle).unwrap();

        // Check that the encrypted bundle contains the expected fields
        assert!(encrypted_bundle["encappedPublic"].is_string());
        assert!(encrypted_bundle["ciphertext"].is_string());

        // It's difficult to verify encryption without the sender private key, which isn't
        // exposed by decryption function. We rely on tests of the `turnkey-enclave-encrypt` crate.
    }

    #[test]
    fn test_import_private_key_with_invalid_import_bundle() {
        let client = Turnkey::new();
        let factor_secret =
            "8b380767b1947c1c67da42dbc6929a9137202bab770bca2ddcdeaa1dbdd505b8";
        let import_bundle = "invalid_json";
        let organization_id = "e9e7e466-f687-48a2-9e95-b9097a475f36";
        let user_id = "4de601ed-832e-4c9f-875d-fd79cd21f5a3";
        let result = client.generate_import_bundle_for_factor_secret(
            factor_secret,
            import_bundle,
            organization_id,
            user_id,
        );
        assert_eq!(
            result.unwrap_err().to_string(),
            "Failed to deserialize import bundle as JSON"
        );
    }

    #[test]
    fn test_import_private_key_with_incorrect_organization_id() {
        let client = Turnkey::new();
        let factor_secret =
            "8b380767b1947c1c67da42dbc6929a9137202bab770bca2ddcdeaa1dbdd505b8";
        let import_bundle = r#"{"version":"v1.0.0","data":"7b227461726765745075626c6963223a2230343962386233366462353538653533356565316161663631303162396561623734383065396439383861636331663666323636613935393266393562643562626236616436613838383565303364346139353934636263646231323363306538623337326265666536666563643235346234666230353836343236306532646366222c226f7267616e697a6174696f6e4964223a2265396537653436362d663638372d343861322d396539352d623930393761343735663336222c22757365724964223a2234646536303165642d383332652d346339662d383735642d666437396364323166356133227d","dataSignature":"3046022100cfe48f3c7a91d4a56439866c8167f8b775873a4ef17c2eac4b42f7e999c9b0e5022100f680ec21a03b21a12182fd955bc2c2fa05d5065e198f7bff9e150e703b9ca0f9","enclaveQuorumPublic":"04cf288fe433cc4e1aa0ce1632feac4ea26bf2f5a09dcfe5a42c398e06898710330f0572882f4dbdf0f5304b8fc8703acd69adca9a4bbf7f5d00d20a5e364b2569"}"#;
        // swapped organization_id and user_id
        let organization_id = "4de601ed-832e-4c9f-875d-fd79cd21f5a3";
        let user_id = "e9e7e466-f687-48a2-9e95-b9097a475f36";
        let result = client.generate_import_bundle_for_factor_secret(
            factor_secret,
            import_bundle,
            organization_id,
            user_id,
        );
        assert_eq!(
            result.unwrap_err().to_string(),
            "Failed to encrypt the factor secret to the import bundle"
        );
    }

    #[test]
    fn test_decrypt_factor_secret() {
        let client = Turnkey::new();

        // Test private key export bundle from Turnkey API using their TS SDK with target public key
        // that corresponds to this private key
        let api_private_key =
            "a528d4d2c23d25bef52192d421a4e2555c9a4a9c3e5ed7c7910fa563d8613b7a";
        let export_bundle = r#"{"version":"v1.0.0","data":"7b22656e6361707065645075626c6963223a2230346361636663376430666336613566356664383764373566333236306233646637346335333037336366666564386462393831633737613462316334623839646162666234326435663337653437633135393836326261333434356462653537336438353265656639336665303061386231393533633731353834333437313135222c2263697068657274657874223a22656437396463373566643865633134346538326261656338313962653661336463353531353233646265633136333731663963613931323134643466613961663336343865336164306561313761373761656236393065613238333931323266222c226f7267616e697a6174696f6e4964223a2262306665303631382d363062302d346664312d613238662d666133626135623762393762227d","dataSignature":"3045022100ba94be796eb38fb1824c96962deece559cae57d0a4889aa9d5bdb10f711f00ac02207b19d5d787312f1485f428e2ec5ef04343bf8eb3343d20765805aa9c987f59c4","enclaveQuorumPublic":"04cf288fe433cc4e1aa0ce1632feac4ea26bf2f5a09dcfe5a42c398e06898710330f0572882f4dbdf0f5304b8fc8703acd69adca9a4bbf7f5d00d20a5e364b2569"}"#;
        let organization_id = "b0fe0618-60b0-4fd1-a28f-fa3ba5b7b97b";

        // Decrypt the factor secret using the API private key and export bundle
        let result = client
            .decrypt_factor_secret(api_private_key, organization_id, export_bundle)
            .unwrap();

        // Expected factor secret has been cross-checked with the private key that was imported to Turnkey
        assert_eq!(
            result,
            "e5a5b45eb81b64fd76322e54b2df5f6d5cea37ff631f27d58dd57119ac69a6d2"
        );

        // Bitflip api_private_key and check that decryption fails
        let mut api_private_key_bytes = hex::decode(api_private_key).unwrap();
        api_private_key_bytes[10] ^= 1;

        let result = client.decrypt_factor_secret(
            &hex::encode(api_private_key_bytes),
            organization_id,
            export_bundle,
        );
        assert_eq!(
            result.unwrap_err().to_string(),
            "Failed to decrypt the factor secret"
        );
    }
}
