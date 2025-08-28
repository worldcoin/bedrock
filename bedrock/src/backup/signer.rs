/// Abstraction for signing backup-service challenges with the sync factor keypair.
///
/// Implementations are expected to:
/// - return the sync factor public key in uncompressed SEC1 form, base64 (standard) encoded
/// - sign the raw ASCII challenge string with ECDSA P-256, DER-encode the signature, base64 (standard) encode it
pub trait SyncSigner: Send + Sync {
    fn public_key_base64(&self) -> String;
    fn sign_challenge_base64(&self, challenge: &str) -> String;
}
