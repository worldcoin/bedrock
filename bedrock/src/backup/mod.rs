// Core backup logic lives in bedrock-core.
// Re-export everything from there; only the Turnkey module remains here
// because it depends on the `turnkey_enclave_encrypt` crate not included in bedrock-core.
pub use bedrock_core::backup::*;

mod turnkey;
