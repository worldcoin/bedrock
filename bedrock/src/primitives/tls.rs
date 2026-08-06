//! TLS trust policy for bedrock's Rust-native outbound HTTPS clients.
//!
//! When interacting with World App's backend, the [`super::AuthenticatedHttpClient`] is
//! used. For anything else, Bedrock handles its own HTTP layer (e.g. Turnkey API, custom
//! transaction bundler, backup service).
//!
//! This module is introduced to define the security-critical trust store to use: for iOS,
//! the native Security framework is used. For Android, Mozilla's `webpki-roots` are bundled, this
//! is because Android requires an explicit JNI `Context` to use the native store, and that doesn't
//! cross the FFI boundary very well.

use crate::primitives::PrimitiveError;

/// Returns a [`reqwest::ClientBuilder`] pre-configured with bedrock's TLS trust
/// policy.
///
/// # Errors
///
/// Returns [`PrimitiveError::Generic`] if the Android TLS configuration cannot
/// be assembled. Infallible on every other platform.
#[cfg_attr(
    not(target_os = "android"),
    expect(clippy::unnecessary_wraps, reason = "platform dependent")
)]
pub(crate) fn client_builder() -> Result<reqwest::ClientBuilder, PrimitiveError> {
    let builder = reqwest::Client::builder();

    #[cfg(target_os = "android")]
    let builder = builder.tls_backend_preconfigured(android_webpki_tls_config()?);

    Ok(builder)
}

/// Root store pinned to the compiled-in Mozilla `webpki-roots` bundle (Android only).
#[cfg(any(target_os = "android", test))]
fn webpki_root_store() -> rustls::RootCertStore {
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    roots
}

/// Builds a rustls config that trusts the bundled `webpki-roots` (Android only).
///
/// # Errors
///
/// Returns [`PrimitiveError::Generic`] if the bundled root store is empty or the
/// rustls configuration cannot be assembled.
#[cfg(any(target_os = "android", test))]
fn android_webpki_tls_config() -> Result<rustls::ClientConfig, PrimitiveError> {
    let roots = webpki_root_store();
    if roots.is_empty() {
        crate::error!("Critical. No bundled webkpi root store found on Bedrock");
        return Err(PrimitiveError::Generic {
            error_message:
                "bundled webpki root store is empty; refusing to build TLS client"
                    .to_string(),
        });
    }

    rustls::ClientConfig::builder_with_provider(std::sync::Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .map(|builder| builder.with_root_certificates(roots).with_no_client_auth())
    .map_err(|e| PrimitiveError::Generic {
        error_message: format!("failed to build TLS config: {e}"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn webpki_root_store_is_populated() {
        let store = webpki_root_store();
        assert!(
            !store.is_empty(),
            "bundled webpki root store must not be empty"
        );
        assert_eq!(
            store.len(),
            webpki_roots::TLS_SERVER_ROOTS.len(),
            "root store should contain the full bundled Mozilla root set"
        );
    }

    #[test]
    fn android_webpki_tls_config_builds() {
        android_webpki_tls_config()
            .expect("android TLS config should build from the bundled webpki roots");
    }

    #[tokio::test]
    async fn preconfigured_webpki_tls_is_accepted_by_reqwest() {
        let tls = android_webpki_tls_config().unwrap();
        reqwest::Client::builder()
            .tls_backend_preconfigured(tls)
            .build()
            .expect("reqwest should accept the preconfigured webpki rustls config");
    }

    #[tokio::test]
    async fn client_builder_builds_a_usable_client() {
        client_builder()
            .unwrap()
            .build()
            .expect("reqwest client should build");
    }
}
