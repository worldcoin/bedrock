//! Per-environment Turnkey policy: the expected users, issuers, and audiences
//! this account-management reconciles toward, plus the public auth-proxy config
//! used to resolve a sub-organization when the caller does not supply its id.

use crate::primitives::config::BedrockEnvironment;

/// Turnkey `userName` of the primary backup user whose OAuth providers the Apple
/// audience migration reconciles.
///
/// This is a precise `userName` and is also the sole member of the sub-org root
/// quorum (a cross-check that may be added in a later migration).
pub const AUTH_USER_MAIN_USERNAME: &str = "auth_user_main";

/// The Apple Sign In OIDC issuer.
pub const APPLE_ISSUER: &str = "https://appleid.apple.com";

/// Prefix used when naming newly-created Apple OAuth providers.
pub const APPLE_PROVIDER_NAME_PREFIX: &str = "apple-";

/// An Apple audience (`aud` / client id) that `auth_user_main` must have a
/// provider for.
pub struct AppleAudience {
    /// Short label identifying the client, used to build the provider name.
    pub label: &'static str,
    /// The Apple `aud` (client id / Services ID) value.
    pub client_id: &'static str,
}

/// The Turnkey configuration for a single [`BedrockEnvironment`].
pub struct TurnkeyPolicy {
    /// Public `X-Auth-Proxy-Config-Id` for unauthenticated sub-organization lookups.
    pub auth_proxy_config_id: &'static str,
    /// Apple audiences the main user must have an OAuth provider for.
    pub apple_audiences: &'static [AppleAudience],
}

// NOTE: placeholder values — replace with the real Apple client IDs and
// auth-proxy config id before enabling in production. Each environment has three
// audiences (World ID iOS, World App iOS, Android); Sandbox reuses Staging.
/// Turnkey policy for the Staging (and Sandbox) environment.
const STAGING_POLICY: TurnkeyPolicy = TurnkeyPolicy {
    auth_proxy_config_id: "PLACEHOLDER_STAGING_AUTH_PROXY_CONFIG_ID",
    apple_audiences: &[
        AppleAudience {
            label: "world-id-ios",
            client_id: "PLACEHOLDER_STAGING_WORLD_ID_IOS",
        },
        AppleAudience {
            label: "world-app-ios",
            client_id: "PLACEHOLDER_STAGING_WORLD_APP_IOS",
        },
        AppleAudience {
            label: "android",
            client_id: "PLACEHOLDER_STAGING_ANDROID",
        },
    ],
};

/// Turnkey policy for the Production environment.
const PRODUCTION_POLICY: TurnkeyPolicy = TurnkeyPolicy {
    auth_proxy_config_id: "PLACEHOLDER_PROD_AUTH_PROXY_CONFIG_ID",
    apple_audiences: &[
        AppleAudience {
            label: "world-id-ios",
            client_id: "PLACEHOLDER_PROD_WORLD_ID_IOS",
        },
        AppleAudience {
            label: "world-app-ios",
            client_id: "PLACEHOLDER_PROD_WORLD_APP_IOS",
        },
        AppleAudience {
            label: "android",
            client_id: "PLACEHOLDER_PROD_ANDROID",
        },
    ],
};

impl BedrockEnvironment {
    /// Returns the Turnkey account-management policy for this environment.
    ///
    /// Sandbox shares Staging's policy.
    pub(crate) const fn turnkey_policy(self) -> &'static TurnkeyPolicy {
        match self {
            Self::Staging | Self::Sandbox => &STAGING_POLICY,
            Self::Production => &PRODUCTION_POLICY,
        }
    }
}
