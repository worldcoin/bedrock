//! This module contains all policies and configurations for World App's use of Turnkey.

use crate::primitives::config::BedrockEnvironment;

/// Represents the user's primary authentication and holds their Main Factor credentials.
///
/// Turnkey's `userName` of the primary user who holds all the Main Factors. Sole
/// member of the root quorum.
///
/// MUST be a precise name. Do not change this! Bad things could happen.
pub const AUTH_USER_MAIN_USERNAME: &str = "auth_user_main";

/// The Apple Sign In OIDC issuer.
pub const APPLE_ISSUER: &str = "https://appleid.apple.com";

impl BedrockEnvironment {
    /// Parent Turnkey organization id (i.e. TFH)
    pub(super) const fn turnkey_parent_organization_id(self) -> &'static str {
        match self {
            Self::Staging | Self::Sandbox => "72955dee-35e7-48a4-86ac-a8020a87bde8",
            Self::Production => "2be0b97b-7732-492d-9047-ca14391d24c9",
        }
    }

    /// Apple audiences for which the [`AUTH_USER_MAIN_USERNAME`] should be registered if
    /// using Sign in with Apple
    pub(super) const fn turnkey_apple_audiences(self) -> &'static [AppleAudience] {
        match self {
            Self::Staging | Self::Sandbox => STAGING_APPLE_AUDIENCES,
            Self::Production => PRODUCTION_APPLE_AUDIENCES,
        }
    }
}

pub(super) struct AppleAudience {
    /// Provider name registered in Turnkey to identify this Apple provider.
    pub(super) provider_name: &'static str,
    /// The `aud` claim from the OIDC JWT.
    pub(super) client_id: &'static str,
}

const STAGING_APPLE_AUDIENCES: &[AppleAudience] = &[
    // World App iOS — the pre-existing provider; keep the name "APPLE".
    AppleAudience {
        provider_name: "APPLE",
        client_id: "org.worldcoin.insight.staging",
    },
    // World ID iOS.
    AppleAudience {
        provider_name: "APPLE-WID",
        client_id: "org.world.staging.id",
    },
    // World ID iOS (sandbox).
    AppleAudience {
        provider_name: "APPLE-WID-SANDBOX",
        client_id: "org.world.sandbox.id",
    },
    // Android (web-based Sign in with Apple).
    AppleAudience {
        provider_name: "APPLE-WEB",
        client_id: "app.world.apple.staging",
    },
];

const PRODUCTION_APPLE_AUDIENCES: &[AppleAudience] = &[
    // World App iOS — the pre-existing provider; keep the name "APPLE".
    AppleAudience {
        provider_name: "APPLE",
        client_id: "org.worldcoin.insight",
    },
    // World ID iOS.
    AppleAudience {
        provider_name: "APPLE-WID",
        client_id: "org.world.id",
    },
    // Android (web-based Sign in with Apple).
    AppleAudience {
        provider_name: "APPLE-WEB",
        client_id: "app.world.apple",
    },
];
