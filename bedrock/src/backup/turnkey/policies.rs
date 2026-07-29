//! This module contains all policies and configurations for World App's use of Turnkey.

use crate::primitives::config::BedrockEnvironment;

/// Turnkey's `userName` of the primary user who holds all the Main Factors. Sole
/// member of the root quorum.
///
/// MUST be a precise name. Do not change this! Bad things could happen.
pub const AUTH_USER_MAIN_USERNAME: &str = "auth_user_main";

/// The Apple Sign In OIDC issuer.
pub const APPLE_ISSUER: &str = "https://appleid.apple.com";

/// Prefix used when naming alternative Apple OAuth providers.
pub const APPLE_PROVIDER_NAME_PREFIX: &str = "apple-";

impl BedrockEnvironment {
    /// Parent Turnkey organization id (i.e. TFH)
    pub(super) const fn turnkey_parent_organization_id(self) -> &'static str {
        match self {
            Self::Staging | Self::Sandbox => "72955dee-35e7-48a4-86ac-a8020a87bde8",
            Self::Production => "2be0b97b-7732-492d-9047-ca14391d24c9",
        }
    }

    /// Apple audiences for which the `auth_main_user` should be registered if
    /// using Sign in with Apple
    pub(super) const fn turnkey_apple_audiences(self) -> &'static [AppleAudience] {
        match self {
            Self::Staging | Self::Sandbox => STAGING_APPLE_AUDIENCES,
            Self::Production => PRODUCTION_APPLE_AUDIENCES,
        }
    }
}

pub(super) struct AppleAudience {
    /// Label used in Turnkey to identify the provider
    pub(super) label: &'static str,
    /// The `aud` claim from the OIDC JWT.
    pub(super) client_id: &'static str,
}

const STAGING_APPLE_AUDIENCES: &[AppleAudience] = &[
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
];

const PRODUCTION_APPLE_AUDIENCES: &[AppleAudience] = &[
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
];
