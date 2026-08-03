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

/// The list of `aud` claims for staging environment.
///
/// # Warning
/// Audiences (i.e. `client_id`) MUST be unique. The `apple_audience_tables_have_no_duplicates`
/// enforces this.
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Hardcoded literal explicit matching
    #[test]
    fn apple_audience_tables_are_pinned() {
        fn pairs(environment: BedrockEnvironment) -> Vec<(&'static str, &'static str)> {
            environment
                .turnkey_apple_audiences()
                .iter()
                .map(|audience| (audience.provider_name, audience.client_id))
                .collect()
        }

        assert_eq!(
            pairs(BedrockEnvironment::Staging),
            vec![
                ("APPLE", "org.worldcoin.insight.staging"),
                ("APPLE-WID", "org.world.staging.id"),
                ("APPLE-WID-SANDBOX", "org.world.sandbox.id"),
                ("APPLE-WEB", "app.world.apple.staging"),
            ]
        );

        // Sandbox intentionally shares the staging table.
        assert_eq!(
            pairs(BedrockEnvironment::Sandbox),
            pairs(BedrockEnvironment::Staging)
        );

        assert_eq!(
            pairs(BedrockEnvironment::Production),
            vec![
                ("APPLE", "org.worldcoin.insight"),
                ("APPLE-WID", "org.world.id"),
                ("APPLE-WEB", "app.world.apple"),
            ]
        );
    }

    #[test]
    fn apple_audience_tables_have_no_duplicates() {
        use std::collections::HashSet;
        for environment in [
            BedrockEnvironment::Staging,
            BedrockEnvironment::Sandbox,
            BedrockEnvironment::Production,
        ] {
            let table = environment.turnkey_apple_audiences();
            let client_ids: HashSet<&str> =
                table.iter().map(|audience| audience.client_id).collect();
            let provider_names: HashSet<&str> = table
                .iter()
                .map(|audience| audience.provider_name)
                .collect();
            assert_eq!(
                client_ids.len(),
                table.len(),
                "duplicate client_id in {environment:?} audiences"
            );
            assert_eq!(
                provider_names.len(),
                table.len(),
                "duplicate provider_name in {environment:?} audiences"
            );
        }
    }
}
