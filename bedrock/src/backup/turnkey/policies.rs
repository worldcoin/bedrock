//! This module contains all policies and configurations for World App's use of Turnkey.

use crate::primitives::config::BedrockEnvironment;

/// Represents the user's primary authentication and holds their Main Factor credentials.
///
/// Turnkey's `userName` of the primary user who holds all the Main Factors. Sole
/// member of the root quorum.
///
/// MUST be a precise name. Changing this without migrations would break existing accounts
/// and lead to diverging states.
pub const AUTH_USER_MAIN_USERNAME: &str = "auth_user_main";

/// The break-glass user's Turnkey `userName`.
///
/// MUST be a precise name. Changing this without migrations would break existing accounts
/// and lead to diverging states.
pub(super) const BREAK_GLASS_USERNAME: &str = "break_glass_user";

/// Prefix of a sync factor user's Turnkey `userName`.
///
/// Sync factor users are named `sync_factor_user_<suffix>`; any Turnkey user whose
/// `userName` starts with this prefix is a device-local sync factor.
pub(super) const SYNC_FACTOR_USERNAME_PREFIX: &str = "sync_factor_user_";

/// The typed role of each user in a user's Turnkey account (sub-organization). We
/// rely on the user name to determine it.
///
/// Reference: <https://docs.toolsforhumanity.com/world-app/backup/components#turnkey-user-setup>
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum UserRole {
    /// The main user ([`AUTH_USER_MAIN_USERNAME`]), holder of the root quorum.
    Main,
    /// A device-local sync factor ([`SYNC_FACTOR_USERNAME_PREFIX`]).
    SyncFactor,
    /// The break-glass recovery user ([`BREAK_GLASS_USERNAME`]).
    BreakGlass,
    /// A `userName` matching none of the known roles. This is unexpected behavior.
    Unexpected,
}

impl UserRole {
    /// Classifies a Turnkey user by its `user_name`.
    pub(super) fn classify(user_name: &str) -> Self {
        if user_name == AUTH_USER_MAIN_USERNAME {
            Self::Main
        } else if user_name.starts_with(SYNC_FACTOR_USERNAME_PREFIX) {
            Self::SyncFactor
        } else if user_name == BREAK_GLASS_USERNAME {
            Self::BreakGlass
        } else {
            Self::Unexpected
        }
    }
}

/// The Apple Sign In OIDC issuer.
pub const APPLE_ISSUER: &str = "https://appleid.apple.com";

/// Notes stored on the sync factor policy
pub(super) const SYNC_FACTOR_POLICY_NOTES: &str =
    "Allows a sync factor to perform deletion operations. Configured by Bedrock.";

/// The conditions on the policy assigned to all Sync Factors.
///
/// The policy permits specific **deletion-only** activities (see `activity.action`).
///
/// Reference: <https://docs.toolsforhumanity.com/world-app/backup/components#turnkey-user-setup>
///
/// # Resources
/// - `USER` allows the sync factor to remove itself (e.g. on logout) and
///   other stale Sync Factor users. It cannot remove [`AUTH_USER_MAIN_USERNAME`] because of Root Quorum validation.
/// - `CREDENTIAL` allows removal of OIDC providers, authenticators, API keys, lets the user
///   delete factors without needing to do a full re-authentication flow.
/// - `ORGANIZATION` allows removal of the entire sub-org (e.g. when deleting the entire backup).
/// - `PRIVATE_KEY` allows removing the imported factor secret. Currently not in active use.
///
/// # Historical Considerations
/// The initial policy targeted `activity.type` but this was updated because those are version
/// sensitive. Further, not all resources were covered in initial policies.
pub(super) const SYNC_FACTOR_POLICY_CONDITION: &str = concat!(
    "activity.action == 'DELETE' && (",
    "activity.resource == 'CREDENTIAL' || ",
    "activity.resource == 'PRIVATE_KEY' || ",
    "activity.resource == 'ORGANIZATION' || ",
    "activity.resource == 'USER')"
);

/// Builds the consensus expression binding a sync factor policy to
/// exactly one user (the sync factor itself).
///
/// Returns `None` if `user_id` is NOT a well-formed identifier.
pub(super) fn sync_factor_policy_consensus(user_id: &str) -> Option<String> {
    is_turnkey_user_id(user_id)
        .then(|| format!("approvers.any(user, user.id == '{user_id}')"))
}

/// Whether `user_id` is a well-formed Turnkey identifier (a UUID).
///
/// Turnkey ids are always UUIDs. Validating the shape ensures there
/// aren't extraneous characters that could change the policy's effect.
const fn is_turnkey_user_id(user_id: &str) -> bool {
    uuid::Uuid::try_parse(user_id).is_ok()
}

/// Deterministic, human-readable name for a sync factor's policy.
pub(super) fn sync_factor_policy_name(user_id: &str) -> String {
    format!("sync_factor_policy_{user_id}")
}

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

    /// Hardcoded literal matching: the deletion condition is security-critical, so
    /// pin its exact text. Update deliberately if the policy scope changes.
    #[test]
    fn sync_factor_deletion_condition_is_pinned() {
        // The parentheses is particularly critical here!
        assert_eq!(
            SYNC_FACTOR_POLICY_CONDITION,
            "activity.action == 'DELETE' && (activity.resource == 'CREDENTIAL' || \
             activity.resource == 'PRIVATE_KEY' || activity.resource == 'ORGANIZATION' \
             || activity.resource == 'USER')"
        );
    }

    #[test]
    fn sync_factor_policy_consensus_binds_single_user() {
        assert_eq!(
            sync_factor_policy_consensus("11111111-2222-3333-4444-555555555555")
                .as_deref(),
            Some("approvers.any(user, user.id == '11111111-2222-3333-4444-555555555555')")
        );
    }

    #[test]
    fn user_role_classify_maps_each_known_username() {
        assert_eq!(UserRole::classify("auth_user_main"), UserRole::Main);
        assert_eq!(UserRole::classify("break_glass_user"), UserRole::BreakGlass);
        assert_eq!(
            UserRole::classify("sync_factor_user_abc123"),
            UserRole::SyncFactor
        );
        assert_eq!(UserRole::classify("something_else"), UserRole::Unexpected);
    }

    /// Important to prevent breaking out of the policy syntax, and to reject ids
    /// that are not real Turnkey UUIDs.
    #[test]
    fn sync_factor_policy_consensus_rejects_malformed_user_id() {
        assert_eq!(sync_factor_policy_consensus(""), None);
        assert_eq!(
            sync_factor_policy_consensus("bad' || approvers.any(user, true) || 'x"),
            None
        );
        assert_eq!(sync_factor_policy_consensus("has space"), None);
        // Hex/hyphen characters but not a UUID layout.
        assert_eq!(sync_factor_policy_consensus("deadbeef"), None);
        assert_eq!(sync_factor_policy_consensus("----"), None);
        assert_eq!(
            sync_factor_policy_consensus("11111111-2222-3333-4444-5555555555"),
            None
        );
        // A well-formed UUID is accepted.
        assert!(
            sync_factor_policy_consensus("11111111-2222-3333-4444-555555555555")
                .is_some()
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
