//! See [`MigrationAppleAudience`]

use std::collections::HashSet;

use turnkey_client::generated::external::data::v1::User;
use turnkey_client::generated::immutable::activity::v1::oauth_provider_params_v2::TokenOrClaims;
use turnkey_client::generated::immutable::activity::v1::{
    OauthProviderParamsV2, OidcClaims,
};

use crate::primitives::config::BedrockEnvironment;

use super::super::error::TurnkeyApiError;
use super::super::policies::{AppleAudience, APPLE_ISSUER, AUTH_USER_MAIN_USERNAME};
use super::{MigrationContext, MigrationOutcome, TurnkeyMigration};

/// If the user has a "Sign in with Apple" configured, ensure `auth_user_main` has
/// an Apple OAuth provider for every required audience.
///
/// The reason why multiple audiences must exist for Apple OIDC is because each client
/// has its own audience. World App has the iOS App, the World ID App and the Android App,
/// each with its own `aud`. Particularly for the Android App, the login is done via a webview
/// as there's no native SDK. This means that all Android clients use the same audience.
///
/// NOTE that Apple assigns the same `sub` to all Apple OIDC tokens under the same developer
/// account.
///
/// If the user already has at least one Apple provider, its `subject` is reused
/// and all remaining providers are created. If the user has no Apple provider at all, this is a no-op.
///
/// # Main Factor
/// If operations need to be executed, this migration REQUIRES a Main Factor.
pub(super) struct MigrationAppleAudience;

#[async_trait::async_trait]
impl TurnkeyMigration for MigrationAppleAudience {
    fn id(&self) -> &'static str {
        "apple_audience"
    }

    fn description(&self) -> &'static str {
        "Enable Sign in with Apple for all iOS and Android apps."
    }

    async fn run(
        &self,
        ctx: &MigrationContext<'_>,
    ) -> Result<MigrationOutcome, TurnkeyApiError> {
        let users = ctx
            .api
            .get_users(ctx.suborganization_id, ctx.sync_factor)
            .await?;

        let plan = plan(users, ctx.environment)?;

        match plan {
            Plan::SkipNoAppleProvider | Plan::SkipReady => {
                crate::info!("apple_audience skipped: {plan}");
                Ok(MigrationOutcome::Skipped)
            }
            Plan::Create { user_id, providers } => {
                let Some(main_factor) = ctx.main_factor else {
                    return Ok(MigrationOutcome::MainFactorRequired);
                };
                let details: Vec<String> =
                    providers.iter().map(|p| p.provider_name.clone()).collect();
                ctx.api
                    .create_oauth_providers(
                        ctx.suborganization_id,
                        &user_id,
                        providers,
                        main_factor,
                    )
                    .await?;
                Ok(MigrationOutcome::Applied { details })
            }
        }
    }
}

/// The action to take, computed purely from the sub-organization's users.
enum Plan {
    /// Nothing to do; the user has no Apple provider.
    SkipNoAppleProvider,
    /// Nothing to do; all providers already set.
    SkipReady,
    /// Create these OAuth providers on the given user.
    Create {
        user_id: String,
        providers: Vec<OauthProviderParamsV2>,
    },
}

impl std::fmt::Display for Plan {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SkipNoAppleProvider => {
                f.write_str("skip: user has no Apple provider")
            }
            Self::SkipReady => {
                f.write_str("skip: all providers are already configured")
            }
            Self::Create {
                user_id: _,
                providers,
            } => {
                write!(f, "create {} OAuth provider(s)", providers.len())
            }
        }
    }
}

/// Computes the plan from the sub-org's users (pure function).
///
/// # Errors
/// Returns [`TurnkeyApiError::MainUserNotFound`] if `auth_user_main` is absent.
fn plan(
    users: Vec<User>,
    environment: BedrockEnvironment,
) -> Result<Plan, TurnkeyApiError> {
    let user = users
        .into_iter()
        .find(|user| user.user_name == AUTH_USER_MAIN_USERNAME)
        .ok_or(TurnkeyApiError::MainUserNotFound)?;

    let apple_providers: Vec<_> = user
        .oauth_providers
        .iter()
        .filter(|provider| provider.issuer == APPLE_ISSUER)
        .collect();

    let Some(first) = apple_providers.first() else {
        return Ok(Plan::SkipNoAppleProvider);
    };

    let subject = first.subject.clone();

    if apple_providers
        .iter()
        .any(|provider| provider.subject != subject)
    {
        crate::error!(
            "critical consistency error. user has Apple OIDCs with different `sub`s"
        );
        return Err(TurnkeyApiError::Consistency);
    }

    let existing: HashSet<&str> = apple_providers
        .iter()
        .map(|provider| provider.audience.as_str())
        .collect();

    let missing: Vec<&AppleAudience> = environment
        .turnkey_apple_audiences()
        .iter()
        .filter(|audience| !existing.contains(audience.client_id))
        .collect();

    if missing.is_empty() {
        return Ok(Plan::SkipReady);
    }

    let providers = missing
        .iter()
        .map(|audience| OauthProviderParamsV2 {
            provider_name: audience.provider_name.to_string(),
            token_or_claims: Some(TokenOrClaims::OidcClaims(OidcClaims {
                iss: APPLE_ISSUER.to_string(),
                sub: subject.clone(),
                aud: audience.client_id.to_string(),
            })),
        })
        .collect();

    Ok(Plan::Create {
        user_id: user.user_id,
        providers,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn user_from_json(value: serde_json::Value) -> User {
        serde_json::from_value(value).unwrap()
    }

    fn staging_audiences() -> Vec<&'static str> {
        BedrockEnvironment::Staging
            .turnkey_apple_audiences()
            .iter()
            .map(|audience| audience.client_id)
            .collect()
    }

    fn main_user_with_apple(audiences: &[&str], subject: &str) -> User {
        let providers: Vec<serde_json::Value> = audiences
            .iter()
            .map(|aud| {
                json!({
                    "providerId": format!("p-{aud}"),
                    "providerName": "apple",
                    "issuer": APPLE_ISSUER,
                    "audience": aud,
                    "subject": subject,
                })
            })
            .collect();
        user_from_json(json!({
            "userId": "user-main",
            "userName": AUTH_USER_MAIN_USERNAME,
            "oauthProviders": providers,
        }))
    }

    #[test]
    fn skips_when_no_apple_provider() {
        let users = vec![user_from_json(json!({
            "userId": "user-main",
            "userName": AUTH_USER_MAIN_USERNAME,
            "oauthProviders": [{
                "providerId": "p-g",
                "providerName": "google",
                "issuer": "https://accounts.google.com",
                "audience": "aud-g",
                "subject": "sub-g",
            }],
        }))];

        assert!(matches!(
            plan(users, BedrockEnvironment::Staging),
            Ok(Plan::SkipNoAppleProvider)
        ));
    }

    #[test]
    fn skips_when_all_audiences_present() {
        let auds = staging_audiences();
        let users = vec![main_user_with_apple(&auds, "sub-1")];

        assert!(matches!(
            plan(users, BedrockEnvironment::Staging),
            Ok(Plan::SkipReady)
        ));
    }

    /// Tests against explicitly hardcoded values
    #[test]
    fn production_plan_uses_production_audiences() {
        let users = vec![main_user_with_apple(&["org.worldcoin.insight"], "sub-prod")];

        let Plan::Create { providers, .. } =
            plan(users, BedrockEnvironment::Production).unwrap()
        else {
            panic!("expected Create plan");
        };

        let created: HashSet<&str> = providers
            .iter()
            .filter_map(|provider| match &provider.token_or_claims {
                Some(TokenOrClaims::OidcClaims(claims)) => Some(claims.aud.as_str()),
                _ => None,
            })
            .collect();
        assert_eq!(created, HashSet::from(["org.world.id", "app.world.apple"]));
    }

    #[test]
    fn creates_only_missing_audiences() {
        let auds = staging_audiences();
        // Only the first audience is present; every other one must be created.
        let users = vec![main_user_with_apple(&auds[..1], "sub-apple")];

        let Plan::Create { user_id, providers } =
            plan(users, BedrockEnvironment::Staging).unwrap()
        else {
            panic!("expected Create plan");
        };

        assert_eq!(user_id, "user-main");
        assert_eq!(providers.len(), auds.len() - 1);

        let created_auds: HashSet<&str> = providers
            .iter()
            .filter_map(|provider| match &provider.token_or_claims {
                Some(TokenOrClaims::OidcClaims(claims)) => Some(claims.aud.as_str()),
                _ => None,
            })
            .collect();
        for aud in &auds[1..] {
            assert!(created_auds.contains(aud));
        }

        for provider in &providers {
            let Some(TokenOrClaims::OidcClaims(claims)) = &provider.token_or_claims
            else {
                panic!("expected claims-based provider");
            };
            assert_eq!(claims.sub, "sub-apple"); // CRITICAL check
            assert_eq!(claims.iss, APPLE_ISSUER);
            assert!(provider.provider_name.starts_with("APPLE"));
        }
    }

    #[test]
    fn errors_when_main_user_missing() {
        let users = vec![user_from_json(json!({
            "userId": "user-other",
            "userName": "someone_else",
            "oauthProviders": [],
        }))];

        assert!(matches!(
            plan(users, BedrockEnvironment::Staging),
            Err(TurnkeyApiError::MainUserNotFound)
        ));
    }

    #[test]
    fn errors_when_account_has_multiple_apple_providers_with_different_sub() {
        let auds = staging_audiences();
        let users = vec![user_from_json(json!({
            "userId": "user-main",
            "userName": AUTH_USER_MAIN_USERNAME,
            "oauthProviders": [
                {
                    "providerId": "p-0",
                    "providerName": "apple",
                    "issuer": APPLE_ISSUER,
                    "audience": auds[0],
                    "subject": "sub-a",
                },
                {
                    "providerId": "p-1",
                    "providerName": "apple",
                    "issuer": APPLE_ISSUER,
                    "audience": auds[1],
                    "subject": "sub-b",
                },
            ],
        }))];

        assert!(matches!(
            plan(users, BedrockEnvironment::Staging),
            Err(TurnkeyApiError::Consistency)
        ));
    }

    /// The `providerName` is a convenience label. This test ensures that the migrations
    /// are run based on registered `aud`s, and any incorrect labels are ignored.
    ///
    /// Every required audience is present by `aud`, but the first provider
    /// carries a configured name bound to the wrong audience (reused/wrong
    /// label). The migration must still treat this as ready.
    #[test]
    fn completes_when_all_audiences_present_despite_reused_name() {
        let auds = BedrockEnvironment::Staging.turnkey_apple_audiences();
        assert!(auds.len() >= 2, "staging needs multiple audiences");

        let providers: Vec<serde_json::Value> = auds
            .iter()
            .enumerate()
            .map(|(i, audience)| {
                let provider_name = match i {
                    0 => auds[1].provider_name,   // reused name, wrong audience
                    1 => "legacy-apple-provider", // unique, non-configured name
                    _ => audience.provider_name,
                };
                json!({
                    "providerId": format!("p-{i}"),
                    "providerName": provider_name,
                    "issuer": APPLE_ISSUER,
                    "audience": audience.client_id,
                    "subject": "sub-apple",
                })
            })
            .collect();
        let users = vec![user_from_json(json!({
            "userId": "user-main",
            "userName": AUTH_USER_MAIN_USERNAME,
            "oauthProviders": providers,
        }))];

        assert!(matches!(
            plan(users, BedrockEnvironment::Staging),
            Ok(Plan::SkipReady)
        ));
    }
}
