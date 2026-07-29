//! Migration: ensure `auth_user_main` has an Apple OAuth provider for every
//! required audience.
//!
//! If the user already has at least one Apple provider, its `subject` is reused
//! and providers are created (claims-based) for any missing required audiences.
//! If the user has no Apple provider at all, this is a no-op.

use std::collections::HashSet;

use turnkey_client::generated::external::data::v1::User;
use turnkey_client::generated::immutable::activity::v1::oauth_provider_params_v2::TokenOrClaims;
use turnkey_client::generated::immutable::activity::v1::{
    OauthProviderParamsV2, OidcClaims,
};

use crate::primitives::config::BedrockEnvironment;
use crate::warn;

use super::super::error::TurnkeyApiError;
use super::super::policies::{
    AppleAudience, APPLE_ISSUER, APPLE_PROVIDER_NAME_PREFIX, AUTH_USER_MAIN_USERNAME,
};
use super::{MigrationContext, MigrationOutcome, TurnkeyMigration};

/// Ensures `auth_user_main` has an Apple OAuth provider for every required
/// audience via claims-based `create_oauth_providers`.
pub(super) struct MigrationAppleAudience;

#[async_trait::async_trait]
impl TurnkeyMigration for MigrationAppleAudience {
    fn id(&self) -> &'static str {
        "apple_audience"
    }

    fn description(&self) -> &'static str {
        "Register Sign in with Apple for the main user across all World app audiences"
    }

    fn requires_main_factor(&self) -> bool {
        true
    }

    async fn run(
        &self,
        ctx: &MigrationContext<'_>,
    ) -> Result<MigrationOutcome, TurnkeyApiError> {
        let users = ctx
            .api
            .get_users(ctx.suborganization_id, ctx.sync_factor.clone())
            .await?;

        match plan(users, ctx.environment)? {
            Plan::Skip(reason) => Ok(MigrationOutcome::Skipped {
                reason: reason.to_string(),
            }),
            Plan::Create { user_id, providers } => {
                let main_factor = ctx.main_factor.clone().ok_or_else(|| {
                    TurnkeyApiError::Client(
                        "main factor unexpectedly missing".to_string(),
                    )
                })?;
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
    /// Nothing to do; carries the reason.
    Skip(&'static str),
    /// Create these OAuth providers on the given user.
    Create {
        user_id: String,
        providers: Vec<OauthProviderParamsV2>,
    },
}

/// Computes the plan from the sub-org's users (pure; no I/O).
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
        return Ok(Plan::Skip("no Apple OAuth provider present"));
    };
    let subject = first.subject.clone();

    if apple_providers
        .iter()
        .any(|provider| provider.subject != subject)
    {
        warn!("turnkey.apple_audience.subject_mismatch");
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
        return Ok(Plan::Skip("all required Apple audiences present"));
    }

    let providers = missing
        .iter()
        .map(|audience| OauthProviderParamsV2 {
            provider_name: format!("{APPLE_PROVIDER_NAME_PREFIX}{}", audience.label),
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
            Ok(Plan::Skip(_))
        ));
    }

    #[test]
    fn skips_when_all_audiences_present() {
        let auds = staging_audiences();
        let users = vec![main_user_with_apple(&auds, "sub-1")];

        assert!(matches!(
            plan(users, BedrockEnvironment::Staging),
            Ok(Plan::Skip(_))
        ));
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
            assert_eq!(claims.sub, "sub-apple");
            assert_eq!(claims.iss, APPLE_ISSUER);
            assert!(provider
                .provider_name
                .starts_with(APPLE_PROVIDER_NAME_PREFIX));
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
}
