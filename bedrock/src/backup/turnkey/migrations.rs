//! Turnkey account migrations.
//!
//! A migration reconciles one aspect of the user's Turnkey sub-organization
//! toward the desired state. [`run_migrations`] runs each registered migration
//! that can run with the available signers; any migration that requires the main
//! factor (when it was not provided) is deferred and reported so the caller can
//! re-invoke with the main factor. It fails fast on the first error.

use std::collections::HashSet;
use std::sync::Arc;

use turnkey_client::generated::immutable::activity::v1::oauth_provider_params_v2::TokenOrClaims;
use turnkey_client::generated::immutable::activity::v1::{
    OauthProviderParamsV2, OidcClaims,
};

use crate::primitives::config::BedrockEnvironment;
use crate::primitives::KeypairSigner;
use crate::{error, info, warn};

use super::api::{failure_class, TurnkeyApi};
use super::error::TurnkeyApiError;
use super::policies::{
    AppleAudience, APPLE_ISSUER, APPLE_PROVIDER_NAME_PREFIX, AUTH_USER_MAIN_USERNAME,
};

/// Result of a `check_migrations` run.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Enum)]
pub enum TurnkeyMigrationOutcome {
    /// Every applicable migration completed (or was already satisfied).
    Completed,
    /// One or more migrations still need to run but require the main factor,
    /// which was not provided. Re-invoke with the main factor to apply them.
    MainFactorRequired {
        /// Human-friendly descriptions of the migrations awaiting the main factor.
        pending: Vec<String>,
    },
}

/// Internal outcome of a single migration run.
enum MigrationOutcome {
    /// The migration applied changes, described by `details`.
    Applied { details: Vec<String> },
    /// The migration was a no-op for the stated `reason`.
    Skipped { reason: String },
}

/// Context passed to each migration.
struct MigrationContext<'a> {
    suborganization_id: &'a str,
    environment: BedrockEnvironment,
    sync_factor: Arc<dyn KeypairSigner>,
    main_factor: Option<Arc<dyn KeypairSigner>>,
    api: &'a dyn TurnkeyApi,
}

/// A single reconciliation step against the Turnkey sub-organization.
#[async_trait::async_trait]
trait TurnkeyMigration: Send + Sync {
    /// Stable identifier used in logs.
    fn id(&self) -> &'static str;
    /// Human-friendly description of what the migration intends to do.
    fn description(&self) -> &'static str;
    /// Whether this migration needs the main factor signer to be present.
    fn requires_main_factor(&self) -> bool;
    /// Runs the migration against `ctx`.
    async fn run(
        &self,
        ctx: &MigrationContext<'_>,
    ) -> Result<MigrationOutcome, TurnkeyApiError>;
}

/// Ensures `auth_user_main` has an Apple OAuth provider for every required
/// audience.
///
/// If the user already has at least one Apple provider, the migration reuses its
/// `subject` and creates providers for any missing audiences via claims-based
/// `create_oauth_providers`. If the user has no Apple provider at all, it is a
/// no-op.
struct MigrationAppleAudience;

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
            return Ok(MigrationOutcome::Skipped {
                reason: "no Apple OAuth provider present".to_string(),
            });
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

        let missing: Vec<&AppleAudience> = ctx
            .environment
            .turnkey_policy()
            .apple_audiences
            .iter()
            .filter(|audience| !existing.contains(audience.client_id))
            .collect();

        if missing.is_empty() {
            return Ok(MigrationOutcome::Skipped {
                reason: "all required Apple audiences present".to_string(),
            });
        }

        let main_factor = ctx.main_factor.clone().ok_or_else(|| {
            TurnkeyApiError::Client("main factor unexpectedly missing".to_string())
        })?;
        let user_id = user.user_id.clone();
        let created: Vec<String> = missing
            .iter()
            .map(|audience| audience.label.to_string())
            .collect();
        let providers: Vec<OauthProviderParamsV2> = missing
            .iter()
            .map(|audience| OauthProviderParamsV2 {
                provider_name: format!(
                    "{APPLE_PROVIDER_NAME_PREFIX}{}",
                    audience.label
                ),
                token_or_claims: Some(TokenOrClaims::OidcClaims(OidcClaims {
                    iss: APPLE_ISSUER.to_string(),
                    sub: subject.clone(),
                    aud: audience.client_id.to_string(),
                })),
            })
            .collect();

        ctx.api
            .create_oauth_providers(
                ctx.suborganization_id,
                &user_id,
                providers,
                main_factor,
            )
            .await?;

        Ok(MigrationOutcome::Applied { details: created })
    }
}

/// Runs all registered migrations and returns the overall [`TurnkeyMigrationOutcome`].
///
/// Migrations that can run with the available signers run in order; migrations
/// that require the main factor when it is absent are deferred and reported.
/// Fails fast: the first error aborts the run and is returned.
///
/// # Errors
/// Returns [`TurnkeyApiError`] if a migration fails (transport, activity, parsing).
pub async fn run_migrations(
    suborganization_id: &str,
    sync_factor: Arc<dyn KeypairSigner>,
    main_factor: Option<Arc<dyn KeypairSigner>>,
    api: &dyn TurnkeyApi,
    environment: BedrockEnvironment,
) -> Result<TurnkeyMigrationOutcome, TurnkeyApiError> {
    let migrations: [Box<dyn TurnkeyMigration>; 1] = [Box::new(MigrationAppleAudience)];
    let mut pending_main_factor: Vec<String> = Vec::new();

    for migration in &migrations {
        if migration.requires_main_factor() && main_factor.is_none() {
            info!(
                "turnkey.migration.deferred migration={} reason=main_factor_required",
                migration.id()
            );
            pending_main_factor.push(migration.description().to_string());
            continue;
        }

        let ctx = MigrationContext {
            suborganization_id,
            environment,
            sync_factor: sync_factor.clone(),
            main_factor: main_factor.clone(),
            api,
        };

        match migration.run(&ctx).await {
            Ok(MigrationOutcome::Applied { details }) => {
                info!(
                    "turnkey.migration.applied migration={} changes={}",
                    migration.id(),
                    details.len()
                );
            }
            Ok(MigrationOutcome::Skipped { reason }) => {
                info!(
                    "turnkey.migration.skipped migration={} reason={reason}",
                    migration.id()
                );
            }
            Err(error) => {
                error!(
                    "turnkey.migration.failed migration={} class={}",
                    migration.id(),
                    failure_class(&error)
                );
                return Err(error);
            }
        }
    }

    if pending_main_factor.is_empty() {
        Ok(TurnkeyMigrationOutcome::Completed)
    } else {
        Ok(TurnkeyMigrationOutcome::MainFactorRequired {
            pending: pending_main_factor,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backup::turnkey::test::TestSigner;
    use std::sync::Mutex;
    use turnkey_client::generated::external::data::v1::User;

    const TEST_KEY: &str =
        "8b380767b1947c1c67da42dbc6929a9137202bab770bca2ddcdeaa1dbdd505b8";

    /// Scripted [`TurnkeyApi`] returning static users and recording created providers.
    struct MockApi {
        users: Vec<User>,
        created: Mutex<Vec<(String, Vec<OauthProviderParamsV2>)>>,
    }

    impl MockApi {
        fn new(users: Vec<User>) -> Self {
            Self {
                users,
                created: Mutex::new(Vec::new()),
            }
        }
    }

    #[async_trait::async_trait]
    impl TurnkeyApi for MockApi {
        async fn resolve_suborganization_id(
            &self,
            _auth_proxy_config_id: &str,
            _public_key_hex: &str,
        ) -> Result<Option<String>, TurnkeyApiError> {
            Ok(Some("suborg-mock".to_string()))
        }

        async fn get_users(
            &self,
            _suborganization_id: &str,
            _stamper: Arc<dyn KeypairSigner>,
        ) -> Result<Vec<User>, TurnkeyApiError> {
            Ok(self.users.clone())
        }

        async fn create_oauth_providers(
            &self,
            _suborganization_id: &str,
            user_id: &str,
            providers: Vec<OauthProviderParamsV2>,
            _stamper: Arc<dyn KeypairSigner>,
        ) -> Result<(), TurnkeyApiError> {
            self.created
                .lock()
                .unwrap()
                .push((user_id.to_string(), providers));
            Ok(())
        }
    }

    /// Builds a `User` from a static JSON payload (exercises SDK deserialization).
    fn user_from_json(value: serde_json::Value) -> User {
        serde_json::from_value(value).unwrap()
    }

    fn main_user_with_apple(audiences: &[&str], subject: &str) -> User {
        let providers: Vec<serde_json::Value> = audiences
            .iter()
            .map(|aud| {
                serde_json::json!({
                    "providerId": format!("p-{aud}"),
                    "providerName": "apple",
                    "issuer": APPLE_ISSUER,
                    "audience": aud,
                    "subject": subject,
                })
            })
            .collect();
        user_from_json(serde_json::json!({
            "userId": "user-main",
            "userName": AUTH_USER_MAIN_USERNAME,
            "oauthProviders": providers,
        }))
    }

    fn signer() -> Arc<dyn KeypairSigner> {
        Arc::new(TestSigner::from_hex(TEST_KEY))
    }

    async fn run_with_main(
        mock: &MockApi,
    ) -> Result<TurnkeyMigrationOutcome, TurnkeyApiError> {
        run_migrations(
            "suborg-1",
            signer(),
            Some(signer()),
            mock,
            BedrockEnvironment::Staging,
        )
        .await
    }

    fn staging_audiences() -> Vec<&'static str> {
        BedrockEnvironment::Staging
            .turnkey_policy()
            .apple_audiences
            .iter()
            .map(|audience| audience.client_id)
            .collect()
    }

    #[tokio::test]
    async fn skips_when_no_apple_provider() {
        let user = user_from_json(serde_json::json!({
            "userId": "user-main",
            "userName": AUTH_USER_MAIN_USERNAME,
            "oauthProviders": [{
                "providerId": "p-g",
                "providerName": "google",
                "issuer": "https://accounts.google.com",
                "audience": "aud-g",
                "subject": "sub-g",
            }],
        }));
        let mock = MockApi::new(vec![user]);

        let outcome = run_with_main(&mock).await.unwrap();

        assert_eq!(outcome, TurnkeyMigrationOutcome::Completed);
        assert!(mock.created.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn skips_when_all_audiences_present() {
        let auds = staging_audiences();
        let mock = MockApi::new(vec![main_user_with_apple(&auds, "sub-1")]);

        let outcome = run_with_main(&mock).await.unwrap();

        assert_eq!(outcome, TurnkeyMigrationOutcome::Completed);
        assert!(mock.created.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn creates_only_missing_audiences() {
        let auds = staging_audiences();
        // Only the first audience is present; the other two must be created.
        let mock = MockApi::new(vec![main_user_with_apple(&auds[..1], "sub-apple")]);

        let outcome = run_with_main(&mock).await.unwrap();
        assert_eq!(outcome, TurnkeyMigrationOutcome::Completed);

        let created = {
            let guard = mock.created.lock().unwrap();
            guard.clone()
        };
        assert_eq!(created.len(), 1);
        let (user_id, providers) = &created[0];
        assert_eq!(user_id, "user-main");
        assert_eq!(providers.len(), 2);

        let created_auds: HashSet<&str> = providers
            .iter()
            .filter_map(|provider| match &provider.token_or_claims {
                Some(TokenOrClaims::OidcClaims(claims)) => Some(claims.aud.as_str()),
                _ => None,
            })
            .collect();
        assert!(created_auds.contains(auds[1]));
        assert!(created_auds.contains(auds[2]));
        // All created providers reuse the existing Apple subject and issuer.
        for provider in providers {
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

    #[tokio::test]
    async fn errors_when_main_user_missing() {
        let other = user_from_json(serde_json::json!({
            "userId": "user-other",
            "userName": "someone_else",
            "oauthProviders": [],
        }));
        let mock = MockApi::new(vec![other]);

        let result = run_with_main(&mock).await;

        assert!(matches!(result, Err(TurnkeyApiError::MainUserNotFound)));
    }

    #[tokio::test]
    async fn reports_main_factor_required_when_absent() {
        let mock = MockApi::new(vec![main_user_with_apple(&[], "sub-1")]);

        let outcome = run_migrations(
            "suborg-1",
            signer(),
            None,
            &mock,
            BedrockEnvironment::Staging,
        )
        .await
        .unwrap();

        assert_eq!(
            outcome,
            TurnkeyMigrationOutcome::MainFactorRequired {
                pending: vec![MigrationAppleAudience.description().to_string()],
            }
        );
        assert!(mock.created.lock().unwrap().is_empty());
    }
}
