//! Turnkey account migrations.
//!
//! Each migration's decision logic is a **pure** function (fetched data in, a
//! plan out) so it can be unit-tested directly with static payloads. The
//! migration's `run` is thin I/O glue around that pure core. [`run_migrations`]
//! runs each migration that can run with the available signers; migrations that
//! require the main factor (when it was not provided) are deferred and reported
//! so the caller can re-invoke with it. It fails fast on the first error.

use std::collections::HashSet;
use std::sync::Arc;

use turnkey_client::generated::external::data::v1::User;
use turnkey_client::generated::immutable::activity::v1::oauth_provider_params_v2::TokenOrClaims;
use turnkey_client::generated::immutable::activity::v1::{
    OauthProviderParamsV2, OidcClaims,
};

use crate::primitives::config::BedrockEnvironment;
use crate::primitives::KeypairSigner;
use crate::{error, info, warn};

use super::api::{failure_class, TurnkeyApiClient};
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
    api: &'a TurnkeyApiClient,
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

/// The action the Apple-audience migration should take, computed purely from the
/// sub-organization's users.
enum AppleAudiencePlan {
    /// Nothing to do; carries the reason.
    Skip(&'static str),
    /// Create these OAuth providers on the given user.
    Create {
        user_id: String,
        providers: Vec<OauthProviderParamsV2>,
    },
}

/// Computes the Apple-audience plan from the sub-org's users (pure; no I/O).
///
/// If `auth_user_main` already has at least one Apple provider, reuses its
/// `subject` and plans providers for any missing required audiences. If it has no
/// Apple provider at all, the plan is a no-op.
///
/// # Errors
/// Returns [`TurnkeyApiError::MainUserNotFound`] if `auth_user_main` is absent.
fn plan_apple_audience(
    users: Vec<User>,
    environment: BedrockEnvironment,
) -> Result<AppleAudiencePlan, TurnkeyApiError> {
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
        return Ok(AppleAudiencePlan::Skip("no Apple OAuth provider present"));
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
        .turnkey_policy()
        .apple_audiences
        .iter()
        .filter(|audience| !existing.contains(audience.client_id))
        .collect();

    if missing.is_empty() {
        return Ok(AppleAudiencePlan::Skip(
            "all required Apple audiences present",
        ));
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

    Ok(AppleAudiencePlan::Create {
        user_id: user.user_id,
        providers,
    })
}

/// Ensures `auth_user_main` has an Apple OAuth provider for every required
/// audience via claims-based `create_oauth_providers`.
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

        match plan_apple_audience(users, ctx.environment)? {
            AppleAudiencePlan::Skip(reason) => Ok(MigrationOutcome::Skipped {
                reason: reason.to_string(),
            }),
            AppleAudiencePlan::Create { user_id, providers } => {
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

/// Runs all registered migrations and returns the overall [`TurnkeyMigrationOutcome`].
///
/// # Errors
/// Returns [`TurnkeyApiError`] if a migration fails (transport, activity, parsing).
pub async fn run_migrations(
    suborganization_id: &str,
    sync_factor: Arc<dyn KeypairSigner>,
    main_factor: Option<Arc<dyn KeypairSigner>>,
    api: &TurnkeyApiClient,
    environment: BedrockEnvironment,
) -> Result<TurnkeyMigrationOutcome, TurnkeyApiError> {
    let migrations: [Box<dyn TurnkeyMigration>; 1] = [Box::new(MigrationAppleAudience)];
    run_migration_list(
        &migrations,
        suborganization_id,
        sync_factor,
        main_factor,
        api,
        environment,
    )
    .await
}

/// Runs a specific list of migrations. Migrations that can run with the available
/// signers run in order; those requiring the main factor when it is absent are
/// deferred and reported. Fails fast on the first error.
async fn run_migration_list(
    migrations: &[Box<dyn TurnkeyMigration>],
    suborganization_id: &str,
    sync_factor: Arc<dyn KeypairSigner>,
    main_factor: Option<Arc<dyn KeypairSigner>>,
    api: &TurnkeyApiClient,
    environment: BedrockEnvironment,
) -> Result<TurnkeyMigrationOutcome, TurnkeyApiError> {
    let mut pending_main_factor: Vec<String> = Vec::new();

    for migration in migrations {
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
    use serde_json::json;
    use std::sync::atomic::{AtomicBool, Ordering};

    const TEST_KEY: &str =
        "8b380767b1947c1c67da42dbc6929a9137202bab770bca2ddcdeaa1dbdd505b8";

    fn signer() -> Arc<dyn KeypairSigner> {
        Arc::new(TestSigner::from_hex(TEST_KEY))
    }

    fn user_from_json(value: serde_json::Value) -> User {
        serde_json::from_value(value).unwrap()
    }

    fn staging_audiences() -> Vec<&'static str> {
        BedrockEnvironment::Staging
            .turnkey_policy()
            .apple_audiences
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

    // ---- Pure planning tests (no async, no I/O) ----

    #[test]
    fn plan_skips_when_no_apple_provider() {
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
            plan_apple_audience(users, BedrockEnvironment::Staging),
            Ok(AppleAudiencePlan::Skip(_))
        ));
    }

    #[test]
    fn plan_skips_when_all_audiences_present() {
        let auds = staging_audiences();
        let users = vec![main_user_with_apple(&auds, "sub-1")];

        assert!(matches!(
            plan_apple_audience(users, BedrockEnvironment::Staging),
            Ok(AppleAudiencePlan::Skip(_))
        ));
    }

    #[test]
    fn plan_creates_only_missing_audiences() {
        let auds = staging_audiences();
        // Only the first audience is present; the other two must be created.
        let users = vec![main_user_with_apple(&auds[..1], "sub-apple")];

        let AppleAudiencePlan::Create { user_id, providers } =
            plan_apple_audience(users, BedrockEnvironment::Staging).unwrap()
        else {
            panic!("expected Create plan");
        };

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
    fn plan_errors_when_main_user_missing() {
        let users = vec![user_from_json(json!({
            "userId": "user-other",
            "userName": "someone_else",
            "oauthProviders": [],
        }))];

        assert!(matches!(
            plan_apple_audience(users, BedrockEnvironment::Staging),
            Err(TurnkeyApiError::MainUserNotFound)
        ));
    }

    // ---- Orchestration tests (fake migrations, no I/O) ----

    /// Canned result for a [`FakeMigration`].
    enum FakeResult {
        Applied,
        Skipped,
        Fail,
    }

    /// A migration with scripted behaviour that records whether it ran.
    struct FakeMigration {
        id: &'static str,
        requires_main: bool,
        result: FakeResult,
        ran: Arc<AtomicBool>,
    }

    #[async_trait::async_trait]
    impl TurnkeyMigration for FakeMigration {
        fn id(&self) -> &'static str {
            self.id
        }
        fn description(&self) -> &'static str {
            "fake migration"
        }
        fn requires_main_factor(&self) -> bool {
            self.requires_main
        }
        async fn run(
            &self,
            _ctx: &MigrationContext<'_>,
        ) -> Result<MigrationOutcome, TurnkeyApiError> {
            self.ran.store(true, Ordering::SeqCst);
            match self.result {
                FakeResult::Applied => Ok(MigrationOutcome::Applied {
                    details: vec!["change".to_string()],
                }),
                FakeResult::Skipped => Ok(MigrationOutcome::Skipped {
                    reason: "noop".to_string(),
                }),
                FakeResult::Fail => Err(TurnkeyApiError::MainUserNotFound),
            }
        }
    }

    async fn run_fakes(
        migrations: Vec<Box<dyn TurnkeyMigration>>,
        with_main_factor: bool,
    ) -> Result<TurnkeyMigrationOutcome, TurnkeyApiError> {
        let api = TurnkeyApiClient::new();
        let main_factor = with_main_factor.then(signer);
        run_migration_list(
            &migrations,
            "suborg-1",
            signer(),
            main_factor,
            &api,
            BedrockEnvironment::Staging,
        )
        .await
    }

    #[tokio::test]
    async fn completes_when_all_migrations_run() {
        let first = Arc::new(AtomicBool::new(false));
        let second = Arc::new(AtomicBool::new(false));
        let migrations: Vec<Box<dyn TurnkeyMigration>> = vec![
            Box::new(FakeMigration {
                id: "a",
                requires_main: false,
                result: FakeResult::Applied,
                ran: first.clone(),
            }),
            Box::new(FakeMigration {
                id: "b",
                requires_main: true,
                result: FakeResult::Skipped,
                ran: second.clone(),
            }),
        ];

        let outcome = run_fakes(migrations, true).await.unwrap();

        assert_eq!(outcome, TurnkeyMigrationOutcome::Completed);
        assert!(first.load(Ordering::SeqCst));
        assert!(second.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn defers_main_factor_migration_when_absent() {
        let ran = Arc::new(AtomicBool::new(false));
        let migrations: Vec<Box<dyn TurnkeyMigration>> =
            vec![Box::new(FakeMigration {
                id: "needs_main",
                requires_main: true,
                result: FakeResult::Applied,
                ran: ran.clone(),
            })];

        let outcome = run_fakes(migrations, false).await.unwrap();

        assert_eq!(
            outcome,
            TurnkeyMigrationOutcome::MainFactorRequired {
                pending: vec!["fake migration".to_string()],
            }
        );
        assert!(!ran.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn fails_fast_and_skips_remaining() {
        let second = Arc::new(AtomicBool::new(false));
        let migrations: Vec<Box<dyn TurnkeyMigration>> = vec![
            Box::new(FakeMigration {
                id: "boom",
                requires_main: false,
                result: FakeResult::Fail,
                ran: Arc::new(AtomicBool::new(false)),
            }),
            Box::new(FakeMigration {
                id: "after",
                requires_main: false,
                result: FakeResult::Applied,
                ran: second.clone(),
            }),
        ];

        let result = run_fakes(migrations, true).await;

        assert!(matches!(result, Err(TurnkeyApiError::MainUserNotFound)));
        assert!(!second.load(Ordering::SeqCst));
    }
}
