//! Turnkey account migrations. The purpose is to check the state of a user's
//! Turnkey account to ensure it is correct and up-to-date.

use std::sync::Arc;

use crate::primitives::config::BedrockEnvironment;
use crate::primitives::KeypairSigner;
use crate::{error, info};

use super::api::TurnkeyApiClient;
use super::error::TurnkeyApiError;

mod apple_audience;

use apple_audience::MigrationAppleAudience;

/// Every Turnkey migration, in the order they are applied.
///
/// Single source of truth for which migrations exist. To add one, create a
/// module under `migrations/`, implement [`TurnkeyMigration`], and append it here.
const MIGRATIONS: &[&dyn TurnkeyMigration] = &[&MigrationAppleAudience];

// TODO Migrations:
// 1. Ensure `auth_user_main` is the only one in the root quorum (housekeeping)
// 2. Ensure break glass user exists and has the correct policy
// 3. Ensure all sync factors have the right deletion policy
// 4. Ensure max number of sync factor users and policies (port over from Android)

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
    run_migration_list(
        MIGRATIONS,
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
    migrations: &[&dyn TurnkeyMigration],
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
                    "turnkey.migration.failed migration={} err={error}",
                    migration.id()
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
    use std::sync::atomic::{AtomicBool, Ordering};

    fn signer() -> Arc<dyn KeypairSigner> {
        Arc::new(TestSigner::new())
    }

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
        migrations: &[&dyn TurnkeyMigration],
        with_main_factor: bool,
    ) -> Result<TurnkeyMigrationOutcome, TurnkeyApiError> {
        let api = TurnkeyApiClient::new();
        let main_factor = with_main_factor.then(signer);
        run_migration_list(
            migrations,
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
        let a = FakeMigration {
            id: "a",
            requires_main: false,
            result: FakeResult::Applied,
            ran: first.clone(),
        };
        let b = FakeMigration {
            id: "b",
            requires_main: true,
            result: FakeResult::Skipped,
            ran: second.clone(),
        };
        let migrations: [&dyn TurnkeyMigration; 2] = [&a, &b];

        let outcome = run_fakes(&migrations, true).await.unwrap();

        assert_eq!(outcome, TurnkeyMigrationOutcome::Completed);
        assert!(first.load(Ordering::SeqCst));
        assert!(second.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn defers_main_factor_migration_when_absent() {
        let ran = Arc::new(AtomicBool::new(false));
        let needs_main = FakeMigration {
            id: "needs_main",
            requires_main: true,
            result: FakeResult::Applied,
            ran: ran.clone(),
        };
        let migrations: [&dyn TurnkeyMigration; 1] = [&needs_main];

        let outcome = run_fakes(&migrations, false).await.unwrap();

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
        let boom = FakeMigration {
            id: "boom",
            requires_main: false,
            result: FakeResult::Fail,
            ran: Arc::new(AtomicBool::new(false)),
        };
        let after = FakeMigration {
            id: "after",
            requires_main: false,
            result: FakeResult::Applied,
            ran: second.clone(),
        };
        let migrations: [&dyn TurnkeyMigration; 2] = [&boom, &after];

        let result = run_fakes(&migrations, true).await;

        assert!(matches!(result, Err(TurnkeyApiError::MainUserNotFound)));
        assert!(!second.load(Ordering::SeqCst));
    }
}
