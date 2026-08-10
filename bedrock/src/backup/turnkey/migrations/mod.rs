#![doc = include_str!("README.md")]

use crate::primitives::config::BedrockEnvironment;
use crate::{error, info};

use super::api::{MainFactor, SyncFactor, TurnkeyApiClient};
use super::error::TurnkeyApiError;

mod apple_audience;
mod sync_factor_policy;

use apple_audience::MigrationAppleAudience;
use sync_factor_policy::MigrationSyncFactorPolicy;

/// Every Turnkey migration, in the order they are applied.
///
/// Single source of truth for which migrations exist. To add one, create a
/// module under `migrations/`, implement [`TurnkeyMigration`], and append it here.
///
/// The list fails fast on the first error, so order first cheaper migrations, more likely
/// to be skipped, or the ones not requiring a Main Factor.
pub(super) const MIGRATIONS: &[&dyn TurnkeyMigration] =
    &[&MigrationAppleAudience, &MigrationSyncFactorPolicy];

// TODO Migrations:
// 1. Ensure `auth_user_main` is the only one in the root quorum (housekeeping)
// 2. Ensure break glass user exists and has the correct policy
// 3. Ensure max number of sync factor users and policies (port over from Android)

/// Global result from running the entire set of migrations.
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
pub(super) enum MigrationOutcome {
    /// The migration applied changes, described by `details`.
    Applied { details: Vec<String> },
    /// The migration was a no-op. This is a success case.
    Skipped,
    /// Changes are required but the main factor was absent, so nothing was
    /// applied. Re-invoke with the main factor to apply them.
    MainFactorRequired,
}

/// Context passed to each migration.
pub(super) struct MigrationContext<'a> {
    suborganization_id: &'a str,
    environment: BedrockEnvironment,
    sync_factor: SyncFactor<'a>,
    main_factor: Option<MainFactor<'a>>,
    api: &'a TurnkeyApiClient,
}

/// A single reconciliation step against the Turnkey sub-organization.
#[async_trait::async_trait]
pub(super) trait TurnkeyMigration: Send + Sync {
    /// Stable identifier used in logs.
    fn id(&self) -> &'static str;
    /// Human-friendly description of what the migration intends to do.
    fn description(&self) -> &'static str;
    /// Runs the migration against `ctx`.
    ///
    /// Implementations decide what (if any) work is needed using the sync factor
    /// (reads). If changes are required but `ctx.main_factor` is absent, return
    /// [`MigrationOutcome::MainFactorRequired`] instead of applying.
    async fn run(
        &self,
        ctx: &MigrationContext<'_>,
    ) -> Result<MigrationOutcome, TurnkeyApiError>;
}

/// Runs the given migrations in order and returns the overall
/// [`TurnkeyMigrationOutcome`].
///
/// Production callers pass [`MIGRATIONS`]; tests pass a scripted list.
///
/// # Errors
/// Returns [`TurnkeyApiError`] if a migration fails (transport, activity, parsing).
pub(super) async fn run_migration_list(
    migrations: &[&dyn TurnkeyMigration],
    suborganization_id: &str,
    sync_factor: SyncFactor<'_>,
    main_factor: Option<MainFactor<'_>>,
    api: &TurnkeyApiClient,
    environment: BedrockEnvironment,
) -> Result<TurnkeyMigrationOutcome, TurnkeyApiError> {
    let mut pending_main_factor: Vec<String> = Vec::new();

    for migration in migrations {
        let ctx = MigrationContext {
            suborganization_id,
            environment,
            sync_factor,
            main_factor,
            api,
        };

        match migration.run(&ctx).await {
            Ok(MigrationOutcome::Applied { details }) => {
                info!(
                    "turnkey.migration.applied migration={} changes=[{}]",
                    migration.id(),
                    details.join(", ")
                );
            }
            Ok(MigrationOutcome::Skipped) => {}
            Ok(MigrationOutcome::MainFactorRequired) => {
                info!(
                    "turnkey.migration.deferred migration={} reason=main_factor_required",
                    migration.id()
                );
                pending_main_factor.push(migration.description().to_string());
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
    use crate::primitives::P256Signer;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

    fn signer() -> P256Signer {
        P256Signer::verify(Arc::new(TestSigner::new())).unwrap()
    }

    /// What a [`FakeMigration`] pretends its plan is.
    enum Behavior {
        /// No changes needed, regardless of the signers present.
        NoWork,
        /// Changes needed: applies when the main factor is present, otherwise
        /// reports [`MigrationOutcome::MainFactorRequired`].
        NeedsWork,
        /// Fails while running.
        Fail,
    }

    struct FakeMigration {
        id: &'static str,
        behavior: Behavior,
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
        async fn run(
            &self,
            ctx: &MigrationContext<'_>,
        ) -> Result<MigrationOutcome, TurnkeyApiError> {
            self.ran.store(true, Ordering::SeqCst);
            match self.behavior {
                Behavior::NoWork => Ok(MigrationOutcome::Skipped),
                Behavior::NeedsWork if ctx.main_factor.is_some() => {
                    Ok(MigrationOutcome::Applied {
                        details: vec!["change".to_string()],
                    })
                }
                Behavior::NeedsWork => Ok(MigrationOutcome::MainFactorRequired),
                Behavior::Fail => Err(TurnkeyApiError::MainUserNotFound),
            }
        }
    }

    async fn run_fakes(
        migrations: &[&dyn TurnkeyMigration],
        with_main_factor: bool,
    ) -> Result<TurnkeyMigrationOutcome, TurnkeyApiError> {
        let api = TurnkeyApiClient::new();
        let sync_factor = signer();
        let main_factor = with_main_factor.then(signer);
        run_migration_list(
            migrations,
            "suborg-1",
            SyncFactor(&sync_factor),
            main_factor.as_ref().map(MainFactor),
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
            behavior: Behavior::NeedsWork,
            ran: first.clone(),
        };
        let b = FakeMigration {
            id: "b",
            behavior: Behavior::NoWork,
            ran: second.clone(),
        };
        let migrations: [&dyn TurnkeyMigration; 2] = [&a, &b];

        let outcome = run_fakes(&migrations, true).await.unwrap();

        assert_eq!(outcome, TurnkeyMigrationOutcome::Completed);
        assert!(first.load(Ordering::SeqCst));
        assert!(second.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn no_op_migration_does_not_require_main_factor() {
        let ran = Arc::new(AtomicBool::new(false));
        let noop = FakeMigration {
            id: "noop",
            behavior: Behavior::NoWork,
            ran: ran.clone(),
        };
        let migrations: [&dyn TurnkeyMigration; 1] = [&noop];

        // No main factor provided, yet a no-op migration must still complete
        // rather than demand it.
        let outcome = run_fakes(&migrations, false).await.unwrap();

        assert_eq!(outcome, TurnkeyMigrationOutcome::Completed);
        assert!(ran.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn defers_needed_migration_when_main_factor_absent() {
        let ran = Arc::new(AtomicBool::new(false));
        let needs_main = FakeMigration {
            id: "needs_main",
            behavior: Behavior::NeedsWork,
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
        // The migration still runs so it can decide whether work is needed.
        assert!(ran.load(Ordering::SeqCst));
    }

    /// Tests that even if two migrations require Main Factor but another one doesn't,
    /// the one requiring a Sync Factor still runs.
    #[tokio::test]
    async fn accumulates_all_deferrals_and_continues() {
        let after_ran = Arc::new(AtomicBool::new(false));
        let first = FakeMigration {
            id: "first",
            behavior: Behavior::NeedsWork,
            ran: Arc::new(AtomicBool::new(false)),
        };
        let second = FakeMigration {
            id: "second",
            behavior: Behavior::NeedsWork,
            ran: Arc::new(AtomicBool::new(false)),
        };
        let after = FakeMigration {
            id: "after",
            behavior: Behavior::NoWork,
            ran: after_ran.clone(),
        };
        let migrations: [&dyn TurnkeyMigration; 3] = [&first, &second, &after];

        let outcome = run_fakes(&migrations, false).await.unwrap();

        let TurnkeyMigrationOutcome::MainFactorRequired { pending } = outcome else {
            panic!("expected MainFactorRequired, got {outcome:?}");
        };
        assert_eq!(pending.len(), 2);
        assert!(after_ran.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn fails_fast_and_skips_remaining() {
        let second = Arc::new(AtomicBool::new(false));
        let boom = FakeMigration {
            id: "boom",
            behavior: Behavior::Fail,
            ran: Arc::new(AtomicBool::new(false)),
        };
        let after = FakeMigration {
            id: "after",
            behavior: Behavior::NeedsWork,
            ran: second.clone(),
        };
        let migrations: [&dyn TurnkeyMigration; 2] = [&boom, &after];

        let result = run_fakes(&migrations, true).await;

        assert!(matches!(result, Err(TurnkeyApiError::MainUserNotFound)));
        assert!(!second.load(Ordering::SeqCst));
    }
}
