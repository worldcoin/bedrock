use super::wallet::permit2_approval::Permit2ApprovalMigration;
use super::wallet::safe_4337_module::Safe4337ModuleMigration;
use super::wallet_migration::{WalletMigration, WalletMigrationResult};
use crate::migration::controller::MigrationRunSummary;
use crate::migration::error::MigrationError;
use crate::migration::record_store::{
    MigrationRecord, MigrationRecordEntry, MigrationStatus, RecordStore,
};
use crate::primitives::key_value_store::DeviceKeyValueStore;
use crate::smart_account::SafeSmartAccount;
use chrono::{Duration, Utc};
use futures::future::join_all;
use std::sync::Arc;

/// Own namespace, so wallet records never collide with the native framework's.
const WALLET_KEY_PREFIX: &str = "migration:wallet:";

/// How long an in-flight submission is given to land.
///
/// Past this it is never going to mine, so retry. Without it, cold starts in
/// quick succession would exhaust [`MAX_ATTEMPTS`] within minutes.
const RESUBMIT_COOLDOWN_HOURS: i64 = 1;

/// Submissions observed to have failed before giving up, counted per gap.
///
/// Once spent, the next pass confirms via [`WalletMigration::end_state_holds`]
/// instead of submitting. Only accepted submissions count, so no number of
/// offline launches exhausts this.
const MAX_ATTEMPTS: i32 = 5;

/// Runs the migrations Bedrock owns.
///
/// Not exported over FFI; see the [module docs](super) for why it is separate
/// from [`MigrationController`](crate::migration::MigrationController).
pub struct WalletMigrationController {
    records: RecordStore,
    /// Runs first, alone. See [`Self::run`].
    prerequisite: Option<Arc<dyn WalletMigration>>,
    /// Run in parallel, once the prerequisite has converged.
    migrations: Vec<Arc<dyn WalletMigration>>,
}

impl WalletMigrationController {
    /// The default set. Migrations needing a Safe account are omitted when there
    /// is none.
    pub fn new(
        kv_store: Arc<dyn DeviceKeyValueStore>,
        safe_account: Option<Arc<SafeSmartAccount>>,
    ) -> Self {
        let Some(account) = safe_account else {
            return Self::with_migrations(kv_store, vec![]);
        };
        Self {
            records: RecordStore::new(kv_store, WALLET_KEY_PREFIX),
            // The 4337 repair relays a plain owner-signed `execTransaction`, so
            // it is the one migration that works on an unrepaired Safe — which
            // makes it everything else's prerequisite.
            prerequisite: Some(Arc::new(Safe4337ModuleMigration::new(account.clone()))),
            migrations: vec![Arc::new(Permit2ApprovalMigration::new(account))],
        }
    }

    /// A controller with migrations injected and no prerequisite, for tests.
    pub fn with_migrations(
        kv_store: Arc<dyn DeviceKeyValueStore>,
        migrations: Vec<Arc<dyn WalletMigration>>,
    ) -> Self {
        Self {
            records: RecordStore::new(kv_store, WALLET_KEY_PREFIX),
            prerequisite: None,
            migrations,
        }
    }

    /// Number of registered migrations, prerequisite included.
    #[must_use]
    pub fn len(&self) -> usize {
        self.migrations.len() + usize::from(self.prerequisite.is_some())
    }

    /// Whether any migrations are registered.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// One pass over every migration, in dependency order.
    ///
    /// The prerequisite goes first and alone; the rest run in parallel only
    /// once it has *converged*. Never fails — problems land in the summary.
    pub async fn run(&self) -> MigrationRunSummary {
        let mut summary = MigrationRunSummary {
            total: i32::try_from(self.len()).unwrap_or(i32::MAX),
            ..MigrationRunSummary::default()
        };

        if let Some(prerequisite) = &self.prerequisite {
            summary.merge_counts(&self.reconcile_one(prerequisite.as_ref()).await);

            if !self.has_converged(&prerequisite.migration_id()) {
                crate::warn!(
                    prerequisite = prerequisite.migration_id(),
                    blocked = self.migrations.len(),
                    "wallet_migration.dependents_blocked"
                );
                summary.skipped +=
                    i32::try_from(self.migrations.len()).unwrap_or(i32::MAX);
                return summary;
            }
        }

        let results = join_all(
            self.migrations
                .iter()
                .map(|m| self.reconcile_one(m.as_ref())),
        )
        .await;
        for s in results {
            summary.merge_counts(&s);
        }
        summary
    }

    /// Is this migration's end state recorded as reached?
    ///
    /// Reads the record the pass just wrote, so a submission made this launch
    /// does not count. Unreadable fails closed: dependents wait a launch.
    fn has_converged(&self, id: &str) -> bool {
        self.records
            .load::<MigrationRecord>(id)
            .is_ok_and(|r| matches!(r.status, MigrationStatus::Succeeded))
    }

    /// One migration's full lifecycle for this launch.
    ///
    /// Four steps in order: decide whether to look at all, look, fold the
    /// outcome into the record, persist it once.
    async fn reconcile_one(
        &self,
        migration: &dyn WalletMigration,
    ) -> MigrationRunSummary {
        let id = migration.migration_id();

        let mut record = match self.records.load::<MigrationRecord>(&id) {
            Ok(r) => r,
            Err(e) => return Self::storage_failure(&id, &e),
        };

        // Step 1: terminal migrations are never looked at again.
        if matches!(record.status, MigrationStatus::FailedTerminal) {
            return MigrationRunSummary::skipped();
        }

        // Step 2: every other launch observes. Submitting is what gets held
        // back — because the cap is spent, or because a submission has not had
        // its hour to land — and then the pass observes without acting.
        if record.attempts >= MAX_ATTEMPTS || Self::still_settling(&id, &record) {
            let summary = self.observe_only(&id, &mut record, migration).await;
            record.last_attempted_at = Some(Utc::now());
            if let Err(e) = self.records.save(&id, &record) {
                return Self::storage_failure(&id, &e);
            }
            return summary;
        }

        let started = Utc::now();
        let outcome = migration.reconcile().await;
        let duration_ms = (Utc::now() - started).num_milliseconds();

        // Step 3: turn that outcome into the new record state.
        let summary = Self::apply(&id, &mut record, outcome, duration_ms);
        record.last_attempted_at = Some(Utc::now());

        // Step 4: one write, after the pass. Nothing is persisted beforehand —
        // if the app dies mid-submission the next launch re-observes anyway,
        // and a lost write only costs an attempt count, which fails open.
        if let Err(e) = self.records.save(&id, &record) {
            return Self::storage_failure(&id, &e);
        }

        summary
    }

    /// Fold one reconcile outcome into the record: the whole state machine.
    ///
    /// No storage access and no clock beyond `Utc::now`, so every transition is
    /// readable and testable in one place.
    fn apply(
        id: &str,
        record: &mut MigrationRecord,
        outcome: Result<WalletMigrationResult, MigrationError>,
        duration_ms: i64,
    ) -> MigrationRunSummary {
        match outcome {
            // Reported as a success only if we submitted something, or every
            // fresh install shows a burst of successes it never earned.
            Ok(WalletMigrationResult::Converged) => {
                let did_work = record.attempts > 0;
                Self::mark_converged(id, record, false);
                if did_work {
                    MigrationRunSummary::succeeded()
                } else {
                    MigrationRunSummary::skipped()
                }
            }

            // Reaching here means the previous submission, if any, did not take
            // effect — the gap was still open. Stop once enough accepted
            // submissions have failed to show up on chain.
            Ok(WalletMigrationResult::Submitted { reference }) => {
                record.attempts += 1;
                record.started_at.get_or_insert_with(Utc::now);
                record.last_submission = reference;
                record.last_error_code = None;
                record.last_error_message = None;
                record.status = MigrationStatus::InProgress;

                crate::info!(
                    migration_id = id,
                    submission = record.last_submission.as_deref().unwrap_or("none"),
                    attempt = record.attempts,
                    max_attempts = MAX_ATTEMPTS,
                    duration_ms = duration_ms,
                    "wallet_migration.submitted"
                );
                MigrationRunSummary::pending()
            }

            Ok(WalletMigrationResult::Retry {
                error_code,
                error_message,
            }) => {
                crate::warn!(
                    migration_id = id,
                    error_code = error_code,
                    error_message = error_message,
                    duration_ms = duration_ms,
                    "wallet_migration.retry"
                );
                Self::mark_failed(
                    record,
                    MigrationStatus::FailedRetryable,
                    error_code,
                    error_message,
                );
                MigrationRunSummary::failed_retryable()
            }

            // The observation failed, which is evidence of nothing, so nothing
            // changes. Next launch looks again.
            Err(e) => {
                crate::error!(
                    migration_id = id,
                    error = format!("{e:?}"),
                    duration_ms = duration_ms,
                    "wallet_migration.observe_failed"
                );
                MigrationRunSummary::skipped()
            }
        }
    }

    /// Look without acting.
    ///
    /// Used whenever submitting is not allowed. The chain still gets read every
    /// launch, so work that landed is noticed immediately.
    async fn observe_only(
        &self,
        id: &str,
        record: &mut MigrationRecord,
        migration: &dyn WalletMigration,
    ) -> MigrationRunSummary {
        match migration.end_state_holds().await {
            // It landed. True whether we were waiting on it or had run out of
            // attempts — either way the work is done.
            Ok(true) => {
                Self::mark_converged(id, record, true);
                MigrationRunSummary::succeeded()
            }

            // Still a gap and no attempts left: confirmed dead. Nothing was
            // submitted to reach this verdict.
            Ok(false) if record.attempts >= MAX_ATTEMPTS => {
                crate::error!(
                    migration_id = id,
                    reason = "never_landed",
                    attempts = record.attempts,
                    submission = record.last_submission.as_deref().unwrap_or("none"),
                    "wallet_migration.gave_up"
                );
                Self::mark_failed(
                    record,
                    MigrationStatus::FailedTerminal,
                    "NEVER_LANDED".to_string(),
                    format!(
                        "{MAX_ATTEMPTS} submissions did not take effect, giving up"
                    ),
                );
                MigrationRunSummary::failed_terminal()
            }

            // Still a gap, still within the submission's grace period.
            Ok(false) => MigrationRunSummary::pending(),

            // No verdict without an observation; nothing changes.
            Err(e) => {
                crate::error!(
                    migration_id = id,
                    error = format!("{e:?}"),
                    observed_only = true,
                    "wallet_migration.observe_failed"
                );
                MigrationRunSummary::skipped()
            }
        }
    }

    /// Record that the end state holds, and start the cap over: the gap those
    /// attempts belonged to is closed.
    fn mark_converged(id: &str, record: &mut MigrationRecord, observed_only: bool) {
        crate::info!(
            migration_id = id,
            attempts = record.attempts,
            observed_only = observed_only,
            "wallet_migration.converged"
        );
        record.status = MigrationStatus::Succeeded;
        record.completed_at.get_or_insert_with(Utc::now);
        record.last_error_code = None;
        record.last_error_message = None;
        record.attempts = 0;
    }

    /// Record a failed pass. Terminal or retryable is the caller's call.
    fn mark_failed(
        record: &mut MigrationRecord,
        status: MigrationStatus,
        code: String,
        message: String,
    ) {
        record.status = status;
        record.last_error_code = Some(code);
        record.last_error_message = Some(message);
    }

    /// Is a submission still within its grace period?
    ///
    /// Only gates *submitting*. Past the cooldown a transaction is never going
    /// to mine, so the next pass resubmits.
    fn still_settling(id: &str, record: &MigrationRecord) -> bool {
        if !matches!(record.status, MigrationStatus::InProgress) {
            return false;
        }
        let Some(last) = record.last_attempted_at else {
            return false;
        };
        let settling = Utc::now() - last < Duration::hours(RESUBMIT_COOLDOWN_HOURS);
        if settling {
            crate::info!(
                migration_id = id,
                last_attempted_at = last.to_rfc3339(),
                "wallet_migration.settling"
            );
        }
        settling
    }

    /// One record per registered migration, for
    /// [`MigrationController::list_all_records`](crate::migration::MigrationController::list_all_records).
    ///
    /// # Errors
    ///
    /// Only unexpected store failures; missing and corrupt keys read as a reset.
    pub fn list_records(&self) -> Result<Vec<MigrationRecordEntry>, MigrationError> {
        self.all()
            .map(|m| {
                let migration_id = m.migration_id();
                let record: MigrationRecord = self.records.load(&migration_id)?;
                Ok(record.into_entry(migration_id))
            })
            .collect()
    }

    /// Delete every wallet migration record. Developer/testing use only.
    ///
    /// # Errors
    ///
    /// If the store fails for a reason other than a missing key.
    pub fn delete_records(&self) -> Result<i32, MigrationError> {
        let mut deleted = 0;
        for m in self.all() {
            if self.records.delete(&m.migration_id())? {
                deleted += 1;
            }
        }
        Ok(deleted)
    }

    /// Every registered migration, prerequisite first — the iteration order
    /// for anything that must cover all of them (listing, deletion).
    fn all(&self) -> impl Iterator<Item = &Arc<dyn WalletMigration>> {
        self.prerequisite.iter().chain(self.migrations.iter())
    }

    /// The store is unusable this launch.
    ///
    /// Reported as retryable and left untouched: losing a record is cheap, but
    /// acting on a half-read one is not.
    fn storage_failure(id: &str, e: &MigrationError) -> MigrationRunSummary {
        crate::error!(
            migration_id = id,
            error = format!("{e:?}"),
            "wallet_migration.storage_error"
        );
        MigrationRunSummary::failed_retryable()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::primitives::key_value_store::InMemoryDeviceKeyValueStore;
    use async_trait::async_trait;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    /// The persisted record for `id`, defaulted if there is none.
    fn record_of(c: &WalletMigrationController, id: &str) -> MigrationRecord {
        c.records.load(id).unwrap()
    }

    /// Replays a fixed script of outcomes, one per reconcile pass, and counts
    /// how many times it was called.
    struct ScriptedMigration {
        id: String,
        script: Vec<fn() -> WalletMigrationResult>,
        calls: AtomicUsize,
        /// Whether a gap remains. Starts open; `close_gap` simulates a
        /// submission finally landing.
        gap: AtomicBool,
        observations: AtomicUsize,
    }

    impl ScriptedMigration {
        fn new(id: &str, script: Vec<fn() -> WalletMigrationResult>) -> Arc<Self> {
            Arc::new(Self {
                id: id.to_string(),
                script,
                calls: AtomicUsize::new(0),
                gap: AtomicBool::new(true),
                observations: AtomicUsize::new(0),
            })
        }

        fn observations(&self) -> usize {
            self.observations.load(Ordering::SeqCst)
        }

        fn close_gap(&self) {
            self.gap.store(false, Ordering::SeqCst);
        }

        fn calls(&self) -> usize {
            self.calls.load(Ordering::SeqCst)
        }
    }

    #[async_trait]
    impl WalletMigration for ScriptedMigration {
        fn migration_id(&self) -> String {
            self.id.clone()
        }

        async fn end_state_holds(&self) -> Result<bool, MigrationError> {
            self.observations.fetch_add(1, Ordering::SeqCst);
            Ok(!self.gap.load(Ordering::SeqCst))
        }

        async fn reconcile(&self) -> Result<WalletMigrationResult, MigrationError> {
            let i = self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(self.script[i.min(self.script.len() - 1)]())
        }
    }

    fn converged() -> WalletMigrationResult {
        WalletMigrationResult::Converged
    }
    fn submitted() -> WalletMigrationResult {
        WalletMigrationResult::submitted("0xdeadbeef")
    }
    fn retry() -> WalletMigrationResult {
        WalletMigrationResult::retry("RPC_ERROR", "offline")
    }

    /// Simulate the resubmit cooldown having elapsed since the last pass.
    fn advance_past_cooldown(c: &WalletMigrationController, id: &str) {
        let mut record = record_of(c, id);
        record.last_attempted_at = record
            .last_attempted_at
            .map(|t| t - Duration::hours(RESUBMIT_COOLDOWN_HOURS + 1));
        c.records.save(id, &record).unwrap();
    }

    fn controller(
        migrations: Vec<Arc<dyn WalletMigration>>,
    ) -> WalletMigrationController {
        WalletMigrationController::with_migrations(
            Arc::new(InMemoryDeviceKeyValueStore::new()),
            migrations,
        )
    }

    /// A migration that was never needed converges on the first pass, and is
    /// reported as skipped rather than succeeded — otherwise every fresh install
    /// shows a burst of successes for work it never did.
    #[tokio::test]
    async fn test_never_needed_is_skipped_not_succeeded() {
        let m = ScriptedMigration::new("never.needed", vec![converged]);
        let c = controller(vec![m.clone()]);

        let summary = c.run().await;
        assert_eq!(summary.skipped, 1);
        assert_eq!(summary.succeeded, 0);
        assert!(matches!(
            c.records
                .load::<MigrationRecord>("never.needed")
                .unwrap()
                .status,
            MigrationStatus::Succeeded
        ));
    }

    /// Submitting leaves the migration in flight; the *next* pass's observation
    /// is what promotes it, and that one counts as a success.
    #[tokio::test]
    async fn test_submission_is_proven_by_the_next_observation() {
        let m =
            ScriptedMigration::new("submits.then.lands", vec![submitted, converged]);
        let c = controller(vec![m.clone()]);

        let first = c.run().await;
        assert_eq!(first.pending, 1);
        let record = c
            .records
            .load::<MigrationRecord>("submits.then.lands")
            .unwrap();
        assert!(matches!(record.status, MigrationStatus::InProgress));
        assert_eq!(record.attempts, 1);

        advance_past_cooldown(&c, "submits.then.lands");
        let second = c.run().await;
        assert_eq!(second.succeeded, 1, "the observation proves completion");
        assert!(matches!(
            c.records
                .load::<MigrationRecord>("submits.then.lands")
                .unwrap()
                .status,
            MigrationStatus::Succeeded
        ));
    }

    /// A migration whose submissions never show up on chain goes terminal — and
    /// the pass that writes it off observes, never submits.
    #[tokio::test]
    async fn test_capped_migration_gives_up_without_submitting_again() {
        let m = ScriptedMigration::new("never.lands", vec![submitted]);
        let c = controller(vec![m.clone()]);

        for _ in 0..MAX_ATTEMPTS {
            c.run().await;
            advance_past_cooldown(&c, "never.lands");
        }
        assert_eq!(m.calls(), MAX_ATTEMPTS as usize);

        // The cap is spent: this pass confirms on chain and gives up.
        let summary = c.run().await;
        assert_eq!(summary.failed_terminal, 1);
        assert_eq!(
            m.calls(),
            MAX_ATTEMPTS as usize,
            "the give-up pass must not submit anything"
        );
        let record = record_of(&c, "never.lands");
        assert!(matches!(record.status, MigrationStatus::FailedTerminal));
        assert_eq!(record.attempts, MAX_ATTEMPTS);

        advance_past_cooldown(&c, "never.lands");
        let summary = c.run().await;
        assert_eq!(summary.skipped, 1, "terminal migrations never run again");
        assert_eq!(m.calls(), MAX_ATTEMPTS as usize);
    }

    /// If the last submission does land, the capped migration is recorded as
    /// converged rather than written off on an unwatched transaction.
    #[tokio::test]
    async fn test_capped_migration_that_landed_is_not_written_off() {
        let m = ScriptedMigration::new("lands.last", vec![submitted]);
        let c = controller(vec![m.clone()]);

        for _ in 0..MAX_ATTEMPTS {
            c.run().await;
            advance_past_cooldown(&c, "lands.last");
        }

        m.close_gap();
        let summary = c.run().await;
        assert_eq!(summary.succeeded, 1);
        assert_eq!(m.calls(), MAX_ATTEMPTS as usize, "no extra submission");
        let record = record_of(&c, "lands.last");
        assert!(matches!(record.status, MigrationStatus::Succeeded));
        assert_eq!(record.attempts, 0, "convergence starts the cap over");
    }

    /// An observation failure on the give-up pass reaches no verdict: the
    /// migration stays in flight and is settled on a later launch.
    #[tokio::test]
    async fn test_capped_migration_needs_an_observation_to_give_up() {
        struct FlakyObserver {
            broken: AtomicBool,
        }
        #[async_trait]
        impl WalletMigration for FlakyObserver {
            fn migration_id(&self) -> String {
                "cannot.observe".to_string()
            }
            async fn end_state_holds(&self) -> Result<bool, MigrationError> {
                if self.broken.load(Ordering::SeqCst) {
                    return Err(MigrationError::InvalidOperation("rpc down".into()));
                }
                Ok(false)
            }
            async fn reconcile(&self) -> Result<WalletMigrationResult, MigrationError> {
                Ok(submitted())
            }
        }

        let m = Arc::new(FlakyObserver {
            broken: AtomicBool::new(false),
        });
        let c = controller(vec![m.clone()]);
        for _ in 0..MAX_ATTEMPTS {
            c.run().await;
            advance_past_cooldown(&c, "cannot.observe");
        }

        // The cap is spent, but now the chain cannot be read.
        m.broken.store(true, Ordering::SeqCst);

        let summary = c.run().await;
        assert_eq!(summary.skipped, 1);
        assert!(matches!(
            c.records
                .load::<MigrationRecord>("cannot.observe")
                .unwrap()
                .status,
            MigrationStatus::InProgress
        ));
    }

    /// Failed passes are not submissions, so no number of them exhausts the cap.
    /// This is what keeps an offline user from being pushed to terminal.
    #[tokio::test]
    async fn test_failures_never_exhaust_the_cap() {
        let m = ScriptedMigration::new("offline", vec![retry]);
        let c = controller(vec![m.clone()]);

        for _ in 0..(MAX_ATTEMPTS * 3) {
            c.run().await;
        }
        let record = record_of(&c, "offline");
        assert_eq!(record.attempts, 0, "nothing was ever submitted");
        assert!(matches!(record.status, MigrationStatus::FailedRetryable));
    }

    /// An observation error is evidence of nothing: the status is left untouched
    /// so it is neither promoted nor charged.
    #[tokio::test]
    async fn test_observation_error_leaves_status_untouched() {
        struct AlwaysErrors;
        #[async_trait]
        impl WalletMigration for AlwaysErrors {
            fn migration_id(&self) -> String {
                "errors".to_string()
            }
            async fn end_state_holds(&self) -> Result<bool, MigrationError> {
                Err(MigrationError::InvalidOperation("rpc down".to_string()))
            }
            async fn reconcile(&self) -> Result<WalletMigrationResult, MigrationError> {
                Err(MigrationError::InvalidOperation("rpc down".to_string()))
            }
        }

        let c = controller(vec![Arc::new(AlwaysErrors)]);
        let summary = c.run().await;
        assert_eq!(summary.skipped, 1);
        let record = record_of(&c, "errors");
        assert!(matches!(record.status, MigrationStatus::NotStarted));
        assert_eq!(record.attempts, 0);
    }

    /// Dependents do not run in the same cold start that submits the 4337
    /// repair: the repair is only a submission, and nothing waits for it to land.
    #[tokio::test]
    async fn test_dependents_wait_for_the_prerequisite_to_converge() {
        let prereq = ScriptedMigration::new("prereq", vec![submitted, converged]);
        let dependent = ScriptedMigration::new("dependent", vec![converged]);
        let c = WalletMigrationController {
            records: RecordStore::new(
                Arc::new(InMemoryDeviceKeyValueStore::new()),
                WALLET_KEY_PREFIX,
            ),
            prerequisite: Some(prereq.clone()),
            migrations: vec![dependent.clone()],
        };

        // Cold start 1: the repair is submitted, so the dependent is not run.
        let first = c.run().await;
        assert_eq!(first.total, 2);
        assert_eq!(first.pending, 1);
        assert_eq!(first.skipped, 1);
        assert_eq!(dependent.calls(), 0, "dependent must not run this launch");

        // Cold start 2: the repair is observed in place, so the dependent runs.
        advance_past_cooldown(&c, "prereq");
        c.run().await;
        assert_eq!(dependent.calls(), 1);
    }

    /// A prerequisite that has already converged does not block anything, and is
    /// not re-observed within its TTL.
    #[tokio::test]
    async fn test_converged_prerequisite_does_not_block() {
        let prereq = ScriptedMigration::new("prereq", vec![converged]);
        let dependent = ScriptedMigration::new("dependent", vec![submitted]);
        let c = WalletMigrationController {
            records: RecordStore::new(
                Arc::new(InMemoryDeviceKeyValueStore::new()),
                WALLET_KEY_PREFIX,
            ),
            prerequisite: Some(prereq.clone()),
            migrations: vec![dependent.clone()],
        };

        c.run().await;
        assert_eq!(dependent.calls(), 1, "dependent runs once the repair holds");

        advance_past_cooldown(&c, "dependent");
        c.run().await;
        assert_eq!(prereq.calls(), 2, "the chain is re-read every launch");
        assert_eq!(dependent.calls(), 2, "dependent keeps retrying");
    }

    /// A second cold start inside the cooldown does not re-submit; past it, the
    /// submission is treated as never going to land and is retried.
    #[tokio::test]
    async fn test_in_flight_submission_is_not_resubmitted_within_the_cooldown() {
        let m = ScriptedMigration::new("in.flight", vec![submitted]);
        let c = controller(vec![m.clone()]);

        c.run().await;
        assert_eq!(m.calls(), 1);

        let summary = c.run().await;
        assert_eq!(summary.pending, 1, "still settling");
        assert_eq!(m.calls(), 1, "must not re-submit within the cooldown");
        assert_eq!(m.observations(), 1, "but the chain is still read");

        advance_past_cooldown(&c, "in.flight");
        c.run().await;
        assert_eq!(
            m.calls(),
            2,
            "past the cooldown it will never land, so retry"
        );
    }

    /// The cap counts submissions for the *current* gap. A migration that
    /// converges, drifts back, and needs work again must not inherit the old
    /// count, or it would go terminal after `MAX_ATTEMPTS` spread over years.
    #[tokio::test]
    async fn test_attempts_reset_on_convergence() {
        let m = ScriptedMigration::new(
            "drifts",
            vec![submitted, submitted, converged, submitted],
        );
        let c = controller(vec![m.clone()]);

        c.run().await;
        advance_past_cooldown(&c, "drifts");
        c.run().await;
        advance_past_cooldown(&c, "drifts");
        c.run().await;
        assert!(matches!(
            record_of(&c, "drifts").status,
            MigrationStatus::Succeeded
        ));
        assert_eq!(
            c.records
                .load::<MigrationRecord>("drifts")
                .unwrap()
                .attempts,
            0,
            "converging closes the gap, so the count starts over"
        );

        // The state drifts back; the next launch observes it and acts.
        c.run().await;
        assert_eq!(
            c.records
                .load::<MigrationRecord>("drifts")
                .unwrap()
                .attempts,
            1
        );
    }

    /// Records live under their own namespace, so they cannot collide with the
    /// FFI framework's `migration:{id}` keys.
    #[tokio::test]
    async fn test_records_use_their_own_namespace() {
        let kv = Arc::new(InMemoryDeviceKeyValueStore::new());
        let c = WalletMigrationController::with_migrations(
            kv.clone(),
            vec![ScriptedMigration::new("collides", vec![converged])],
        );
        c.run().await;

        assert!(kv.get("migration:wallet:collides".to_string()).is_ok());
        assert!(
            kv.get("migration:collides".to_string()).is_err(),
            "must not write into the FFI framework's namespace"
        );
    }
}
