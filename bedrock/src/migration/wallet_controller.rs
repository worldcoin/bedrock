use super::wallet::permit2_approval::Permit2ApprovalMigration;
use super::wallet::safe_4337_module::Safe4337ModuleMigration;
use super::wallet_migration::{Reconciled, WalletMigration};
use crate::migration::controller::{MigrationRecordEntry, MigrationRunSummary};
use crate::migration::error::MigrationError;
use crate::migration::MigrationStatus;
use crate::primitives::key_value_store::{DeviceKeyValueStore, KeyValueStoreError};
use crate::smart_account::SafeSmartAccount;
use crate::warn;
use chrono::{DateTime, Duration, Utc};
use futures::future::join_all;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// Where a wallet migration stands.
///
/// Deliberately not [`MigrationStatus`], the foreign processors' published FFI
/// vocabulary: here work is *in flight* until the chain *converges*.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum WalletMigrationStatus {
    /// Never reconciled.
    #[default]
    NotStarted,

    /// Work was submitted and has not been observed on chain yet.
    InFlight,

    /// The end state was observed. Re-checked when `recheck_at` comes due.
    Converged,

    /// The last pass failed. Retried next launch; nothing is in flight.
    Retrying,

    /// Terminal. Never reconciled again.
    GaveUp,
}

impl WalletMigrationStatus {
    /// The FFI-facing equivalent, for
    /// [`MigrationRecordEntry`](crate::migration::MigrationRecordEntry).
    #[must_use]
    pub const fn to_ffi(self) -> MigrationStatus {
        match self {
            Self::NotStarted => MigrationStatus::NotStarted,
            Self::InFlight => MigrationStatus::InProgress,
            Self::Converged => MigrationStatus::Succeeded,
            Self::Retrying => MigrationStatus::FailedRetryable,
            Self::GaveUp => MigrationStatus::FailedTerminal,
        }
    }
}

/// Persisted state of one wallet migration.
///
/// Lives under its own `migration:wallet:{id}` key. Corrupt or missing data is
/// safe to discard: the chain is the oracle, so it costs one reconcile pass.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct WalletMigrationRecord {
    /// Current status.
    pub status: WalletMigrationStatus,

    /// Submissions made. Only incremented when work was actually accepted, so a
    /// failed or offline pass never advances it toward the give-up cap.
    pub attempts: i32,

    /// When the first submission was made.
    pub started_at: Option<DateTime<Utc>>,

    /// When the most recent reconcile pass ran.
    pub last_attempted_at: Option<DateTime<Utc>>,

    /// Error code from the most recent failed pass.
    pub last_error_code: Option<String>,

    /// Error message from the most recent failed pass.
    pub last_error_message: Option<String>,

    /// When the end state was first observed to hold.
    pub completed_at: Option<DateTime<Utc>>,

    /// When to re-observe a converged migration. On-chain state can drift back
    /// (e.g. a USDC allowance decaying), so convergence is cached, not final.
    pub recheck_at: Option<DateTime<Utc>>,

    /// Reference for the most recent submission (userOp hash or relay id).
    /// Diagnostics only — never read for control flow.
    pub last_submission: Option<String>,
}

/// Own namespace, so on-chain records never collide with the FFI framework's.
const WALLET_KEY_PREFIX: &str = "migration:wallet:";

/// How long a converged migration is trusted before re-observing.
///
/// A spend knob, not only an RPC knob: a recheck that finds the state drifted
/// back will submit work on the spot.
const SUCCESS_TTL_DAYS: i64 = 30;

/// Backoff when a recheck's observation failed (e.g. an RPC outage).
///
/// A converged migration then neither re-observes on every app open nor waits a
/// full [`SUCCESS_TTL_DAYS`].
const OBSERVE_ERROR_RETRY_DAYS: i64 = 1;

/// How long an in-flight submission is given to land.
///
/// Past this it is never going to mine, so retry. Without it, cold starts in
/// quick succession would exhaust [`MAX_ATTEMPTS`] within minutes.
const RESUBMIT_COOLDOWN_HOURS: i64 = 1;

/// Submissions observed to have failed before giving up, counted per gap.
///
/// Once spent, the next pass confirms on chain via
/// [`WalletMigration::end_state_holds`] instead of submitting again.
///
/// A failed or offline pass returns `Retry` and does not count, so no number of
/// offline launches exhausts this and no receipt lookup is needed.
const MAX_ATTEMPTS: i32 = 5;

/// Runs the migrations Bedrock owns.
///
/// Not exported over FFI; see the [module docs](super) for why it is separate
/// from [`MigrationController`](crate::migration::MigrationController).
pub struct WalletMigrationController {
    kv_store: Arc<dyn DeviceKeyValueStore>,
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
            kv_store,
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
            kv_store,
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
                    "wallet_migration.dependents_blocked prerequisite={} count={} timestamp={}",
                    prerequisite.migration_id(),
                    self.migrations.len(),
                    Utc::now().to_rfc3339()
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
        self.load_record(id)
            .is_ok_and(|r| matches!(r.status, WalletMigrationStatus::Converged))
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

        let mut record = match self.load_record(&id) {
            Ok(r) => r,
            Err(e) => return Self::storage_failure(&id, &e),
        };

        // Step 1: is this migration due? Terminal, converged-and-fresh, and
        // still-cooling-down records are left alone.
        if !Self::should_attempt(&id, &record) {
            return MigrationRunSummary::skipped();
        }

        // Step 2a: the cap is spent, so observe instead of reconciling. Giving
        // up must rest on a confirmed gap, and submitting again would only add
        // an unwatched transaction to the pile.
        if record.attempts >= MAX_ATTEMPTS {
            let summary = self.settle_capped(&id, &mut record, migration).await;
            record.last_attempted_at = Some(Utc::now());
            if let Err(e) = self.save_record(&id, &record) {
                return Self::storage_failure(&id, &e);
            }
            return summary;
        }

        // Step 2b: observe, and submit if the end state does not hold.
        let started = Utc::now();
        let outcome = Self::reconcile(migration).await;
        let duration_ms = (Utc::now() - started).num_milliseconds();

        // Step 3: turn that outcome into the new record state.
        let summary = Self::apply(&id, &mut record, outcome, duration_ms);
        record.last_attempted_at = Some(Utc::now());

        // Step 4: one write, after the pass. Nothing is persisted beforehand —
        // if the app dies mid-submission the next launch re-observes anyway,
        // and a lost write only costs an attempt count, which fails open.
        if let Err(e) = self.save_record(&id, &record) {
            return Self::storage_failure(&id, &e);
        }

        summary
    }

    /// Fold one reconcile outcome into the record: the whole state machine.
    ///
    /// Pure — no I/O and no clock beyond `Utc::now`, so every transition is
    /// readable and testable in one place.
    fn apply(
        id: &str,
        record: &mut WalletMigrationRecord,
        outcome: Result<Reconciled, MigrationError>,
        duration_ms: i64,
    ) -> MigrationRunSummary {
        match outcome {
            // Cache the result so the TTL recheck is the only thing that looks
            // again. Reported as a success only if we submitted something, or
            // every fresh install shows a burst of successes it never earned.
            Ok(Reconciled::Converged) => {
                let did_work = record.attempts > 0;
                crate::info!(
                    "wallet_migration.converged id={} did_work={} attempts={} duration_ms={} timestamp={}",
                    id, did_work, record.attempts, duration_ms, Utc::now().to_rfc3339()
                );
                Self::mark_converged(record);

                if did_work {
                    MigrationRunSummary::succeeded()
                } else {
                    MigrationRunSummary::skipped()
                }
            }

            // Reaching here means the previous submission, if any, did not take
            // effect — the gap was still open. Stop once enough accepted
            // submissions have failed to show up on chain.
            Ok(Reconciled::Submitted { reference }) => {
                record.attempts += 1;
                record.started_at.get_or_insert_with(Utc::now);
                record.last_submission = reference;
                record.last_error_code = None;
                record.last_error_message = None;

                crate::info!(
                    "wallet_migration.submitted id={} submission={} attempt={}/{} duration_ms={} timestamp={}",
                    id, record.last_submission.as_deref().unwrap_or("none"),
                    record.attempts, MAX_ATTEMPTS, duration_ms, Utc::now().to_rfc3339()
                );
                record.status = WalletMigrationStatus::InFlight;
                MigrationRunSummary::pending()
            }

            Ok(Reconciled::Retry {
                error_code,
                error_message,
            }) => {
                crate::warn!(
                    "wallet_migration.retry id={} code={} error={} duration_ms={} timestamp={}",
                    id, error_code, error_message, duration_ms, Utc::now().to_rfc3339()
                );
                record.status = WalletMigrationStatus::Retrying;
                record.last_error_code = Some(error_code);
                record.last_error_message = Some(error_message);
                MigrationRunSummary::failed_retryable()
            }

            Ok(Reconciled::GiveUp {
                error_code,
                error_message,
            }) => {
                crate::error!(
                    "wallet_migration.gave_up id={} reason=migration_request code={} error={} timestamp={}",
                    id, error_code, error_message, Utc::now().to_rfc3339()
                );
                record.status = WalletMigrationStatus::GaveUp;
                record.last_error_code = Some(error_code);
                record.last_error_message = Some(error_message);
                MigrationRunSummary::failed_terminal()
            }

            // The observation failed, which is evidence of nothing, so the
            // status is left alone. A converged migration whose TTL just expired
            // gets a short backoff instead of re-observing every app open.
            Err(e) => {
                crate::error!(
                    "wallet_migration.observe_failed id={} error={:?} duration_ms={} timestamp={}",
                    id, e, duration_ms, Utc::now().to_rfc3339()
                );
                if matches!(record.status, WalletMigrationStatus::Converged) {
                    record.recheck_at =
                        Some(Utc::now() + Duration::days(OBSERVE_ERROR_RETRY_DAYS));
                }
                MigrationRunSummary::skipped()
            }
        }
    }

    /// Observe, then submit if the end state does not hold.
    ///
    /// Lives here rather than on the trait so the check that decides "is there
    /// work to do" cannot be overridden or restated by a migration.
    async fn reconcile(
        migration: &dyn WalletMigration,
    ) -> Result<Reconciled, MigrationError> {
        if migration.end_state_holds().await? {
            return Ok(Reconciled::Converged);
        }
        migration.submit().await
    }

    /// The cap is spent: one pure observation decides done vs. dead.
    ///
    /// Holds → it landed after all. Gap → confirmed dead. Error → no verdict,
    /// so nothing changes. Nothing is submitted on any branch.
    async fn settle_capped(
        &self,
        id: &str,
        record: &mut WalletMigrationRecord,
        migration: &dyn WalletMigration,
    ) -> MigrationRunSummary {
        match migration.end_state_holds().await {
            Ok(true) => {
                crate::info!(
                    "wallet_migration.converged id={} attempts={} note=capped_but_landed timestamp={}",
                    id, record.attempts, Utc::now().to_rfc3339()
                );
                Self::mark_converged(record);
                MigrationRunSummary::succeeded()
            }
            Ok(false) => {
                crate::error!(
                    "wallet_migration.gave_up id={} reason=never_landed attempts={} last_submission={} timestamp={}",
                    id, record.attempts,
                    record.last_submission.as_deref().unwrap_or("none"),
                    Utc::now().to_rfc3339()
                );
                record.status = WalletMigrationStatus::GaveUp;
                record.last_error_code = Some("NEVER_LANDED".to_string());
                record.last_error_message = Some(format!(
                    "{MAX_ATTEMPTS} submissions did not take effect, giving up"
                ));
                MigrationRunSummary::failed_terminal()
            }
            // No verdict without an observation; try again next launch.
            Err(e) => {
                crate::error!(
                    "wallet_migration.observe_failed id={} error={:?} note=capped timestamp={}",
                    id, e, Utc::now().to_rfc3339()
                );
                MigrationRunSummary::skipped()
            }
        }
    }

    /// Record that the end state holds.
    ///
    /// Caches it behind `recheck_at` and starts the cap over: the gap those
    /// attempts belonged to is closed.
    fn mark_converged(record: &mut WalletMigrationRecord) {
        record.status = WalletMigrationStatus::Converged;
        record.completed_at.get_or_insert_with(Utc::now);
        record.recheck_at = Some(Utc::now() + Duration::days(SUCCESS_TTL_DAYS));
        record.last_error_code = None;
        record.last_error_message = None;
        record.attempts = 0;
    }

    /// Is this migration due for a look this launch?
    ///
    /// The only place a migration is skipped without observing anything, so
    /// every reason to stay quiet is visible here. Converged ones wait for
    /// their TTL; terminal ones never run again; everything else runs.
    fn should_attempt(id: &str, record: &WalletMigrationRecord) -> bool {
        match record.status {
            WalletMigrationStatus::Converged => {
                let due = record.recheck_at.is_some_and(|at| Utc::now() >= at);
                if due {
                    crate::info!(
                        "wallet_migration.recheck_due id={} timestamp={}",
                        id,
                        Utc::now().to_rfc3339()
                    );
                }
                due
            }
            WalletMigrationStatus::GaveUp => false,

            // Give an in-flight submission time to land. Re-observing now would
            // find the same open gap and re-submit, spending an attempt to learn
            // nothing. Past the cooldown it will never land, so retry.
            WalletMigrationStatus::InFlight => {
                let cooled_down = record.last_attempted_at.is_none_or(|at| {
                    Utc::now() - at >= Duration::hours(RESUBMIT_COOLDOWN_HOURS)
                });
                if !cooled_down {
                    crate::info!(
                        "wallet_migration.cooling_down id={} last_attempted_at={} timestamp={}",
                        id,
                        record
                            .last_attempted_at
                            .map(|t| t.to_rfc3339())
                            .unwrap_or_default(),
                        Utc::now().to_rfc3339()
                    );
                }
                cooled_down
            }

            // Nothing was submitted, so looking again costs only an observation.
            WalletMigrationStatus::NotStarted | WalletMigrationStatus::Retrying => true,
        }
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
                let record = self.load_record(&migration_id)?;
                Ok(MigrationRecordEntry {
                    migration_id,
                    status: record.status.to_ffi(),
                    attempts: record.attempts,
                    started_at: record.started_at.map(|t| t.to_rfc3339()),
                    last_attempted_at: record.last_attempted_at.map(|t| t.to_rfc3339()),
                    last_error_code: record.last_error_code,
                    last_error_message: record.last_error_message,
                    completed_at: record.completed_at.map(|t| t.to_rfc3339()),
                })
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
            let key = format!("{WALLET_KEY_PREFIX}{}", m.migration_id());
            match self.kv_store.delete(key) {
                Ok(()) => deleted += 1,
                Err(KeyValueStoreError::KeyNotFound) => {}
                Err(e) => return Err(e.into()),
            }
        }
        Ok(deleted)
    }

    /// Every registered migration, prerequisite first — the iteration order
    /// for anything that must cover all of them (listing, deletion).
    fn all(&self) -> impl Iterator<Item = &Arc<dyn WalletMigration>> {
        self.prerequisite.iter().chain(self.migrations.iter())
    }

    /// Load a record. Corrupt or missing data reads as a reset: the chain is the
    /// oracle, so the worst case is one redundant reconcile pass.
    fn load_record(&self, id: &str) -> Result<WalletMigrationRecord, MigrationError> {
        match self.kv_store.get(format!("{WALLET_KEY_PREFIX}{id}")) {
            Ok(json) => Ok(serde_json::from_str(&json).unwrap_or_else(|e| {
                warn!("Wallet migration {id} has corrupted JSON, resetting: {e:?}");
                WalletMigrationRecord::default()
            })),
            Err(KeyValueStoreError::KeyNotFound) => {
                Ok(WalletMigrationRecord::default())
            }
            Err(KeyValueStoreError::ParsingFailure) => {
                warn!("Wallet migration {id} has corrupted storage data, resetting");
                Ok(WalletMigrationRecord::default())
            }
            Err(e) => Err(e.into()),
        }
    }

    /// Persist a record under this framework's namespace.
    fn save_record(
        &self,
        id: &str,
        record: &WalletMigrationRecord,
    ) -> Result<(), MigrationError> {
        let json = serde_json::to_string(record)?;
        self.kv_store
            .set(format!("{WALLET_KEY_PREFIX}{id}"), json)?;
        Ok(())
    }

    /// The store is unusable this launch.
    ///
    /// Reported as retryable and left untouched: losing a record is cheap, but
    /// acting on a half-read one is not.
    fn storage_failure(id: &str, e: &MigrationError) -> MigrationRunSummary {
        crate::error!(
            "wallet_migration.storage_error id={} error={:?} timestamp={}",
            id,
            e,
            Utc::now().to_rfc3339()
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

    /// Replays a fixed script of outcomes, one per reconcile pass, and counts
    /// how many times it was called.
    struct ScriptedMigration {
        id: String,
        script: Vec<fn() -> Reconciled>,
        calls: AtomicUsize,
        /// Whether a gap remains. Starts open; `close_gap` simulates a
        /// submission finally landing.
        gap: AtomicBool,
    }

    impl ScriptedMigration {
        fn new(id: &str, script: Vec<fn() -> Reconciled>) -> Arc<Self> {
            Arc::new(Self {
                id: id.to_string(),
                script,
                calls: AtomicUsize::new(0),
                gap: AtomicBool::new(true),
            })
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
            Ok(!self.gap.load(Ordering::SeqCst))
        }

        async fn submit(&self) -> Result<Reconciled, MigrationError> {
            let i = self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(self.script[i.min(self.script.len() - 1)]())
        }
    }

    fn converged() -> Reconciled {
        Reconciled::Converged
    }
    fn submitted() -> Reconciled {
        Reconciled::submitted("0xdeadbeef")
    }
    fn retry() -> Reconciled {
        Reconciled::retry("RPC_ERROR", "offline")
    }

    /// Simulate the resubmit cooldown having elapsed since the last pass.
    fn advance_past_cooldown(c: &WalletMigrationController, id: &str) {
        let mut record = c.load_record(id).unwrap();
        record.last_attempted_at = record
            .last_attempted_at
            .map(|t| t - Duration::hours(RESUBMIT_COOLDOWN_HOURS + 1));
        c.save_record(id, &record).unwrap();
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
            c.load_record("never.needed").unwrap().status,
            WalletMigrationStatus::Converged
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
        let record = c.load_record("submits.then.lands").unwrap();
        assert!(matches!(record.status, WalletMigrationStatus::InFlight));
        assert_eq!(record.attempts, 1);

        advance_past_cooldown(&c, "submits.then.lands");
        let second = c.run().await;
        assert_eq!(second.succeeded, 1, "the observation proves completion");
        assert!(matches!(
            c.load_record("submits.then.lands").unwrap().status,
            WalletMigrationStatus::Converged
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
        let record = c.load_record("never.lands").unwrap();
        assert!(matches!(record.status, WalletMigrationStatus::GaveUp));
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
        let record = c.load_record("lands.last").unwrap();
        assert!(matches!(record.status, WalletMigrationStatus::Converged));
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
            async fn submit(&self) -> Result<Reconciled, MigrationError> {
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
            c.load_record("cannot.observe").unwrap().status,
            WalletMigrationStatus::InFlight
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
        let record = c.load_record("offline").unwrap();
        assert_eq!(record.attempts, 0, "nothing was ever submitted");
        assert!(matches!(record.status, WalletMigrationStatus::Retrying));
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
            async fn submit(&self) -> Result<Reconciled, MigrationError> {
                unreachable!("end_state_holds errors first")
            }
        }

        let c = controller(vec![Arc::new(AlwaysErrors)]);
        let summary = c.run().await;
        assert_eq!(summary.skipped, 1);
        let record = c.load_record("errors").unwrap();
        assert!(matches!(record.status, WalletMigrationStatus::NotStarted));
        assert_eq!(record.attempts, 0);
    }

    /// Dependents do not run in the same cold start that submits the 4337
    /// repair: the repair is only a submission, and nothing waits for it to land.
    #[tokio::test]
    async fn test_dependents_wait_for_the_prerequisite_to_converge() {
        let prereq = ScriptedMigration::new("prereq", vec![submitted, converged]);
        let dependent = ScriptedMigration::new("dependent", vec![converged]);
        let c = WalletMigrationController {
            kv_store: Arc::new(InMemoryDeviceKeyValueStore::new()),
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
            kv_store: Arc::new(InMemoryDeviceKeyValueStore::new()),
            prerequisite: Some(prereq.clone()),
            migrations: vec![dependent.clone()],
        };

        c.run().await;
        assert_eq!(dependent.calls(), 1, "dependent runs once the repair holds");

        advance_past_cooldown(&c, "dependent");
        c.run().await;
        assert_eq!(prereq.calls(), 1, "prerequisite waits for its TTL");
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
        assert_eq!(summary.skipped, 1, "still cooling down");
        assert_eq!(m.calls(), 1, "must not re-submit within the cooldown");

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
            c.load_record("drifts").unwrap().status,
            WalletMigrationStatus::Converged
        ));
        assert_eq!(
            c.load_record("drifts").unwrap().attempts,
            0,
            "converging closes the gap, so the count starts over"
        );

        // 30 days later the state has drifted back.
        let mut record = c.load_record("drifts").unwrap();
        record.recheck_at = Some(Utc::now() - Duration::days(1));
        c.save_record("drifts", &record).unwrap();

        c.run().await;
        assert_eq!(c.load_record("drifts").unwrap().attempts, 1);
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
