//! Wallet migrations: the on-chain migrations Bedrock itself owns.
//!
//! A Rust-only sibling of the FFI
//! [`MigrationProcessor`](crate::migration::MigrationProcessor) framework.
//!
//! # Why this is separate
//!
//! `MigrationProcessor` is a published FFI contract shared with the Swift and
//! Kotlin processors another team owns. Every variant added for a
//! fire-and-forget wallet migration is one those platforms must ship.
//!
//! The two also disagree about what "done" means. A foreign processor reports
//! its own success and is believed; an wallet migration cannot, since the only
//! proof its work landed is a later observation of the chain.
//!
//! So [`WalletMigrationResult`] has no success variant — the rule is a type here, not a doc
//! comment, and the enum is free to change in a normal PR.
//!
//! # Model
//!
//! One method, [`WalletMigration::reconcile`], run on every launch:
//!
//! 1. **Observe** — read chain state and compute the gap.
//! 2. No gap → [`WalletMigrationResult::Converged`] → recorded as converged.
//! 3. Gap → **submit**, return [`WalletMigrationResult::Submitted`], stay in flight. The
//!    next launch's observation is what proves it landed.
//!
//! Nothing is ever waited on and no receipt is read anywhere. Completion comes
//! off the chain, never off a submission.
//!
//! # Ordering
//!
//! The ERC-4337 repair is a prerequisite: it relays an owner-signed
//! `execTransaction`, while every other migration submits a userOp that an
//! unrepaired Safe cannot validate. Dependents wait until it has converged.
//!
//! # Giving up
//!
//! After `MAX_ATTEMPTS` submissions the chain never reflects, the migration goes
//! terminal. Only accepted submissions count — a failed or offline pass returns
//! `Retry` — so no number of offline launches exhausts it.
//!
//! **Implementations must be idempotent**, since `reconcile` re-submits whenever
//! the gap is still open, including with a userOp already in flight.

use crate::migration::MigrationError;
use async_trait::async_trait;

/// Result of a reconcile pass.
///
/// Deliberately has no "succeeded" variant: a migration is complete only when a
/// *later* pass observes the end state.
#[derive(Debug)]
pub enum WalletMigrationResult {
    /// Observed state already matches the desired end state; nothing was
    /// submitted. The controller marks the migration converged.
    Converged,

    /// A gap was observed and work was submitted to close it. The migration
    /// stays in flight; a later pass proves whether it landed.
    Submitted {
        /// userOp hash or relay transaction id, for correlating logs. Never
        /// read for control flow — the chain is the only oracle.
        reference: Option<String>,
    },

    /// This pass failed. Retried on the next launch.
    Retry {
        /// Error code for categorizing the failure.
        error_code: String,
        /// Human-readable error message.
        error_message: String,
    },
}

impl WalletMigrationResult {
    /// Work was submitted, identified by `reference` for log correlation.
    #[must_use]
    pub fn submitted(reference: impl Into<String>) -> Self {
        Self::Submitted {
            reference: Some(reference.into()),
        }
    }

    /// A retryable failure.
    #[must_use]
    pub fn retry(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self::Retry {
            error_code: code.into(),
            error_message: message.into(),
        }
    }
}

/// A migration Bedrock owns, whose completion is proven by on-chain state.
///
/// # Implementing
///
/// Both methods read through one private `observe` — always that name —
/// returning the gap as a value. Never stash it on `self`.
///
/// ```rust,ignore
/// async fn end_state_holds(&self) -> Result<bool, MigrationError> {
///     Ok(self.observe().await?.is_empty())
/// }
///
/// async fn reconcile(&self) -> Result<WalletMigrationResult, MigrationError> {
///     let gap = self.observe().await?;          // the only read
///     if gap.is_empty() {
///         return Ok(WalletMigrationResult::Converged);
///     }
///     Ok(WalletMigrationResult::submitted(self.send(gap).await?))
/// }
/// ```
///
/// # Blocking
///
/// Nothing bounds how long these may take, and the run holds the migration
/// lock, so a slow read stalls every other migration. Never block the thread,
/// and never spawn work that outlives the returned future.
#[async_trait]
pub trait WalletMigration: Send + Sync {
    /// Unique identifier, version included (e.g. `"wallet.permit2.approval.v1"`).
    fn migration_id(&self) -> String;

    /// Does the desired end state already hold on chain?
    ///
    /// A pure read, called only when submitting is not allowed — the cap is
    /// spent, or a submission is still settling. Never on a healthy launch.
    ///
    /// # Errors
    ///
    /// If the observation failed. The migration is left untouched.
    async fn end_state_holds(&self) -> Result<bool, MigrationError>;

    /// Observe, and submit work if the end state does not hold.
    ///
    /// **One chain read**, and **must be idempotent** — called every launch
    /// while the gap is open, including with a submission already in flight.
    ///
    /// # Errors
    ///
    /// If the chain could not be read, or the work could not be submitted.
    async fn reconcile(&self) -> Result<WalletMigrationResult, MigrationError>;
}
