//! NFC Credential Refresh Processor
//!
//! Foreign trait for NFC refresh - the actual logic runs in the native app (iOS/Android)
//! because it needs access to Oxide, WalletKit, and CredentialStorage.
//!
//! ## Flow
//!
//! 1. App implements `ForeignNfcProcessor`
//! 2. `is_applicable()`: check if PCP exists && no v4 credential yet
//! 3. `execute()`: Oxide payload → WalletKit API call → save credential
//!
//! ## Example (Swift)
//!
//! ```swift
//! class NfcProcessorImpl: ForeignNfcProcessor {
//!     func isApplicable() async throws -> Bool {
//!         return hasDocumentPcp(fileSystem: fs) && !credentialStorage.hasNfcCredential()
//!     }
//!
//!     func execute() async throws -> ForeignProcessorResult {
//!         // 1. Get payload from Oxide
//!         guard let payload = try prepareNfcRefreshPayload(
//!             fileSystem: fs,
//!             documentEncryptionKey: key,
//!             identity: identity,
//!             sub: sub
//!         ) else { return .terminal(errorCode: "NO_PCP", errorMessage: "No PCP") }
//!
//!         // 2. Generate auth headers
//!         let zkpHeader = try walletKit.generateZkpHeader(identity: identity)
//!         let attestation = try await getAttestationToken(aud: "toolsforhumanity.com")
//!
//!         // 3. Call WalletKit API
//!         let credential = try await walletKit.refreshNfcCredential(
//!             requestBody: payload.requestBody,
//!             zkpHeader: zkpHeader,
//!             attestation: attestation
//!         )
//!
//!         // 4. Save
//!         try credentialStorage.saveCredential(credential)
//!         return .success
//!     }
//! }
//!
//! // Register
//! let processor = NfcRefreshProcessor(foreign: NfcProcessorImpl(...))
//! controller.register(processor)
//! ```

use crate::migration::error::MigrationError;
use crate::migration::processor::{MigrationProcessor, ProcessorResult};
use async_trait::async_trait;
use log::info;
use std::sync::Arc;

/// Result type for foreign processor execution (FFI-friendly version of `ProcessorResult`)
#[derive(Debug, Clone, uniffi::Enum)]
pub enum ForeignProcessorResult {
    /// Migration completed successfully
    Success,
    /// Transient failure, can retry
    Retryable {
        /// Error code
        error_code: String,
        /// Error message
        error_message: String,
        /// Retry delay in ms
        retry_after_ms: Option<i64>,
    },
    /// Permanent failure, don't retry
    Terminal {
        /// Error code
        error_code: String,
        /// Error message
        error_message: String,
    },
    /// Needs user action
    BlockedUserAction {
        /// Reason
        reason: String,
    },
}

impl From<ForeignProcessorResult> for ProcessorResult {
    fn from(result: ForeignProcessorResult) -> Self {
        match result {
            ForeignProcessorResult::Success => Self::Success,
            ForeignProcessorResult::Retryable {
                error_code,
                error_message,
                retry_after_ms,
            } => Self::Retryable {
                error_code,
                error_message,
                retry_after_ms,
            },
            ForeignProcessorResult::Terminal {
                error_code,
                error_message,
            } => Self::Terminal {
                error_code,
                error_message,
            },
            ForeignProcessorResult::BlockedUserAction { reason } => {
                Self::BlockedUserAction { reason }
            }
        }
    }
}

/// Implement this trait in the native app (iOS/Android).
///
/// Dependencies needed:
/// - `Oxide.hasDocumentPcp()`, `Oxide.prepareNfcRefreshPayload()`
/// - `WalletKit.refreshNfcCredential()`
/// - `CredentialStorage`
#[uniffi::export(with_foreign)]
#[async_trait]
pub trait ForeignNfcProcessor: Send + Sync {
    /// Return true if: `hasDocumentPcp() && !credentialStorage.hasNfcCredential()`
    async fn is_applicable(&self) -> Result<bool, MigrationError>;

    /// Call Oxide → `WalletKit` → `CredentialStorage`
    async fn execute(&self) -> Result<ForeignProcessorResult, MigrationError>;
}

/// Wraps `ForeignNfcProcessor` for use with `MigrationController`
#[derive(uniffi::Object)]
pub struct NfcRefreshProcessor {
    foreign: Arc<dyn ForeignNfcProcessor>,
}

#[uniffi::export]
impl NfcRefreshProcessor {
    /// Create new processor with foreign implementation
    #[uniffi::constructor]
    pub fn new(foreign: Arc<dyn ForeignNfcProcessor>) -> Arc<Self> {
        Arc::new(Self { foreign })
    }
}

#[async_trait]
impl MigrationProcessor for NfcRefreshProcessor {
    fn migration_id(&self) -> String {
        "worldid.credentials.nfc.refresh.v1".to_string()
    }

    async fn is_applicable(&self) -> Result<bool, MigrationError> {
        info!("NFC refresh: checking applicability");
        self.foreign.is_applicable().await
    }

    async fn execute(&self) -> Result<ProcessorResult, MigrationError> {
        info!("NFC refresh: executing");
        self.foreign.execute().await.map(Into::into)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockForeignProcessor {
        applicable: bool,
        result: ForeignProcessorResult,
    }

    #[async_trait]
    impl ForeignNfcProcessor for MockForeignProcessor {
        async fn is_applicable(&self) -> Result<bool, MigrationError> {
            Ok(self.applicable)
        }

        async fn execute(&self) -> Result<ForeignProcessorResult, MigrationError> {
            Ok(self.result.clone())
        }
    }

    #[tokio::test]
    async fn test_processor_delegates_to_foreign() {
        let foreign = Arc::new(MockForeignProcessor {
            applicable: true,
            result: ForeignProcessorResult::Success,
        });
        let processor = NfcRefreshProcessor::new(foreign);

        assert!(processor.is_applicable().await.unwrap());
        assert!(matches!(
            processor.execute().await.unwrap(),
            ProcessorResult::Success
        ));
    }

    #[tokio::test]
    async fn test_processor_not_applicable() {
        let foreign = Arc::new(MockForeignProcessor {
            applicable: false,
            result: ForeignProcessorResult::Success,
        });
        let processor = NfcRefreshProcessor::new(foreign);
        assert!(!processor.is_applicable().await.unwrap());
    }

    #[tokio::test]
    async fn test_terminal_error() {
        let foreign = Arc::new(MockForeignProcessor {
            applicable: true,
            result: ForeignProcessorResult::Terminal {
                error_code: "DOCUMENT_EXPIRED".to_string(),
                error_message: "Document expired".to_string(),
            },
        });
        let processor = NfcRefreshProcessor::new(foreign);

        match processor.execute().await.unwrap() {
            ProcessorResult::Terminal { error_code, .. } => {
                assert_eq!(error_code, "DOCUMENT_EXPIRED");
            }
            _ => panic!("Expected Terminal"),
        }
    }
}
