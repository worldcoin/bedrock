//! Error types for Turnkey account management.
//!
//! [`TurnkeyApiError`] is the rich internal error used for classification and
//! logging inside Bedrock. [`TurnkeyMigrationError`] is the deliberately opaque
//! error surfaced to clients — callers only learn that a run failed; all detail
//! is logged internally.

use crate::primitives::KeypairSignerError;
use turnkey_client::TurnkeyClientError;

/// Rich, internal error for Turnkey API operations. Used for retry
/// classification and structured logging; never returned across the FFI boundary.
#[crate::bedrock_error]
pub enum TurnkeyApiError {
    /// The request timed out.
    #[error("Turnkey request timed out")]
    Timeout,
    /// Turnkey rate-limited the request (HTTP 429).
    #[error("Turnkey rate limited the request")]
    RateLimited,
    /// The request was not authorized (HTTP 401/403).
    #[error("Turnkey request unauthorized")]
    Unauthorized,
    /// The requested resource was not found (HTTP 404).
    #[error("Turnkey resource not found")]
    NotFound,
    /// Turnkey returned a server error (HTTP 5xx).
    #[error("Turnkey server error: status {status}")]
    ServerError {
        /// The HTTP status code returned.
        status: u16,
    },
    /// A transport-level failure (connectivity, DNS, TLS). Never contains a URL.
    #[error("Turnkey transport error: {message}")]
    Transport {
        /// Description of the transport failure.
        message: String,
    },
    /// A submitted activity failed, was rejected, or required extra approval.
    #[error("Turnkey activity error: {message}")]
    Activity {
        /// Description of the activity failure.
        message: String,
    },
    /// Producing a request stamp failed (signing or key retrieval).
    #[error("failed to produce request stamp: {0}")]
    Signer(String),
    /// Any other Turnkey client error (decoding, serialization, etc.).
    #[error("Turnkey client error: {0}")]
    Client(String),
    /// The auth proxy returned no sub-organization for the credential.
    #[error("no sub-organization found for the provided credential")]
    SubOrgNotFound,
    /// The expected main user (`auth_user_main`) was not found in the sub-organization.
    #[error("main user not found in sub-organization")]
    MainUserNotFound,
}

/// Maps a signer failure to [`TurnkeyApiError::Signer`], preserving its message.
impl From<KeypairSignerError> for TurnkeyApiError {
    fn from(error: KeypairSignerError) -> Self {
        Self::Signer(error.to_string())
    }
}

/// Classifies a [`TurnkeyClientError`] from the Turnkey SDK into our internal error.
impl From<TurnkeyClientError> for TurnkeyApiError {
    fn from(error: TurnkeyClientError) -> Self {
        match error {
            TurnkeyClientError::Http(source) => {
                if source.is_timeout() {
                    Self::Timeout
                } else {
                    Self::Transport {
                        message: source.without_url().to_string(),
                    }
                }
            }
            TurnkeyClientError::ReqwestBuilder(source) => Self::Transport {
                message: source.without_url().to_string(),
            },
            TurnkeyClientError::UnexpectedHttpStatus(code, _) => match code {
                429 => Self::RateLimited,
                401 | 403 => Self::Unauthorized,
                404 => Self::NotFound,
                500..=599 => Self::ServerError { status: code },
                _ => Self::Transport {
                    message: format!("unexpected HTTP status {code}"),
                },
            },
            TurnkeyClientError::StamperError(source) => {
                Self::Signer(source.to_string())
            }
            other @ (TurnkeyClientError::ActivityFailed(_)
            | TurnkeyClientError::UnexpectedActivityStatus(_)
            | TurnkeyClientError::ActivityRequiresApproval(_)
            | TurnkeyClientError::MissingActivity
            | TurnkeyClientError::MissingResult
            | TurnkeyClientError::MissingInnerResult
            | TurnkeyClientError::UnexpectedInnerActivityResult(_)) => Self::Activity {
                message: other.to_string(),
            },
            other => Self::Client(other.to_string()),
        }
    }
}

/// Opaque error returned to clients when a Turnkey migration run fails.
///
/// All diagnostic detail is logged inside Bedrock (see [`TurnkeyApiError`]); the
/// client only learns that the run did not succeed.
#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum TurnkeyMigrationError {
    /// A migration run failed. See the Bedrock logs for details.
    #[error("turnkey migration run failed")]
    Failed,
}
