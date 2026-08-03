//! Internal error types for Turnkey module

use crate::primitives::KeypairSignerError;
use turnkey_client::TurnkeyClientError;

/// Rich, internal error for Turnkey API operations. Used for retry classification
/// and structured logging; never returned across the FFI boundary.
#[derive(Debug, thiserror::Error)]
pub enum TurnkeyApiError {
    /// The request timed out.
    #[error("Turnkey request timed out")]
    Timeout,
    /// Turnkey rate-limited the request (HTTP 429).
    #[error("Turnkey rate limited the request: {body}")]
    RateLimited {
        /// The upstream response body, for diagnostics.
        body: String,
    },
    /// The request was not authorized (HTTP 401/403).
    #[error("Turnkey request unauthorized: {body}")]
    Unauthorized {
        /// The upstream response body, for diagnostics.
        body: String,
    },
    /// The requested resource was not found (HTTP 404).
    #[error("Turnkey resource not found: {body}")]
    NotFound {
        /// The upstream response body, for diagnostics.
        body: String,
    },
    /// Turnkey returned a server error (HTTP 5xx).
    #[error("Turnkey server error: status {status}: {body}")]
    ServerError {
        /// The HTTP status code returned.
        status: u16,
        /// The upstream response body, for diagnostics.
        body: String,
    },
    /// The request was rejected with a client error (HTTP 4xx other than
    /// 401/403/404/429). Permanent; must not be retried.
    #[error("Turnkey client request rejected: status {status}: {body}")]
    ClientError {
        /// The HTTP status code returned.
        status: u16,
        /// The upstream response body, for diagnostics.
        body: String,
    },
    /// A transport-level failure (connectivity, DNS, TLS). Never contains a URL.
    #[error("Turnkey transport error: {error_message}")]
    Transport {
        /// Description of the transport failure.
        error_message: String,
    },
    /// A submitted activity failed, was rejected, or required extra approval.
    #[error("Turnkey activity error: {error_message}")]
    Activity {
        /// Description of the activity failure.
        error_message: String,
    },
    /// The SDK exhausted its attempts polling a submitted activity to completion
    /// (it was still `PENDING`).
    #[error("Turnkey activity still pending after polling: {error_message}")]
    ActivityPollingExceeded {
        /// The SDK's description (includes the retry count).
        error_message: String,
    },
    /// Producing a request stamp failed (signing or key retrieval).
    #[error("failed to produce request stamp: {0}")]
    Signer(String),
    /// Any other Turnkey client error (decoding, serialization, etc.).
    #[error("Turnkey client error: {0}")]
    Client(String),
    /// The expected main user (`auth_user_main`) was not found in the sub-organization.
    #[error("main user not found in sub-organization")]
    MainUserNotFound,
    /// The account shows a data consistency error which cannot be automatically resolved. Treat as critical.
    #[error("critical consistency error")]
    Consistency,
}

impl TurnkeyApiError {
    /// Whether this error is worth retrying (transient classes only).
    ///
    /// `ActivityPollingExceeded` is deliberately **not** retryable: the activity
    /// is already submitted. If execution fails at the TEE, the next migration will pick it up.
    pub(super) const fn is_retryable(&self) -> bool {
        match self {
            Self::Timeout
            | Self::RateLimited { .. }
            | Self::ServerError { .. }
            | Self::Transport { .. } => true,
            Self::Unauthorized { .. }
            | Self::NotFound { .. }
            | Self::ClientError { .. }
            | Self::Activity { .. }
            | Self::ActivityPollingExceeded { .. }
            | Self::Signer(_)
            | Self::Client(_)
            | Self::MainUserNotFound
            | Self::Consistency => false,
        }
    }

    /// Collapses this rich internal error into the opaque client-facing
    /// [`TurnkeyMigrationError`], preserving only the coarse retry classification.
    pub(super) const fn to_migration_error(&self) -> TurnkeyMigrationError {
        if self.is_retryable() {
            TurnkeyMigrationError::Retryable
        } else {
            TurnkeyMigrationError::Failed
        }
    }
}

/// Maps a signer failure to [`TurnkeyApiError::Signer`], preserving its message.
impl From<KeypairSignerError> for TurnkeyApiError {
    fn from(error: KeypairSignerError) -> Self {
        Self::Signer(error.to_string())
    }
}

/// Max length (in bytes) of an upstream response body retained on an error, to
/// bound log volume and limit exposure of non-generic info.
const MAX_LOGGED_BODY_LEN: usize = 256;

/// Truncates an upstream response body when logging
fn truncate_body(body: String) -> String {
    if body.len() <= MAX_LOGGED_BODY_LEN {
        return body;
    }
    let mut end = MAX_LOGGED_BODY_LEN;
    while !body.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}…[truncated, {} bytes total]", &body[..end], body.len())
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
                        error_message: source.without_url().to_string(),
                    }
                }
            }
            TurnkeyClientError::ReqwestBuilder(source) => Self::Transport {
                error_message: source.without_url().to_string(),
            },
            TurnkeyClientError::UnexpectedHttpStatus(code, body) => {
                // NOTE: Turnkey may occasionally append public keys or sub-organization IDs to bodies,
                // which would be logged here. We rely on the short TTL of logs for this
                // not to be persisted. These logs are essential to ensure proper functioning of this
                // mission critical system.
                let body = truncate_body(body);
                match code {
                    429 => Self::RateLimited { body },
                    401 | 403 => Self::Unauthorized { body },
                    404 => Self::NotFound { body },
                    400..=499 => Self::ClientError { status: code, body },
                    500..=599 => Self::ServerError { status: code, body },
                    _ => Self::Client(format!("unexpected HTTP status {code}: {body}")),
                }
            }
            TurnkeyClientError::StamperError(source) => {
                Self::Signer(source.to_string())
            }
            other @ TurnkeyClientError::ExceededRetries(_) => {
                Self::ActivityPollingExceeded {
                    error_message: other.to_string(),
                }
            }
            other @ (TurnkeyClientError::ActivityFailed(_)
            | TurnkeyClientError::UnexpectedActivityStatus(_)
            | TurnkeyClientError::ActivityRequiresApproval(_)
            | TurnkeyClientError::MissingActivity
            | TurnkeyClientError::MissingResult
            | TurnkeyClientError::MissingInnerResult
            | TurnkeyClientError::UnexpectedInnerActivityResult(_)) => Self::Activity {
                error_message: other.to_string(),
            },
            // Response-header parsing fails before the SDK inspects the status, so
            // an error response missing Content-Type surfaces here (e.g. CloudFlare's default error page)
            other @ (TurnkeyClientError::MissingContentTypeHeader
            | TurnkeyClientError::HeaderToStrError(_)
            | TurnkeyClientError::HeaderFromStrError(_)) => Self::Transport {
                error_message: other.to_string(),
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
    /// The run failed fairly permanent; retrying will not help. Typically a
    /// misconfiguration, a consistency error, or an unauthorized signer.
    #[error("turnkey migration run failed")]
    Failed,
    /// The run failed transiently (timeout, connectivity, rate limiting, an
    /// overall deadline, or a concurrent run). A later retry may succeed.
    #[error("turnkey migration run failed transiently; a retry may succeed")]
    Retryable,
}
