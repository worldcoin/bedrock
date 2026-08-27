//! Internal error types for Turnkey module

use crate::primitives::KeypairSignerError;
use turnkey_client::TurnkeyClientError;

/// Rich, internal error for Turnkey API operations. Used for retry classification
/// and structured logging; never returned across the FFI boundary.
#[derive(Debug, thiserror::Error)]
pub enum TurnkeyApiError {
    /// The total operation timed out (including retries). Terminal.
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
    /// Whether Turnkey rejected the request because the stamping key is not
    /// registered on the sub-organization (`PUBLIC_KEY_NOT_FOUND`).
    ///
    /// For a sync-factor-signed activity this means the sync factor is stale and
    /// the caller must re-authenticate to re-register it.
    pub fn is_public_key_not_found(&self) -> bool {
        self.body_contains("PUBLIC_KEY_NOT_FOUND")
    }

    /// Whether Turnkey rejected a provider deletion because the provider is already
    /// gone. The caller should treat this as an idempotent success.
    pub fn is_no_matching_provider(&self) -> bool {
        self.body_contains("No matching providers found")
    }

    /// Whether the error indicates the stamping key is not a valid signer for the
    /// sub-organization (unregistered key or unauthorized). The caller must
    /// re-authenticate the sync factor.
    pub fn indicates_invalid_signer(&self) -> bool {
        self.is_public_key_not_found() || matches!(self, Self::Unauthorized { .. })
    }

    /// A coarse, non-sensitive classification for the client-facing error `code`.
    pub const fn code(&self) -> &'static str {
        match self {
            Self::Timeout => "timeout",
            Self::RateLimited { .. } => "rate_limited",
            Self::Unauthorized { .. } => "unauthorized",
            Self::NotFound { .. } => "not_found",
            Self::ServerError { .. } => "server_error",
            Self::ClientError { .. } => "client_error",
            Self::Transport { .. } => "transport",
            Self::Activity { .. } => "activity",
            Self::ActivityPollingExceeded { .. } => "activity_pending",
            Self::Signer(_) => "signer",
            Self::Client(_) => "client",
            Self::MainUserNotFound => "main_user_not_found",
            Self::Consistency => "consistency",
        }
    }

    /// Searches the upstream diagnostic text of the error, if any, for `needle`.
    /// Turnkey encodes its error codes in the response body rather than in a
    /// dedicated field the SDK surfaces.
    fn body_contains(&self, needle: &str) -> bool {
        match self {
            Self::Unauthorized { body }
            | Self::NotFound { body }
            | Self::RateLimited { body }
            | Self::ClientError { body, .. }
            | Self::ServerError { body, .. } => body.contains(needle),
            Self::Activity { error_message }
            | Self::ActivityPollingExceeded { error_message } => {
                error_message.contains(needle)
            }
            Self::Timeout
            | Self::Transport { .. }
            | Self::Signer(_)
            | Self::Client(_)
            | Self::MainUserNotFound
            | Self::Consistency => false,
        }
    }

    /// Whether this error is worth retrying (transient classes only).
    ///
    /// `ActivityPollingExceeded` is deliberately **not** retryable: the activity
    /// is already submitted. If execution fails at the TEE, the next migration will pick it up.
    pub const fn is_retryable(&self) -> bool {
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
    /// A migration is already in progress. Only one migration can be running at a time.
    #[error("a migration is already in progress")]
    AlreadyInProgress,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recognizes_the_upstream_strings_it_depends_on() {
        let stale = TurnkeyApiError::Unauthorized {
            body: r#"{"code":7,"message":"PUBLIC_KEY_NOT_FOUND: unknown key"}"#
                .to_string(),
        };
        assert!(stale.is_public_key_not_found());
        assert!(stale.indicates_invalid_signer());

        let absent = TurnkeyApiError::Activity {
            error_message: "No matching providers found for the given ids".to_string(),
        };
        assert!(absent.is_no_matching_provider());
    }

    /// A 401 without the marker is still a stale/under-permissioned signer.
    #[test]
    fn any_unauthorized_is_an_invalid_signer() {
        let denied = TurnkeyApiError::Unauthorized {
            body: "policy denied".to_string(),
        };
        assert!(!denied.is_public_key_not_found());
        assert!(denied.indicates_invalid_signer());
    }

    #[test]
    fn does_not_fire_on_unrelated_failures() {
        for error in [
            TurnkeyApiError::Timeout,
            TurnkeyApiError::ServerError {
                status: 503,
                body: "upstream unavailable".to_string(),
            },
            TurnkeyApiError::Activity {
                error_message: "activity rejected by policy".to_string(),
            },
            TurnkeyApiError::MainUserNotFound,
            TurnkeyApiError::Consistency,
        ] {
            assert!(!error.is_no_matching_provider(), "{error}");
            assert!(!error.indicates_invalid_signer(), "{error}");
        }
    }

    #[test]
    fn a_pending_activity_is_not_an_absent_provider() {
        let pending = TurnkeyApiError::ActivityPollingExceeded {
            error_message: "still PENDING after 5 attempts".to_string(),
        };
        assert!(!pending.is_no_matching_provider());
        assert!(!pending.indicates_invalid_signer());
        assert_eq!(pending.code(), "activity_pending");
    }
}
