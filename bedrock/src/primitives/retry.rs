//! Generic retry logic for HTTP requests to different backends.
//!
//! The retry logic is bounded, with exponential backoff and [full jitter](https://aws.amazon.com/blogs/architecture/exponential-backoff-and-jitter/).

use std::future::Future;
use std::time::Duration;

/// Bounded retry policy: exponential backoff capped by `max_delay`, with full jitter.
#[derive(Debug, Clone, Copy)]
pub struct RetryPolicy {
    /// Maximum number of attempts (including the first).
    pub max_attempts: u32,
    /// Base delay used for the first backoff.
    pub base_delay: Duration,
    /// Ceiling on any single backoff delay.
    pub max_delay: Duration,
    /// The maximum time the entire request (including retries) may take. This is a
    /// last resort stop-gap to prevent handing requests.
    pub total_timeout: Duration,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            max_attempts: 3,
            base_delay: Duration::from_millis(250),
            max_delay: Duration::from_secs(2),
            total_timeout: Duration::from_secs(15),
        }
    }
}

impl RetryPolicy {
    /// Full-jitter exponential backoff for `attempt` (1-indexed), capped at
    /// [`Self::max_delay`].
    #[must_use]
    pub fn backoff_delay(&self, attempt: u32) -> Duration {
        let factor = 2u32.saturating_pow(attempt.saturating_sub(1));
        let capped = self.base_delay.saturating_mul(factor).min(self.max_delay);
        let ceil_ms = u64::try_from(capped.as_millis()).unwrap_or(u64::MAX);
        if ceil_ms == 0 {
            return Duration::ZERO;
        }
        // Uniform in [0, ceil_ms].
        Duration::from_millis(rand::random::<u64>() % ceil_ms.saturating_add(1))
    }
}

/// Why a retried operation failed.
#[derive(Debug)]
pub enum RetryError<E> {
    /// Operation reported a non-retryable error.
    Operation(E),
    /// [`RetryPolicy::total_timeout`] elapsed before a success.
    Timeout,
}

/// Runs `op`, retrying transient failures per `policy` until terminal state.
///
/// `is_retryable` decides whether a given error warrants another attempt, so each
/// client keeps its own transient/permanent classification.
///
/// # Errors
/// Returns the last error from `op` once retries are exhausted or `is_retryable`
/// returns `false`.
pub async fn retry_with_backoff<T, E, Fut>(
    policy: &RetryPolicy,
    operation: &str,
    is_retryable: impl Fn(&E) -> bool + Send + Sync,
    mut op: impl FnMut() -> Fut + Send,
) -> Result<T, RetryError<E>>
where
    Fut: Future<Output = Result<T, E>> + Send,
    E: std::fmt::Display + Send,
    T: Send,
{
    let result = tokio::time::timeout(policy.total_timeout, async {
        let mut attempt: u32 = 0;

        loop {
            match op().await {
                Ok(value) => return Ok(value),

                Err(error) => {
                    attempt += 1;

                    if attempt >= policy.max_attempts || !is_retryable(&error) {
                        crate::warn!(
                            operation = operation,
                            "request.failed op={operation} attempts={attempt} err={error}"
                        );
                        return Err(RetryError::Operation(error));
                    }

                    let delay = policy.backoff_delay(attempt);

                    crate::warn!(
                        "request.retry op={operation} attempt={attempt} delay_ms={} err={error}",
                        delay.as_millis()
                    );

                    tokio::time::sleep(delay).await;
                }
            }
        }
    })
    .await;

    let Ok(result) = result else {
        let timeout_ms = policy.total_timeout.as_millis();
        crate::warn!(
            operation = operation,
            timeout_ms = timeout_ms,
            "request.total_timeout op={operation}",
        );
        return Err(RetryError::Timeout);
    };
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    #[test]
    fn backoff_is_bounded_by_max_delay() {
        let policy = RetryPolicy::default();
        for attempt in 1..=8 {
            assert!(policy.backoff_delay(attempt) <= policy.max_delay);
        }
    }

    #[tokio::test(start_paused = true)]
    async fn recovers_after_transient_failures() {
        let policy = RetryPolicy::default();
        let calls = AtomicU32::new(0);
        let result: Result<u32, RetryError<&str>> = retry_with_backoff(
            &policy,
            "op",
            |_| true,
            || {
                let attempt = calls.fetch_add(1, Ordering::SeqCst);
                async move {
                    if attempt < 2 {
                        Err("transient")
                    } else {
                        Ok(42)
                    }
                }
            },
        )
        .await;

        assert_eq!(result.unwrap(), 42);
        assert_eq!(calls.load(Ordering::SeqCst), 3);
    }

    #[tokio::test(start_paused = true)]
    async fn gives_up_after_max_attempts() {
        let policy = RetryPolicy::default();
        let calls = AtomicU32::new(0);
        let result: Result<(), RetryError<&str>> = retry_with_backoff(
            &policy,
            "op",
            |_| true,
            || {
                calls.fetch_add(1, Ordering::SeqCst);
                async { Err("always") }
            },
        )
        .await;

        assert!(matches!(result, Err(RetryError::Operation("always"))));
        assert_eq!(calls.load(Ordering::SeqCst), policy.max_attempts);
    }

    #[tokio::test(start_paused = true)]
    async fn does_not_retry_non_retryable() {
        let policy = RetryPolicy::default();
        let calls = AtomicU32::new(0);
        let result: Result<(), RetryError<&str>> = retry_with_backoff(
            &policy,
            "op",
            |_| false,
            || {
                calls.fetch_add(1, Ordering::SeqCst);
                async { Err("permanent") }
            },
        )
        .await;

        assert!(matches!(result, Err(RetryError::Operation("permanent"))));
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn total_timeout_exceeded_raises_timeout_error() {
        let policy = RetryPolicy {
            total_timeout: Duration::from_secs(5),
            ..Default::default()
        };
        let calls = AtomicU32::new(0);
        let result: Result<(), RetryError<&str>> = retry_with_backoff(
            &policy,
            "op",
            |_| true,
            || {
                calls.fetch_add(1, Ordering::SeqCst);
                async {
                    tokio::time::sleep(Duration::from_secs(60)).await;
                    Err("never settles")
                }
            },
        )
        .await;

        assert!(matches!(result, Err(RetryError::Timeout)));
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "the first attempt never settled, so no retry was ever reached"
        );
    }
}
