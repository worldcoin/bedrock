use std::sync::Arc;

use chrono::{DateTime, Utc};
use once_cell::sync::OnceCell;

/// A pluggable time source for foreign bindings for remote NTP.
#[uniffi::export(with_foreign)]
pub trait Ntp: Send + Sync {
    /// Returns the current timestamp in milliseconds since the Unix Epoch (UTC)
    fn now_millis(&self) -> i64;
}

/// A globally configured time provider instance provided by the host application.
static TIME_PROVIDER: OnceCell<Arc<dyn Ntp>> = OnceCell::new();

/// Configures the global time provider.
#[uniffi::export]
pub fn set_time_provider(provider: Arc<dyn Ntp>) {
    let _ = TIME_PROVIDER.set(provider);
}

/// Returns the configured global time provider, if any.
pub fn get_time_provider() -> Option<Arc<dyn Ntp>> {
    TIME_PROVIDER.get().cloned()
}

/// Returns the current UTC time from the configured [`Ntp`],
/// or falls back to the device clock if none is set.
///
/// # Usage
/// Use only for sensitive operations where a precise time is required. For
/// example when generating authentication requests.
#[must_use]
pub fn now_with_ntp() -> DateTime<Utc> {
    if let Some(provider) = get_time_provider() {
        let ms = provider.now_millis();
        if let Some(dt) = DateTime::<Utc>::from_timestamp_millis(ms) {
            return dt;
        }
    }
    Utc::now()
}
