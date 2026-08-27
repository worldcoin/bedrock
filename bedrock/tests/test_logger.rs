//! Tests logger behaviour that needs a process to itself. Being a separate binary
//! lets test logs not coming from `bedrock`.

use std::cell::Cell;
use std::collections::HashMap;
use std::fmt;
use std::sync::{Arc, Mutex, PoisonError};

use bedrock::primitives::logger::{set_logger, LogLevel, Logger};
use bedrock::{critical, debug, error, info, trace, warn};
use tracing_log::log;

/// A single record as the host logger received it.
type Record = (LogLevel, String, HashMap<String, String>);

/// Records everything delivered to the host.
#[derive(Default)]
struct CapturingLogger {
    records: Mutex<Vec<Record>>,
}

impl Logger for CapturingLogger {
    fn log(
        &self,
        level: LogLevel,
        message: String,
        attributes: HashMap<String, String>,
    ) {
        self.records
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push((level, message, attributes));
    }
}

impl CapturingLogger {
    /// Cloned out so the guard is released before any assertion can panic.
    fn records(&self) -> Vec<Record> {
        self.records
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    fn matching(&self, needle: &str) -> Vec<Record> {
        self.records()
            .into_iter()
            .filter(|(_, message, _)| message.contains(needle))
            .collect()
    }

    /// The one record whose message contains `needle`. Requiring exactly one match
    /// also catches a record being delivered twice.
    fn only(&self, needle: &str) -> Record {
        let found = self.matching(needle);
        assert_eq!(
            found.len(),
            1,
            "expected exactly one record for {needle:?}, got {found:?}"
        );
        found.into_iter().next().expect("checked non-empty")
    }
}

/// Counts how many times it is formatted, standing in for a `Display` impl that is
/// expensive or has side effects.
struct CountsFormatting<'a>(&'a Cell<usize>);

impl fmt::Display for CountsFormatting<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.set(self.0.get() + 1);
        f.write_str("formatted")
    }
}

#[test]
fn logger_is_inert_until_installed_then_forwards_dependency_records() {
    inert_without_a_logger();

    let capturing = Arc::new(CapturingLogger::default());
    set_logger(capturing.clone());

    forwards_dependency_records(&capturing);
}

fn inert_without_a_logger() {
    let fields = Cell::new(0);
    let message = Cell::new(0);

    trace!("{}", CountsFormatting(&message));
    debug!("{}", CountsFormatting(&message));
    info!("no arguments at all");

    warn!(
        k = CountsFormatting(&fields),
        "{}",
        CountsFormatting(&message)
    );
    error!(a = CountsFormatting(&fields), b = 1, "two fields");
    critical!(
        c = CountsFormatting(&fields),
        "{}",
        CountsFormatting(&message)
    );

    assert_eq!(
        fields.get(),
        0,
        "attribute values must not be formatted without a logger"
    );
    assert_eq!(
        message.get(),
        0,
        "message arguments must not be formatted without a logger"
    );
}

fn forwards_dependency_records(capturing: &CapturingLogger) {
    assert_eq!(
        tracing::level_filters::STATIC_MAX_LEVEL,
        tracing::level_filters::LevelFilter::TRACE
    );

    let secret = "a".repeat(32);
    // `target` is what the real `enabled` filter sees, since this binary's module
    // path is not `bedrock`.
    tracing::warn!(target: "siegel", key = %secret, "mlock failed for {secret}");
    tracing::error!(target: "siegel", "an error from a dependency");
    tracing::info!(target: "siegel", "info noise");
    tracing::debug!(target: "siegel", "debug noise");
    tracing::trace!(target: "siegel", "trace noise");

    // A field-only event with no `message`
    tracing::error!(target: "siegel", code = 500, path = "/foo/bar", ok = true);

    // Bedrock's own attributes must win over a dependency field of the same name.
    tracing::warn!(
        target: "siegel",
        bedrock_dependency = "spoofed",
        bedrock_version = "0.0.0-spoofed",
        "spoof-marker",
    );

    // Bedrock's own records take the direct path; forwarding them here too would
    // double-log every line.
    tracing::warn!(target: "bedrock::smart_account", "bedrock's own must not forward");

    // Dependencies that log via the `log` crate are bridged by `LogTracer`
    log::warn!(target: "rustls", "a warning through the log facade");

    let (level, message, attributes) = capturing.only("mlock failed");
    assert!(matches!(level, LogLevel::Warn), "wrong level: {level:?}");
    assert_eq!(
        message, "mlock failed for aa..aa",
        "the message must be hex-redacted"
    );
    assert_eq!(
        attributes.get("key").map(String::as_str),
        Some("aa..aa"),
        "attribute values must be hex-redacted"
    );
    assert_eq!(
        attributes.get("bedrock_dependency").map(String::as_str),
        Some("siegel"),
        "the forwarded record must name the dependency it came from"
    );
    assert!(
        attributes.contains_key("bedrock_version"),
        "every record carries the Bedrock version"
    );

    let (level, _, _) = capturing.only("an error from a dependency");
    assert!(matches!(level, LogLevel::Error), "wrong level: {level:?}");

    // The field-only event: non-blank body, and every field rendered unquoted.
    let (level, message, attributes) = capturing
        .records()
        .into_iter()
        .find(|(_, _, attributes)| attributes.contains_key("code"))
        .expect("the field-only event was forwarded");
    assert!(matches!(level, LogLevel::Error));
    assert_eq!(message, "siegel event without a message");
    assert_eq!(attributes.get("code").map(String::as_str), Some("500"));
    assert_eq!(attributes.get("path").map(String::as_str), Some("/foo/bar"));
    assert_eq!(attributes.get("ok").map(String::as_str), Some("true"));

    let (_, _, attributes) = capturing.only("spoof-marker");
    assert_eq!(
        attributes.get("bedrock_dependency").map(String::as_str),
        Some("siegel")
    );
    assert_eq!(
        attributes.get("bedrock_version").map(String::as_str),
        Some(env!("CARGO_PKG_VERSION"))
    );

    let (level, _, attributes) = capturing.only("a warning through the log facade");
    assert!(matches!(level, LogLevel::Warn), "wrong level: {level:?}");
    assert_eq!(
        attributes.get("bedrock_dependency").map(String::as_str),
        Some("rustls"),
        "a `log`-bridged record must name its real target, not \"log\""
    );
    for plumbing in ["log.target", "log.module_path", "log.file", "log.line"] {
        assert!(
            !attributes.contains_key(plumbing),
            "`log` bridge plumbing must not reach the host ({plumbing} leaks a \
             build-time path): {attributes:?}"
        );
    }

    for rejected in [
        "info noise",
        "debug noise",
        "trace noise",
        "bedrock's own must not forward",
    ] {
        assert!(
            capturing.matching(rejected).is_empty(),
            "must never reach the host: {rejected}"
        );
    }
}
