//! End-to-end test of the dependency log forwarding chain:
//! `set_logger` → global `tracing` subscriber → `enabled` filter → host `Logger`.
//!
//! This has to be its own integration binary. Inside the `bedrock` crate every
//! callsite's `module_path!()` starts with `bedrock`, so `ForeignLoggerSubscriber`
//! correctly classifies it as one of Bedrock's own records and refuses to forward it
//! — which makes the `enabled` filter untestable from a unit test. Here the module
//! path is this test binary, so an explicit `target:` decides, and the real filter
//! runs. `set_logger` installs the global subscriber exactly once per process, hence
//! a dedicated binary with a single test.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use bedrock::primitives::logger::{set_logger, LogLevel, Logger};
// `log` is not a direct dependency of `bedrock`; use the copy `tracing-log` links, so
// the facade under test is exactly the one `LogTracer` bridges.
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
            .expect("records lock")
            .push((level, message, attributes));
    }
}

/// Siegel's `mlock` warning is the reason `install_dependency_capture` exists, so the
/// whole chain is asserted here: a dependency `WARN` reaches the host redacted,
/// version-stamped and attributed, while sub-`WARN` dependency noise and Bedrock's own
/// records never arrive.
///
/// One test per binary: `set_logger` fills a process-global `OnceLock` and installs the
/// global `tracing` subscriber once, so a second test here would silently no-op and
/// observe nothing.
#[test]
fn dependency_warnings_reach_the_host_and_noise_does_not() {
    // The noise assertions below would be vacuous if `debug!`/`trace!`/`info!` were
    // compiled out: `tracing`'s `max_level_*` features are additive across the
    // dependency graph, so any crate enabling one would silently disarm them.
    assert_eq!(
        tracing::level_filters::STATIC_MAX_LEVEL,
        tracing::level_filters::LevelFilter::TRACE,
        "a compile-time max level would make the sub-WARN assertions vacuous",
    );

    let capturing = Arc::new(CapturingLogger::default());
    set_logger(capturing.clone());

    let secret = "a".repeat(32);
    // `target` is what the real `enabled` filter sees, since this binary's module
    // path is not `bedrock`.
    tracing::warn!(target: "siegel", key = %secret, "mlock failed for {secret}");
    tracing::error!(target: "siegel", "an error from a dependency");
    tracing::info!(target: "siegel", "info noise");
    tracing::debug!(target: "siegel", "debug noise");
    tracing::trace!(target: "siegel", "trace noise");
    // A field-only event records no `message`, and must not arrive blank. The fields
    // also cover both visitor paths: `&str` via `record_str`, the rest via
    // `record_debug`; all must render unquoted so a backend can filter on them.
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
    // Dependencies that log via the `log` crate are bridged by `LogTracer`. Every such
    // record shares one callsite whose target is the literal "log", so without
    // normalization they would all be attributed to "log".
    log::warn!(target: "rustls", "a warning through the log facade");

    let records = capturing.records.lock().expect("records lock").clone();
    let matching = |needle: &str| -> Vec<Record> {
        records
            .iter()
            .filter(|(_, message, _)| message.contains(needle))
            .cloned()
            .collect()
    };
    let only = |needle: &str| -> Record {
        let found = matching(needle);
        assert_eq!(
            found.len(),
            1,
            "expected exactly one record for {needle:?}, got {found:?}"
        );
        found.into_iter().next().expect("checked non-empty")
    };

    let (level, message, attributes) = only("mlock failed");
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

    let (level, _, _) = only("an error from a dependency");
    assert!(matches!(level, LogLevel::Error), "wrong level: {level:?}");

    // The field-only event: non-blank body, and every field rendered unquoted.
    let field_only = records
        .iter()
        .find(|(_, _, attributes)| attributes.contains_key("code"))
        .expect("the field-only event was forwarded");
    let (level, message, attributes) = field_only;
    assert!(matches!(level, LogLevel::Error), "wrong level: {level:?}");
    assert_eq!(
        message, "siegel event without a message",
        "the fallback body must be the target, not the callsite's source path"
    );
    assert_eq!(attributes.get("code").map(String::as_str), Some("500"));
    assert_eq!(attributes.get("path").map(String::as_str), Some("/foo/bar"));
    assert_eq!(attributes.get("ok").map(String::as_str), Some("true"));

    let (_, _, attributes) = only("spoof-marker");
    assert_eq!(
        attributes.get("bedrock_dependency").map(String::as_str),
        Some("siegel"),
        "the real target must override a spoofed dependency field"
    );
    assert_eq!(
        attributes.get("bedrock_version").map(String::as_str),
        Some(env!("CARGO_PKG_VERSION")),
        "the real version must override a spoofed version field"
    );

    let (level, _, attributes) = only("a warning through the log facade");
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
            matching(rejected).is_empty(),
            "must never reach the host: {rejected}"
        );
    }
}
