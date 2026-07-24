use std::cell::RefCell;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};

use tracing::{span, Event, Level, Metadata, Subscriber};

thread_local! {
    static LOG_CONTEXT: RefCell<Option<String>> = const { RefCell::new(None) };
}

/// Trait representing a logger that can log messages at various levels.
///
/// This trait should be implemented by any logger that wants to receive log messages.
/// It is exported via `UniFFI` for use in foreign languages.
///
/// # Examples
///
/// Implementing the `Logger` trait:
///
/// ```rust
/// use std::collections::HashMap;
///
/// use bedrock::primitives::logger::{Logger, LogLevel};
///
/// struct MyLogger;
///
/// impl Logger for MyLogger {
///     fn log(&self, level: LogLevel, message: String, attributes: HashMap<String, String>) {
///         println!("[{:?}] {} {:?}", level, message, attributes);
///     }
/// }
/// ```
///
/// ## swift
///
/// ```swift
///class BedrockCoreLoggerBridge: Bedrock.Logger {
///    static let shared = BedrockCoreLoggerBridge()
///
///    func log(level: Bedrock.LogLevel, message: String, attributes: [String: String]) {
///        Log.log(level.toCoreLevel(), message, attributes: attributes)
///    }
///}
///
///public func setupBedrockLogger() {
///    Bedrock.setLogger(logger: BedrockCoreLoggerBridge.shared)
///}
///
///extension Bedrock.LogLevel {
///    func toCoreLevel() -> WorldAppCore.LogLevel {
///        switch self {
///        case .debug, .trace:
///            return .debug
///        case .info:
///            return .info
///        case .error:
///            return .error
///        case .warn:
///            return .warn
///        }
///    }
///}
/// ```
///
/// ### In app delegate
///
/// ```swift
/// setupBedrockLogger() // Call this only once!!!
/// ```
#[uniffi::export(with_foreign)]
pub trait Logger: Sync + Send {
    /// Logs a message at the specified log level.
    ///
    /// # Arguments
    ///
    /// * `level` - The severity level of the log message.
    /// * `message` - The log message to be recorded.
    /// * `attributes` - Structured key/value metadata for the log line. Hosts
    ///   that support structured logging (e.g. Datadog) should attach these as
    ///   log attributes rather than folding them into `message`. Every log
    ///   carries at least the [`VERSION_ATTRIBUTE_KEY`] attribute.
    fn log(
        &self,
        level: LogLevel,
        message: String,
        attributes: HashMap<String, String>,
    );
}

/// Enumeration of possible log levels.
///
/// This enum represents the severity levels that can be used when logging messages.
#[derive(Debug, Clone, uniffi::Enum)]
pub enum LogLevel {
    /// Designates very low priority, often extremely detailed messages.
    Trace,
    /// Designates lower priority debugging information.
    Debug,
    /// Designates informational messages that highlight the progress of the application.
    Info,
    /// Designates potentially harmful situations.
    Warn,
    /// Designates error events that might still allow the application to continue running.
    Error,
}

/// The host-provided logger. Bedrock's own logs are delivered here directly by
/// [`log_message`], independent of the global `tracing` dispatcher.
static LOGGER_INSTANCE: OnceLock<Arc<dyn Logger>> = OnceLock::new();

/// Sets the logger that receives Bedrock's log messages.
///
/// Bedrock's own instrumentation is delivered to `logger` **directly**, so it is
/// unaffected by whichever Rust library in the process owns the global `tracing`
/// dispatcher. As a best effort, this also installs a global `tracing` subscriber
/// to forward relevant *dependency* logs (notably siegel's `mlock` warning).
///
/// # Arguments
///
/// * `logger` - An `Arc` containing your logger implementation.
///
/// # Note
///
/// Only the first logger is used; later calls keep the original and are no-ops.
#[allow(clippy::module_name_repetitions)]
#[uniffi::export]
pub fn set_logger(logger: Arc<dyn Logger>) {
    if LOGGER_INSTANCE.set(logger).is_err() {
        // Already configured; the first logger stays active.
        return;
    }
    install_dependency_capture();
}

/// Attribute key carrying the running Bedrock version. Attached to every log
/// line so log backends can attribute records to a specific Bedrock release.
pub const VERSION_ATTRIBUTE_KEY: &str = "bedrock_version";

/// The Bedrock crate version, attached to every log line under
/// [`VERSION_ATTRIBUTE_KEY`].
const BEDROCK_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Delivers a Bedrock-originated log record directly to the host [`Logger`],
/// bypassing the global `tracing` dispatcher so delivery never depends on Bedrock
/// owning it. Applies the active [`LogContext`] prefix and hex-secret redaction.
/// A no-op until [`set_logger`] has been called.
#[doc(hidden)]
pub fn log_message(level: LogLevel, args: std::fmt::Arguments<'_>) {
    log_message_with_attributes(level, args, HashMap::new());
}

/// Like [`log_message`], but attaches structured `attributes` to the log line.
///
/// Attribute values are hex-secret redacted just like the message. The
/// [`VERSION_ATTRIBUTE_KEY`] attribute is always added by [`deliver`], and takes
/// precedence over any caller-supplied value for that key.
#[doc(hidden)]
pub fn log_message_with_attributes<S: std::hash::BuildHasher>(
    level: LogLevel,
    args: std::fmt::Arguments<'_>,
    attributes: HashMap<String, String, S>,
) {
    let Some(logger) = LOGGER_INSTANCE.get() else {
        return;
    };
    let message = get_context()
        .map_or_else(|| args.to_string(), |context| format!("{context} {args}"));
    deliver(logger, level, message, attributes);
}

/// Redacts hex secrets from the message and attribute values, attaches the
/// Bedrock version attribute, and forwards the record to the host `logger`.
///
/// The single choke point for both delivery paths ([`log_message_with_attributes`]
/// for Bedrock's own logs and [`ForeignLoggerSubscriber::event`] for dependency
/// logs), so every emitted line is sanitized and version-stamped.
fn deliver<S: std::hash::BuildHasher>(
    logger: &Arc<dyn Logger>,
    level: LogLevel,
    message: String,
    attributes: HashMap<String, String, S>,
) {
    let message = sanitize_hex_secrets(message);
    let mut attributes: HashMap<String, String> = attributes
        .into_iter()
        .map(|(key, value)| (key, sanitize_hex_secrets(value)))
        .collect();
    attributes.insert(VERSION_ATTRIBUTE_KEY.to_owned(), BEDROCK_VERSION.to_owned());
    logger.log(level, message, attributes);
}

/// Internal implementation of the logging macros. Not public API.
///
/// Splits a macro invocation into leading `key = value` fields (delivered as
/// structured attributes) and a trailing `format_args!` message, then routes to
/// [`log_message`] or [`log_message_with_attributes`] accordingly. Fields must
/// precede the format string, matching the `tracing` convention.
#[doc(hidden)]
#[macro_export]
macro_rules! __bedrock_log {
    // Munch one `key = value` field into the accumulator.
    (@acc $level:expr, [$($fields:tt)*] $key:ident = $val:expr, $($rest:tt)*) => {
        $crate::__bedrock_log!(@acc $level, [$($fields)* ($key = $val)] $($rest)*)
    };
    // No fields: use the lightweight path (no attribute map to build).
    (@acc $level:expr, [] $($fmt:tt)*) => {
        $crate::primitives::logger::log_message($level, ::core::format_args!($($fmt)*))
    };
    // One or more fields: collect them into an attribute map.
    (@acc $level:expr, [$(($key:ident = $val:expr))+] $($fmt:tt)*) => {{
        let mut attributes = ::std::collections::HashMap::new();
        $(
            attributes.insert(
                ::core::stringify!($key).to_owned(),
                ($val).to_string(),
            );
        )+
        $crate::primitives::logger::log_message_with_attributes(
            $level,
            ::core::format_args!($($fmt)*),
            attributes,
        )
    }};
    // Entry point: start munching with an empty accumulator.
    ($level:expr, $($rest:tt)*) => {
        $crate::__bedrock_log!(@acc $level, [] $($rest)*)
    };
}

/// Context-aware logging macros that automatically use the current logging context.
///
/// These macros prefix messages with the current logging context if one is set.
/// Leading `key = value` pairs (before the format string) are attached as
/// structured attributes; each value must implement [`std::fmt::Display`].
///
/// # Examples
///
/// ```rust
/// use bedrock::{trace, debug, info, warn, error};
/// use bedrock::primitives::logger::LogContext;
///
/// let _bedrock_logger_ctx = LogContext::new("SmartAccount");
/// info!("This is an info message");
/// debug!("Debug info: {}", 42);
/// info!(chain_id = 480, tx_hash = "0xabc", "user operation submitted");
/// ```
/// Logs a trace-level message with automatic context prefixing
#[macro_export]
macro_rules! trace {
    ($($arg:tt)*) => {
        $crate::__bedrock_log!($crate::primitives::logger::LogLevel::Trace, $($arg)*)
    };
}

/// Logs a debug-level message with automatic context prefixing
#[macro_export]
macro_rules! debug {
    ($($arg:tt)*) => {
        $crate::__bedrock_log!($crate::primitives::logger::LogLevel::Debug, $($arg)*)
    };
}

/// Logs an info-level message with automatic context prefixing
#[macro_export]
macro_rules! info {
    ($($arg:tt)*) => {
        $crate::__bedrock_log!($crate::primitives::logger::LogLevel::Info, $($arg)*)
    };
}

/// Logs a warning-level message with automatic context prefixing
#[macro_export]
macro_rules! warn {
    ($($arg:tt)*) => {
        $crate::__bedrock_log!($crate::primitives::logger::LogLevel::Warn, $($arg)*)
    };
}

/// Logs an error-level message with automatic context prefixing
#[macro_export]
macro_rules! error {
    ($($arg:tt)*) => {
        $crate::__bedrock_log!($crate::primitives::logger::LogLevel::Error, $($arg)*)
    };
}

/// A scope guard that sets a logging context and automatically clears it when dropped.
///
/// # Examples
///
/// ```rust
/// use bedrock::{debug, info};
/// use bedrock::primitives::logger::LogContext;
///
/// {
///     let _bedrock_logger_ctx = LogContext::new("SmartAccount");
///     info!("This will be prefixed with [Bedrock][SmartAccount]");
///     debug!("This too!");
/// } // Context automatically cleared here
/// ```
pub struct LogContext {
    previous: Option<String>,
}

impl LogContext {
    /// Creates a new logging context scope.
    ///
    /// The context will be active until this `LogContext` is dropped.
    #[must_use]
    pub fn new(module: &str) -> Self {
        let previous = LOG_CONTEXT.with(|ctx| {
            let mut ctx = ctx.borrow_mut();
            let prev = ctx.clone();
            *ctx = Some(format!("[Bedrock][{module}]"));
            prev
        });

        Self { previous }
    }
}

impl Drop for LogContext {
    fn drop(&mut self) {
        LOG_CONTEXT.with(|ctx| {
            (*ctx.borrow_mut()).clone_from(&self.previous);
        });
    }
}

/// Gets the current logging context, if any.
#[must_use]
pub fn get_context() -> Option<String> {
    LOG_CONTEXT.with(|ctx| ctx.borrow().clone())
}

/// Macro to create a scoped logging context.
///
/// # Examples
///
/// ```rust
/// use bedrock::{debug, info, with_log_context};
///
/// with_log_context!("SmartAccount" => {
///     info!("This will be prefixed with [Bedrock][SmartAccount]");
///     debug!("This too!");
/// });
/// ```
#[macro_export]
macro_rules! with_log_context {
    ($module:expr => $block:block) => {{
        let _bedrock_logger_ctx = $crate::primitives::logger::LogContext::new($module);
        $block
    }};
}

/// Sets a logging context for the current scope.
///
/// Returns a `LogContext` that should be kept alive for the duration
/// you want the context to be active.
///
/// # Examples
///
/// ```rust
/// use bedrock::{info, set_log_context};
///
/// let _bedrock_logger_ctx = set_log_context!("SmartAccount");
/// info!("This will be prefixed with [Bedrock][SmartAccount]");
/// ```
#[macro_export]
macro_rules! set_log_context {
    ($module:expr) => {
        $crate::primitives::logger::LogContext::new($module)
    };
}

/// Minimum contiguous hex digits to treat as a potential secret.
const HEX_SECRET_MIN_LEN: usize = 21;

/// Replaces hex sequences of [`HEX_SECRET_MIN_LEN`] or more digits with a
/// redacted form showing only the first and last two hex characters.
/// An optional `0x` prefix is preserved in the output.
///
/// Returns `input` unmodified (zero-allocation) when no redaction is needed.
fn sanitize_hex_secrets(input: String) -> String {
    if !has_long_hex_run(input.as_bytes()) {
        return input;
    }

    let bytes = input.as_bytes();
    let len = bytes.len();
    let mut out = String::with_capacity(len);
    let mut i = 0;

    while i < len {
        let has_prefix = i + 1 < len
            && bytes[i] == b'0'
            && (bytes[i + 1] == b'x' || bytes[i + 1] == b'X');
        let digit_start = if has_prefix { i + 2 } else { i };

        let mut j = digit_start;
        while j < len && bytes[j].is_ascii_hexdigit() {
            j += 1;
        }

        let hex_len = j - digit_start;
        if hex_len >= HEX_SECRET_MIN_LEN {
            if has_prefix {
                out.push_str("0x");
            }
            out.push(char::from(bytes[digit_start]));
            out.push(char::from(bytes[digit_start + 1]));
            out.push_str("..");
            out.push(char::from(bytes[j - 2]));
            out.push(char::from(bytes[j - 1]));
            i = j;
        } else if j > i {
            out.push_str(&input[i..j]);
            i = j;
        } else {
            // Copy one full UTF-8 character. Non-ASCII leading bytes
            // are never hex digits, so `i` is always at a char boundary.
            let next = input.ceil_char_boundary(i + 1);
            out.push_str(&input[i..next]);
            i = next;
        }
    }

    out
}

fn has_long_hex_run(bytes: &[u8]) -> bool {
    let mut run: usize = 0;
    for &b in bytes {
        if b.is_ascii_hexdigit() {
            run += 1;
            if run >= HEX_SECRET_MIN_LEN {
                return true;
            }
        } else {
            run = 0;
        }
    }
    false
}

// SECTION: `tracing` dependency capture

/// Best-effort install of the global `tracing` subscriber and
/// forward dependency (non-Bedrock) logs to the host logger.
///
/// Bedrock's own logging does not depend on this succeeding.
fn install_dependency_capture() {
    let subscriber = ForeignLoggerSubscriber {
        next_span_id: AtomicU64::new(1),
    };
    if tracing::subscriber::set_global_default(subscriber).is_err() {
        crate::warn!(
            "another global tracing subscriber is already installed; siegel and \
             dependency logs will not be forwarded (Bedrock's own logs are unaffected)"
        );
        return;
    }

    let _ =
        tracing_log::LogTracer::init_with_filter(tracing_log::log::LevelFilter::Warn);
}

/// A best-effort [`tracing::Subscriber`] that forwards **non-Bedrock** events
/// (siegel, plus dependencies that log via `tracing`/`log`) to the host [`Logger`].
///
/// Spans are not recorded.
struct ForeignLoggerSubscriber {
    /// Monotonic source of span identifiers, required by the `tracing` contract.
    next_span_id: AtomicU64,
}

impl Subscriber for ForeignLoggerSubscriber {
    /// Bedrock's own events use the direct path ([`log_message`]) and are ignored
    /// here to avoid double-forwarding. Dependency (non-Bedrock) events are
    /// forwarded at `WARN` and above; their debug/trace noise is rejected at the
    /// callsite so it is never even formatted.
    fn enabled(&self, metadata: &Metadata<'_>) -> bool {
        if is_bedrock_target(metadata) {
            return false;
        }
        let level = *metadata.level();
        level == Level::WARN || level == Level::ERROR
    }

    fn new_span(&self, _span: &span::Attributes<'_>) -> span::Id {
        let id = self.next_span_id.fetch_add(1, Ordering::Relaxed);
        span::Id::from_u64(id)
    }

    fn record(&self, _span: &span::Id, _values: &span::Record<'_>) {}

    fn record_follows_from(&self, _span: &span::Id, _follows: &span::Id) {}

    /// Forwards a dependency event to the host logger. Structured fields are
    /// forwarded as log attributes; both message and attributes are hex-secret
    /// redacted and version-stamped by [`deliver`].
    fn event(&self, event: &Event<'_>) {
        let Some(logger) = LOGGER_INSTANCE.get() else {
            return;
        };
        let mut visitor = EventVisitor::default();
        event.record(&mut visitor);
        let level = log_level(*event.metadata().level());
        deliver(logger, level, visitor.message, visitor.attributes);
    }

    fn enter(&self, _span: &span::Id) {}

    fn exit(&self, _span: &span::Id) {}
}

/// Returns `true` when the event originates from the `bedrock` crate.
fn is_bedrock_target(metadata: &Metadata<'_>) -> bool {
    metadata.target().starts_with("bedrock")
        || metadata
            .module_path()
            .is_some_and(|module_path| module_path.starts_with("bedrock"))
}

/// Collects a `tracing` event's fields.
///
/// The `message` field (the format string passed to the logging macros) forms
/// the log body; every other structured field is collected into `attributes` so
/// it is forwarded to the host as a log attribute rather than being dropped.
#[derive(Default)]
struct EventVisitor {
    message: String,
    attributes: HashMap<String, String>,
}

impl tracing::field::Visit for EventVisitor {
    fn record_debug(
        &mut self,
        field: &tracing::field::Field,
        value: &dyn std::fmt::Debug,
    ) {
        use std::fmt::Write as _;
        if field.name() == "message" {
            let _ = write!(self.message, "{value:?}");
        } else {
            self.attributes
                .insert(field.name().to_owned(), format!("{value:?}"));
        }
    }
}

/// Converts a [`tracing::Level`] to a [`LogLevel`].
///
/// `tracing` levels are associated constants rather than enum variants, so this
/// uses equality comparisons; the final branch necessarily maps [`Level::TRACE`].
fn log_level(level: Level) -> LogLevel {
    if level == Level::ERROR {
        LogLevel::Error
    } else if level == Level::WARN {
        LogLevel::Warn
    } else if level == Level::INFO {
        LogLevel::Info
    } else if level == Level::DEBUG {
        LogLevel::Debug
    } else {
        LogLevel::Trace
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn short_hex_passes_through() {
        let input = "tx hash is abcdef1";
        assert_eq!(sanitize_hex_secrets(input.to_string()), input);
    }

    #[test]
    fn long_hex_is_redacted() {
        let input = "key=deadbeefcafebabe1234567890abcdef1234567890abcdef end";
        assert_eq!(sanitize_hex_secrets(input.to_string()), "key=de..ef end");
    }

    #[test]
    fn hex_with_0x_prefix() {
        let input = "addr 0xdeadbeefcafebabe1234567890abcdef1234567890abcdef end";
        assert_eq!(sanitize_hex_secrets(input.to_string()), "addr 0xde..ef end");
    }

    #[test]
    fn multiple_secrets_redacted() {
        let a = "a".repeat(32);
        let b = "b".repeat(32);
        let input = format!("x={a} y={b}");
        assert_eq!(sanitize_hex_secrets(input), "x=aa..aa y=bb..bb");
    }

    #[test]
    fn exactly_threshold_is_redacted() {
        let input = "a".repeat(HEX_SECRET_MIN_LEN);
        assert_eq!(sanitize_hex_secrets(input), "aa..aa");
    }

    #[test]
    fn below_threshold_passes() {
        let input = "a".repeat(HEX_SECRET_MIN_LEN - 1);
        assert_eq!(sanitize_hex_secrets(input.clone()), input);
    }

    #[test]
    fn no_hex_passes_through() {
        let input = "hello world, no hex here!";
        assert_eq!(sanitize_hex_secrets(input.to_string()), input);
    }

    #[test]
    fn empty_string() {
        assert_eq!(sanitize_hex_secrets(String::new()), "");
    }

    #[test]
    fn uppercase_hex_redacted() {
        let input = "DEADBEEFCAFEBABE1234567890ABCDEF1234567890ABCDEF";
        assert_eq!(sanitize_hex_secrets(input.to_string()), "DE..EF");
    }

    #[test]
    fn mixed_text_and_hex() {
        let secret = "f".repeat(64);
        let input = format!("user=alice secret={secret} action=login");
        assert_eq!(
            sanitize_hex_secrets(input),
            "user=alice secret=ff..ff action=login"
        );
    }

    #[test]
    fn utf8_preserved_alongside_hex_redaction() {
        let secret = "a".repeat(32);
        let input = format!("clé={secret} résumé");
        assert_eq!(sanitize_hex_secrets(input), "clé=aa..aa résumé");
    }

    #[test]
    fn multibyte_utf8_no_hex() {
        let input = "café naïve 日本語".to_string();
        assert_eq!(sanitize_hex_secrets(input.clone()), input);
    }

    #[test]
    fn no_alloc_when_clean() {
        let input = String::from("no secrets here");
        let ptr = input.as_ptr();
        let output = sanitize_hex_secrets(input);
        assert_eq!(output.as_ptr(), ptr, "should return same allocation");
    }

    /// A single captured log line: level, message, and attributes.
    type CapturedRecord = (LogLevel, String, HashMap<String, String>);

    /// A [`Logger`] that records every delivered log line for assertions.
    #[derive(Default)]
    struct CapturingLogger {
        records: std::sync::Mutex<Vec<CapturedRecord>>,
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
                .unwrap()
                .push((level, message, attributes));
        }
    }

    #[test]
    fn deliver_attaches_version_and_sanitizes_attributes() {
        let capturing = Arc::new(CapturingLogger::default());
        let logger: Arc<dyn Logger> = capturing.clone();

        let secret = "a".repeat(32);
        let mut attributes = HashMap::new();
        attributes.insert("factor".to_owned(), secret.clone());
        attributes.insert("plain".to_owned(), "value".to_owned());

        deliver(
            &logger,
            LogLevel::Info,
            format!("secret={secret}"),
            attributes,
        );

        let records = capturing.records.lock().unwrap().clone();
        assert_eq!(records.len(), 1);
        let (level, message, attrs) = &records[0];
        assert!(matches!(level, LogLevel::Info));
        assert_eq!(message, "secret=aa..aa");
        assert_eq!(attrs.get("factor").map(String::as_str), Some("aa..aa"));
        assert_eq!(attrs.get("plain").map(String::as_str), Some("value"));
        assert_eq!(
            attrs.get(VERSION_ATTRIBUTE_KEY).map(String::as_str),
            Some(env!("CARGO_PKG_VERSION")),
        );
    }

    #[test]
    fn deliver_overrides_caller_supplied_version() {
        let capturing = Arc::new(CapturingLogger::default());
        let logger: Arc<dyn Logger> = capturing.clone();

        let mut attributes = HashMap::new();
        attributes.insert(VERSION_ATTRIBUTE_KEY.to_owned(), "0.0.0-fake".to_owned());
        deliver(&logger, LogLevel::Warn, "msg".to_owned(), attributes);

        let records = capturing.records.lock().unwrap().clone();
        let (_, _, attrs) = &records[0];
        assert_eq!(
            attrs.get(VERSION_ATTRIBUTE_KEY).map(String::as_str),
            Some(env!("CARGO_PKG_VERSION")),
        );
    }

    #[test]
    fn macros_forward_fields_and_version() {
        // Owns the process-global logger for this crate's unit-test binary.
        // Records are matched by unique markers so logs emitted by other tests
        // sharing the global logger do not affect these assertions.
        let capturing = Arc::new(CapturingLogger::default());
        let global: Arc<dyn Logger> = capturing.clone();
        assert!(
            LOGGER_INSTANCE.set(global).is_ok(),
            "no other test may install the global logger",
        );

        info!(chain_id = 480, tx = "0xabc", "wf-marker-fields submitted");
        warn!("wf-marker-plain no fields here");

        let records = capturing.records.lock().unwrap().clone();

        let (level, _, attrs) = records
            .iter()
            .find(|(_, message, _)| message.contains("wf-marker-fields"))
            .expect("fielded record captured");
        assert!(matches!(level, LogLevel::Info));
        assert_eq!(attrs.get("chain_id").map(String::as_str), Some("480"));
        assert_eq!(attrs.get("tx").map(String::as_str), Some("0xabc"));
        assert_eq!(
            attrs.get(VERSION_ATTRIBUTE_KEY).map(String::as_str),
            Some(env!("CARGO_PKG_VERSION")),
        );

        let (level, _, attrs) = records
            .iter()
            .find(|(_, message, _)| message.contains("wf-marker-plain"))
            .expect("plain record captured");
        assert!(matches!(level, LogLevel::Warn));
        assert_eq!(
            attrs.get(VERSION_ATTRIBUTE_KEY).map(String::as_str),
            Some(env!("CARGO_PKG_VERSION")),
        );
        assert_eq!(
            attrs.len(),
            1,
            "version is the only attribute on a fieldless log"
        );
    }
}
