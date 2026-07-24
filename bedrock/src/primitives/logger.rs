use std::cell::RefCell;
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
///
/// use bedrock::primitives::logger::{Logger, LogLevel};
///
/// struct MyLogger;
///
/// impl Logger for MyLogger {
///     fn log(&self, level: LogLevel, message: String) {
///         println!("[{:?}] {}", level, message);
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
///    func log(level: Bedrock.LogLevel, message: String) {
///        Log.log(level.toCoreLevel(), message)
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
    fn log(&self, level: LogLevel, message: String);
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

/// A best-effort [`tracing::Subscriber`] that forwards **non-Bedrock** events
/// (siegel, plus dependencies that log via `tracing`/`log`) to the host [`Logger`].
///
/// Bedrock's own logs never flow through here — they are delivered directly by
/// [`log_message`], so they reach the host even when another Rust library in the
/// process owns the global `tracing` dispatcher. This subscriber is installed as
/// that global default only when it is still free. Spans are not recorded.
struct ForeignLoggerSubscriber {
    /// Monotonic source of span identifiers, required by the `tracing` contract.
    next_span_id: AtomicU64,
}

impl Subscriber for ForeignLoggerSubscriber {
    /// Bedrock's own events use the direct path ([`log_message`]) and are ignored
    /// here to avoid double-forwarding. Dependency (non-Bedrock) events are
    /// forwarded at `INFO` and above; their debug/trace noise is rejected at the
    /// callsite so it is never even formatted.
    fn enabled(&self, metadata: &Metadata<'_>) -> bool {
        if is_bedrock_target(metadata) {
            return false;
        }
        let level = *metadata.level();
        level != Level::DEBUG && level != Level::TRACE
    }

    fn new_span(&self, _span: &span::Attributes<'_>) -> span::Id {
        // `fetch_add` starts at 1 so the id is never 0 (which `Id::from_u64` rejects).
        let id = self.next_span_id.fetch_add(1, Ordering::Relaxed);
        span::Id::from_u64(id)
    }

    fn record(&self, _span: &span::Id, _values: &span::Record<'_>) {}

    fn record_follows_from(&self, _span: &span::Id, _follows: &span::Id) {}

    /// Forwards a dependency event to the host logger after redacting hex secrets.
    fn event(&self, event: &Event<'_>) {
        let Some(logger) = LOGGER_INSTANCE.get() else {
            return;
        };
        let mut visitor = EventVisitor::default();
        event.record(&mut visitor);
        let message = sanitize_hex_secrets(visitor.into_message());
        let level = log_level(*event.metadata().level());
        logger.log(level, message);
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

/// Collects a `tracing` event's fields into a single log line.
///
/// The `message` field (the format string passed to the logging macros) forms
/// the body; any additional structured fields are appended as ` key=value` so
/// they are never silently dropped.
#[derive(Default)]
struct EventVisitor {
    message: String,
    fields: String,
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
            let _ = write!(self.fields, " {}={value:?}", field.name());
        }
    }
}

impl EventVisitor {
    /// Consumes the visitor, returning the message with structured fields appended.
    fn into_message(mut self) -> String {
        self.message.push_str(&self.fields);
        self.message
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

/// The host-provided logger. Bedrock's own logs are delivered here directly by
/// [`log_message`], independent of the global `tracing` dispatcher.
static LOGGER_INSTANCE: OnceLock<Arc<dyn Logger>> = OnceLock::new();

/// Sets the logger that receives Bedrock's log messages.
///
/// Bedrock's own instrumentation is delivered to `logger` **directly**, so it is
/// unaffected by whichever Rust library in the process owns the global `tracing`
/// dispatcher. As a best effort, this also installs a global `tracing` subscriber
/// (plus a `log` bridge) to forward *dependency* logs — notably siegel's `mlock`
/// warning — to the same logger; if the global dispatcher is already taken, that
/// extra capture is skipped and only dependency logs are missed.
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

/// Best-effort install of the global `tracing` subscriber and `log` bridge that
/// forward dependency (non-Bedrock) logs to the host logger.
///
/// Bedrock's own logging does not depend on this succeeding. If another global
/// subscriber already owns the dispatcher, dependency logs (e.g. siegel's `mlock`
/// warning) are not captured; that degradation is reported once, via the direct
/// path, so it is not silent.
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

    // Bridge dependencies that still use the `log` crate; `INFO`+ only, since the
    // subscriber drops dependency debug/trace anyway.
    let _ =
        tracing_log::LogTracer::init_with_filter(tracing_log::log::LevelFilter::Info);
}

/// Delivers a Bedrock-originated log record directly to the host [`Logger`],
/// bypassing the global `tracing` dispatcher so delivery never depends on Bedrock
/// owning it. Applies the active [`LogContext`] prefix and hex-secret redaction.
/// A no-op until [`set_logger`] has been called.
#[doc(hidden)]
pub fn log_message(level: LogLevel, args: std::fmt::Arguments<'_>) {
    let Some(logger) = LOGGER_INSTANCE.get() else {
        return;
    };
    let message = get_context()
        .map_or_else(|| args.to_string(), |context| format!("{context} {args}"));
    logger.log(level, sanitize_hex_secrets(message));
}

/// Context-aware logging macros that automatically use the current logging context.
///
/// These macros allow you to log messages that will be automatically prefixed
/// with the current logging context if one is set.
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
/// ```
/// Logs a trace-level message with automatic context prefixing
#[macro_export]
macro_rules! trace {
    ($($arg:tt)*) => {
        $crate::primitives::logger::log_message(
            $crate::primitives::logger::LogLevel::Trace,
            format_args!($($arg)*),
        )
    };
}

/// Logs a debug-level message with automatic context prefixing
#[macro_export]
macro_rules! debug {
    ($($arg:tt)*) => {
        $crate::primitives::logger::log_message(
            $crate::primitives::logger::LogLevel::Debug,
            format_args!($($arg)*),
        )
    };
}

/// Logs an info-level message with automatic context prefixing
#[macro_export]
macro_rules! info {
    ($($arg:tt)*) => {
        $crate::primitives::logger::log_message(
            $crate::primitives::logger::LogLevel::Info,
            format_args!($($arg)*),
        )
    };
}

/// Logs a warning-level message with automatic context prefixing
#[macro_export]
macro_rules! warn {
    ($($arg:tt)*) => {
        $crate::primitives::logger::log_message(
            $crate::primitives::logger::LogLevel::Warn,
            format_args!($($arg)*),
        )
    };
}

/// Logs an error-level message with automatic context prefixing
#[macro_export]
macro_rules! error {
    ($($arg:tt)*) => {
        $crate::primitives::logger::log_message(
            $crate::primitives::logger::LogLevel::Error,
            format_args!($($arg)*),
        )
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
}
