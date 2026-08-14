use std::cell::RefCell;
use std::collections::HashMap;
use std::future::Future;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};

use tracing::{span, Event, Level, Metadata, Subscriber};
use tracing_log::NormalizeEvent as _;

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
///        case .warn:
///            return .warn
///        case .error:
///            return .error
///        case .critical:
///            return .critical
///        }
///    }
///}
/// ```
///
/// Map [`LogLevel::Critical`] to a severity **above** error (Datadog's `critical`
/// status, `Logger.critical` on `dd-sdk-ios`). Collapsing it into `.error` silently
/// discards the only signal that distinguishes an alertable record from routine
/// error noise.
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
///
/// Variants are ordered by ascending severity and **must only be appended to**:
/// `UniFFI` transfers them by ordinal, so reordering silently remaps the severity of
/// every record crossing the FFI boundary.
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
    /// Designates state that needs immediate attention (a corrupt manifest, an
    /// inconsistent remote account). Emitted only by [`critical`](crate::critical),
    /// and expected to carry a very low alerting threshold on the host.
    Critical,
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

/// Attribute key naming the dependency a forwarded record came from (its `tracing`
/// target). Present only on dependency logs, never on Bedrock's own.
pub const DEPENDENCY_ATTRIBUTE_KEY: &str = "bedrock_dependency";

/// Delivers a Bedrock-originated log record directly to the host [`Logger`],
/// bypassing the global `tracing` dispatcher so delivery never depends on Bedrock
/// owning it. Applies the active [`LogContext`] prefix and hex-secret redaction.
/// A no-op until [`set_logger`] has been called.
#[doc(hidden)]
pub fn log_message(level: LogLevel, args: std::fmt::Arguments<'_>) {
    log_message_with_attributes(level, args, HashMap::new);
}

/// Like [`log_message`], but attaches structured attributes to the log line.
///
/// `attributes` is only invoked once a host logger is known to be installed, so a
/// disabled logger never pays to format attribute values — matching how
/// `format_args!` defers formatting the message.
///
/// Attribute values are hex-secret redacted just like the message. The
/// [`VERSION_ATTRIBUTE_KEY`] attribute is always added by [`deliver`], and takes
/// precedence over any caller-supplied value for that key.
#[doc(hidden)]
pub fn log_message_with_attributes<F>(
    level: LogLevel,
    args: std::fmt::Arguments<'_>,
    attributes: F,
) where
    F: FnOnce() -> HashMap<String, String>,
{
    log_to(LOGGER_INSTANCE.get(), level, args, attributes);
}

/// Applies the [`LogContext`] prefix and hands the record to `logger`, doing no work
/// whatsoever when it is `None`.
///
/// Split out of [`log_message_with_attributes`] so the disabled path is testable
/// without depending on the state of the process-global logger.
fn log_to<F>(
    logger: Option<&Arc<dyn Logger>>,
    level: LogLevel,
    args: std::fmt::Arguments<'_>,
    attributes: F,
) where
    F: FnOnce() -> HashMap<String, String>,
{
    let Some(logger) = logger else {
        return;
    };
    let message = get_context()
        .map_or_else(|| args.to_string(), |context| format!("{context} {args}"));
    deliver(logger, level, message, attributes());
}

/// Redacts hex secrets from the message and attribute values, attaches the
/// Bedrock version attribute, and forwards the record to the host `logger`.
///
/// The single choke point for both delivery paths ([`log_message_with_attributes`]
/// for Bedrock's own logs and [`ForeignLoggerSubscriber::event`] for dependency
/// logs), so every emitted line is sanitized and version-stamped.
fn deliver(
    logger: &Arc<dyn Logger>,
    level: LogLevel,
    message: String,
    mut attributes: HashMap<String, String>,
) {
    for value in attributes.values_mut() {
        *value = sanitize_hex_secrets(std::mem::take(value));
    }
    attributes.insert(VERSION_ATTRIBUTE_KEY.to_owned(), BEDROCK_VERSION.to_owned());
    logger.log(level, sanitize_hex_secrets(message), attributes);
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
    // One or more fields: collect them into an attribute map. The map is built
    // inside a closure so that formatting each value is skipped entirely when no
    // host logger is installed, just as `format_args!` defers the message.
    (@acc $level:expr, [$(($key:ident = $val:expr))+] $($fmt:tt)*) => {
        $crate::primitives::logger::log_message_with_attributes(
            $level,
            ::core::format_args!($($fmt)*),
            || {
                let mut attributes = ::std::collections::HashMap::new();
                $(
                    attributes.insert(
                        ::core::stringify!($key).to_owned(),
                        ($val).to_string(),
                    );
                )+
                attributes
            },
        )
    };
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
/// # Syntax
///
/// A format string is **mandatory** and must come after any fields. Keys are plain
/// identifiers: `tracing`'s `?value`/`%value` sigils and its bare-identifier
/// shorthand are not supported, and a dotted key (`http.status_code = 500`) does not
/// parse. Prefer the value the log is *about* as a field over interpolating it into
/// the message, so backends can filter and aggregate on it.
///
/// Avoid attribute keys that log backends reserve for their own use — `message`,
/// `status`, `service`, `host`, `timestamp`, `trace_id`, and the `error.*` family:
/// only [`VERSION_ATTRIBUTE_KEY`] is protected from being overwritten here, so a
/// clashing key silently shadows the host's field instead.
///
/// # Evaluation
///
/// Field values are evaluated **only when a host logger is installed**, whereas
/// message arguments are always evaluated. Keep field expressions side-effect free:
/// `info!(n = counter.fetch_add(1, Ordering::Relaxed), "...")` would increment in
/// production and not in a test that never calls [`set_logger`].
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

/// Logs a message at [`LogLevel::Critical`], for state that needs immediate
/// attention. There's usually very low alerting threshold for these.
///
/// The severity is carried by the level, not by a tag in the message, so alerts match
/// on the record's status rather than its text. Accepts structured fields like the
/// other macros.
///
/// # Alerting
///
/// Records previously arrived as `ERROR` with a literal `[Critical] ` prefix in the
/// message. Any monitor still matching that text will not match these, so monitors
/// have to move to the record's status (Datadog's `critical`, syslog severity 2)
/// before a release carrying this ships. See [`LogLevel::Critical`].
#[macro_export]
macro_rules! critical {
    ($($arg:tt)*) => {
        $crate::__bedrock_log!($crate::primitives::logger::LogLevel::Critical, $($arg)*)
    };
}

/// A scope guard that sets a logging context and automatically clears it when dropped.
///
/// The context is thread-local, so a guard is only valid for synchronous code. Held
/// across an `.await` it is silently lost as soon as the future resumes on another
/// runtime worker; use [`in_log_context`] for anything `async`.
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

/// Runs `future` in the [`LogContext`] of `module`, re-applying it on every poll.
///
/// The context is thread-local while a future may resume on any runtime worker, so a
/// single guard held across an `.await` would drop the prefix from every record
/// emitted after the first suspension (and restore a stale context onto whichever
/// worker resumed it). Re-applying the context per poll keeps the prefix on
/// everything the future logs, nested synchronous calls included.
///
/// [`bedrock_export`](crate::bedrock_export) wraps every exported `async` method in it.
pub async fn in_log_context<F>(module: &str, future: F) -> F::Output
where
    F: Future + Send,
    F::Output: Send,
{
    let mut future = std::pin::pin!(future);
    std::future::poll_fn(move |cx| {
        let _bedrock_logger_ctx = LogContext::new(module);
        future.as_mut().poll(cx)
    })
    .await
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

    if let Err(error) =
        tracing_log::LogTracer::init_with_filter(tracing_log::log::LevelFilter::Warn)
    {
        // Not fatal, but it silently halves dependency coverage for the process
        // lifetime, so say so rather than leaving triage to guess.
        crate::warn!(
            error_message = error,
            "another `log` logger is already installed; dependencies logging via the \
             `log` crate will not be forwarded (`tracing`-based ones are unaffected)"
        );
    }
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
        !is_bedrock_target(metadata)
            && is_forwardable_dependency_level(*metadata.level())
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
    ///
    /// The originating crate is attached under [`DEPENDENCY_ATTRIBUTE_KEY`] so a
    /// forwarded warning can be attributed to a dependency without parsing its text.
    fn event(&self, event: &Event<'_>) {
        let Some(logger) = LOGGER_INSTANCE.get() else {
            return;
        };
        // Records bridged from the `log` crate by `tracing_log::LogTracer` all share
        // one static callsite whose target is the literal "log"; the real target only
        // arrives as a `log.target` field. Normalizing recovers it, so a `log`-based
        // dependency is attributed to itself rather than to "log".
        let normalized = event.normalized_metadata();
        let metadata = normalized.as_ref().unwrap_or_else(|| event.metadata());
        let mut visitor = EventVisitor::default();
        event.record(&mut visitor);
        visitor.attributes.insert(
            DEPENDENCY_ATTRIBUTE_KEY.to_owned(),
            metadata.target().to_owned(),
        );
        // A field-only event (`tracing::error!(code = 500)`) records no `message`
        // field. Hosts and log backends key their views on the body, so fall back to
        // the target: it is constant per dependency, which groups. `metadata.name()`
        // would not — it embeds the dependency's build-time source path and line.
        let message = if visitor.message.is_empty() {
            format!("{} event without a message", metadata.target())
        } else {
            visitor.message
        };
        let level = log_level(*metadata.level());
        deliver(logger, level, message, visitor.attributes);
    }

    fn enter(&self, _span: &span::Id) {}

    fn exit(&self, _span: &span::Id) {}
}

/// Whether a dependency record at `level` is severe enough to forward.
///
/// Dependency debug and trace noise is rejected at the callsite so it is never even
/// formatted; only `WARN` and above reach the host.
fn is_forwardable_dependency_level(level: Level) -> bool {
    level == Level::WARN || level == Level::ERROR
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

/// Bookkeeping fields that `tracing_log::LogTracer` attaches to every record it
/// bridges from the `log` crate. They are plumbing, not the dependency's own data:
/// `log.target` is recovered via `normalized_metadata` instead, and `log.file` is the
/// dependency's **build-time** absolute path, which must not reach the host.
const LOG_BRIDGE_FIELDS: [&str; 4] =
    ["log.target", "log.module_path", "log.file", "log.line"];

impl EventVisitor {
    /// Records `value` under `name`, unless it is `log` bridge plumbing.
    fn record_attribute(&mut self, name: &str, value: String) {
        if LOG_BRIDGE_FIELDS.contains(&name) {
            return;
        }
        self.attributes.insert(name.to_owned(), value);
    }
}

impl tracing::field::Visit for EventVisitor {
    /// Records string fields verbatim. Overriding this (rather than letting the
    /// default forward to [`Self::record_debug`]) keeps string attribute values
    /// unquoted, which log backends can filter and aggregate on directly.
    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        if field.name() == "message" {
            self.message.push_str(value);
        } else {
            self.record_attribute(field.name(), value.to_owned());
        }
    }

    /// Fallback for non-string fields (numbers, booleans, and other `Debug`
    /// types). `Debug` already renders these without surrounding quotes.
    fn record_debug(
        &mut self,
        field: &tracing::field::Field,
        value: &dyn std::fmt::Debug,
    ) {
        use std::fmt::Write as _;
        if field.name() == "message" {
            let _ = write!(self.message, "{value:?}");
        } else {
            self.record_attribute(field.name(), format!("{value:?}"));
        }
    }
}

/// Converts a [`tracing::Level`] to a [`LogLevel`].
///
/// `tracing` levels are associated constants rather than enum variants, so this
/// uses equality comparisons; the final branch necessarily maps [`Level::TRACE`].
///
/// [`LogLevel::Critical`] is unreachable here: `tracing` has no severity above
/// `ERROR`, so only [`critical`](crate::critical) can produce it.
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

/// Tests that exercise delivery through the process-global logger: the log context
/// is what makes every record alertable, so its scoping is tested directly (a lost
/// context means logs a monitor can no longer match), as are the level and
/// attributes the host ultimately receives.
///
/// [`set_logger`] keeps the first logger for the whole process, so every global-logger
/// test belongs in this module and must be `#[serial]`.
#[cfg(test)]
mod delivery_tests {
    use super::{
        get_context, in_log_context, set_logger, span, Event, LogContext, LogLevel,
        Logger, Metadata, Subscriber, VERSION_ATTRIBUTE_KEY,
    };
    use serial_test::serial;
    use std::collections::HashMap;
    use std::future::Future;
    use std::pin::Pin;
    use std::sync::{Arc, Mutex};
    use std::task::{Context, Poll, Waker};

    /// A single record as the host logger saw it: level, message, and attributes.
    type Captured = (LogLevel, String, HashMap<String, String>);

    /// Records delivered to [`CapturingLogger`].
    static CAPTURED: Mutex<Vec<Captured>> = Mutex::new(Vec::new());

    /// Captures the fully formatted records, i.e. what the host logger receives.
    struct CapturingLogger;

    impl Logger for CapturingLogger {
        fn log(
            &self,
            level: LogLevel,
            message: String,
            attributes: HashMap<String, String>,
        ) {
            captured().push((level, message, attributes));
        }
    }

    /// Locks [`CAPTURED`], recovering from poisoning.
    ///
    /// A failing assertion in one test would otherwise poison the sink and make every
    /// later test in this module fail with `PoisonError` instead of its own assertion,
    /// hiding which test actually broke.
    fn captured() -> std::sync::MutexGuard<'static, Vec<Captured>> {
        CAPTURED
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Marker for the record [`capture_records`] emits to confirm delivery.
    const PROBE: &str = "capture-probe";

    /// Installs [`CapturingLogger`] and drops records left by an earlier test.
    ///
    /// Callers must be `#[serial]` and must assert on the records they recognize:
    /// other tests logging in parallel land in the same sink.
    ///
    /// `set_logger` keeps whichever logger got there first, so this probes delivery
    /// and fails naming that cause. Without the probe, an earlier `set_logger` (for
    /// example `StdoutLogger` under `--include-ignored`) makes every test in this
    /// module fail with a misleading "no record containing ...".
    fn capture_records() {
        set_logger(Arc::new(CapturingLogger));
        captured().clear();

        crate::trace!("{PROBE}");
        let delivered = captured().iter().any(|(_, m, _)| m.contains(PROBE));
        assert!(
            delivered,
            "another logger owns the process-global slot; CapturingLogger sees nothing",
        );
        captured().clear();
    }

    /// The record containing `needle`, or a panic naming everything captured.
    fn captured_record(needle: &str) -> Captured {
        let captured = captured();
        captured
            .iter()
            .find(|(_, message, _)| message.contains(needle))
            .unwrap_or_else(|| {
                panic!("no record containing {needle:?} in {captured:?}")
            })
            .clone()
    }

    /// Returns `Pending` on the first poll only, so the caller has to poll twice.
    #[derive(Default)]
    struct YieldOnce(bool);

    impl Future for YieldOnce {
        type Output = ();

        fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
            if self.0 {
                return Poll::Ready(());
            }
            self.0 = true;
            cx.waker().wake_by_ref();
            Poll::Pending
        }
    }

    #[test]
    fn guard_scopes_the_context_to_its_lifetime() {
        assert!(get_context().is_none());
        {
            let _bedrock_logger_ctx = LogContext::new("Backup");
            assert_eq!(get_context().as_deref(), Some("[Bedrock][Backup]"));
        }
        assert!(get_context().is_none());
    }

    /// A runtime may resume a task on any worker. The context must be re-applied by
    /// whichever thread polls the future, otherwise every record after the first
    /// `.await` loses its tag.
    #[test]
    fn context_is_reapplied_when_a_future_resumes_on_another_thread() {
        let mut future = Box::pin(in_log_context("TurnkeyMigration", async {
            let on_first_poll = get_context();
            YieldOnce::default().await;
            (on_first_poll, get_context())
        }));

        assert!(
            future
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending(),
            "the future must suspend once for this test to be meaningful"
        );

        let (first, second) = std::thread::scope(|scope| {
            scope
                .spawn(|| {
                    let polled = future
                        .as_mut()
                        .poll(&mut Context::from_waker(Waker::noop()));
                    let Poll::Ready(observed) = polled else {
                        panic!("future should have completed on its second poll");
                    };
                    observed
                })
                .join()
                .expect("polling thread panicked")
        });

        assert_eq!(first.as_deref(), Some("[Bedrock][TurnkeyMigration]"));
        assert_eq!(
            second.as_deref(),
            Some("[Bedrock][TurnkeyMigration]"),
            "the resuming thread must see the context"
        );
        assert!(
            get_context().is_none(),
            "the context must not outlive the future"
        );
    }

    /// End to end: an exported `async` method logs on both sides of an `.await`, and
    /// both records have to reach the host logger tagged.
    #[cfg(feature = "tooling_tests")]
    #[tokio::test]
    #[serial]
    async fn exported_async_method_tags_records_around_an_await() {
        capture_records();

        crate::primitives::tooling_tests::ToolingDemo::new()
            .demo_async_operation(1)
            .await
            .expect("the demo operation succeeds under 5s");

        for needle in ["Starting async operation", "Async operation successful"] {
            let (_, record, _) = captured_record(needle);
            assert!(
                record.starts_with("[Bedrock][ToolingDemo] "),
                "untagged record: {record}"
            );
        }
    }

    /// Criticals carry their severity in the level, not as a tag in the message, so
    /// the host (and Datadog) can alert on status instead of matching text.
    #[test]
    #[serial]
    fn critical_records_use_the_critical_level_without_a_message_tag() {
        capture_records();

        let _bedrock_logger_ctx = LogContext::new("Backup");
        crate::critical!(
            designator = "orb_pkg",
            "checksum for the file is unreadable"
        );

        let (level, message, attributes) = captured_record("is unreadable");
        assert!(
            matches!(level, LogLevel::Critical),
            "wrong level: {level:?}"
        );
        assert_eq!(
            message,
            "[Bedrock][Backup] checksum for the file is unreadable"
        );
        assert_eq!(
            attributes.get("designator").map(String::as_str),
            Some("orb_pkg")
        );
    }

    /// Structured fields reach the host as attributes, and every record carries the
    /// Bedrock version regardless of whether the call site supplied fields.
    #[test]
    #[serial]
    fn macros_forward_fields_and_version() {
        capture_records();

        crate::info!(chain_id = 480, tx = "0xabc", "user operation submitted");
        crate::warn!("no fields here");

        let (level, _, attributes) = captured_record("user operation submitted");
        assert!(matches!(level, LogLevel::Info), "wrong level: {level:?}");
        assert_eq!(attributes.get("chain_id").map(String::as_str), Some("480"));
        assert_eq!(attributes.get("tx").map(String::as_str), Some("0xabc"));
        assert_eq!(
            attributes.get(VERSION_ATTRIBUTE_KEY).map(String::as_str),
            Some(env!("CARGO_PKG_VERSION")),
        );

        let (level, _, attributes) = captured_record("no fields here");
        assert!(matches!(level, LogLevel::Warn), "wrong level: {level:?}");
        assert_eq!(
            attributes.get(VERSION_ATTRIBUTE_KEY).map(String::as_str),
            Some(env!("CARGO_PKG_VERSION")),
        );
        assert_eq!(
            attributes.len(),
            1,
            "version is the only attribute on a fieldless log"
        );
    }

    /// Relays every event into the real [`ForeignLoggerSubscriber::event`] path.
    ///
    /// `ForeignLoggerSubscriber::enabled` rejects anything whose target *or* module
    /// path starts with `bedrock`, which is every event this file can emit (see
    /// [`in_crate_events_are_never_treated_as_dependencies`]). This relay therefore
    /// accepts everything so the real `event` body can be driven; the filter itself
    /// is asserted separately.
    struct RelayToForeign(super::ForeignLoggerSubscriber);

    impl Subscriber for RelayToForeign {
        fn enabled(&self, _: &Metadata<'_>) -> bool {
            true
        }
        fn new_span(&self, _: &span::Attributes<'_>) -> span::Id {
            span::Id::from_u64(1)
        }
        fn record(&self, _: &span::Id, _: &span::Record<'_>) {}
        fn record_follows_from(&self, _: &span::Id, _: &span::Id) {}
        fn event(&self, event: &Event<'_>) {
            self.0.event(event);
        }
        fn enter(&self, _: &span::Id) {}
        fn exit(&self, _: &span::Id) {}
    }

    /// The dependency path is the one place log values are third-party controlled, so
    /// it is the path that most needs to be shown going through [`super::deliver`]:
    /// redacted, version-stamped, and attributed to the crate it came from.
    #[test]
    #[serial]
    fn dependency_events_are_redacted_stamped_and_attributed() {
        use super::{ForeignLoggerSubscriber, DEPENDENCY_ATTRIBUTE_KEY};
        use std::sync::atomic::AtomicU64;

        capture_records();

        let relay = Arc::new(RelayToForeign(ForeignLoggerSubscriber {
            next_span_id: AtomicU64::new(1),
        }));
        let secret = "a".repeat(32);
        tracing::subscriber::with_default(relay, || {
            tracing::warn!(target: "siegel", key = %secret, "dep-marker mlock failed {secret}");
            tracing::error!(target: "siegel", code = 500);
        });

        let (level, message, attributes) = captured_record("dep-marker mlock");
        assert!(matches!(level, LogLevel::Warn), "wrong level: {level:?}");
        assert_eq!(
            message, "dep-marker mlock failed aa..aa",
            "the dependency message must be hex-redacted"
        );
        assert_eq!(
            attributes.get("key").map(String::as_str),
            Some("aa..aa"),
            "dependency attribute values must be hex-redacted"
        );
        assert_eq!(
            attributes.get(VERSION_ATTRIBUTE_KEY).map(String::as_str),
            Some(env!("CARGO_PKG_VERSION")),
        );
        assert_eq!(
            attributes.get(DEPENDENCY_ATTRIBUTE_KEY).map(String::as_str),
            Some("siegel"),
        );

        // A field-only event records no `message` field, but must still arrive with a
        // non-empty body plus its fields.
        let field_only = captured()
            .iter()
            .find(|(_, _, attributes)| attributes.contains_key("code"))
            .cloned()
            .expect("the field-only event was forwarded");
        let (level, message, attributes) = field_only;
        assert!(matches!(level, LogLevel::Error), "wrong level: {level:?}");
        // Pinned exactly: `metadata.name()` would embed the dependency's build-time
        // source path and line, which must not reach the host and cannot be grouped.
        assert_eq!(
            message, "siegel event without a message",
            "the fallback body must be the target, not the callsite's source path"
        );
        assert_eq!(attributes.get("code").map(String::as_str), Some("500"));
    }

    /// A dependency field named like one of Bedrock's own attribute keys must not be
    /// able to spoof it: Bedrock's value wins.
    #[test]
    #[serial]
    fn dependency_fields_cannot_spoof_bedrock_attributes() {
        use super::{ForeignLoggerSubscriber, DEPENDENCY_ATTRIBUTE_KEY};
        use std::sync::atomic::AtomicU64;

        capture_records();

        let relay = Arc::new(RelayToForeign(ForeignLoggerSubscriber {
            next_span_id: AtomicU64::new(1),
        }));
        tracing::subscriber::with_default(relay, || {
            tracing::warn!(
                target: "siegel",
                bedrock_dependency = "not-siegel",
                bedrock_version = "0.0.0-spoofed",
                "spoof-marker",
            );
        });

        let (_, _, attributes) = captured_record("spoof-marker");
        assert_eq!(
            attributes.get(DEPENDENCY_ATTRIBUTE_KEY).map(String::as_str),
            Some("siegel"),
            "the real target must override a spoofed dependency field"
        );
        assert_eq!(
            attributes.get(VERSION_ATTRIBUTE_KEY).map(String::as_str),
            Some(env!("CARGO_PKG_VERSION")),
            "the real version must override a spoofed version field"
        );
    }

    /// Bedrock's own records take the direct path, so forwarding them through
    /// `tracing` as well would double-log every line. The check is on the module path
    /// as well as the target, which is why even an explicit `target:` override here
    /// is still recognized as Bedrock's own, and why [`RelayToForeign`] exists.
    #[test]
    fn in_crate_events_are_never_treated_as_dependencies() {
        /// Captures what [`super::is_bedrock_target`] answers for a real event's
        /// metadata, then rejects it so nothing reaches the host logger.
        struct Probe(Mutex<Vec<bool>>);

        impl Subscriber for Probe {
            fn enabled(&self, metadata: &Metadata<'_>) -> bool {
                self.0
                    .lock()
                    .expect("probe lock")
                    .push(super::is_bedrock_target(metadata));
                false
            }
            fn new_span(&self, _: &span::Attributes<'_>) -> span::Id {
                span::Id::from_u64(1)
            }
            fn record(&self, _: &span::Id, _: &span::Record<'_>) {}
            fn record_follows_from(&self, _: &span::Id, _: &span::Id) {}
            fn event(&self, _: &Event<'_>) {}
            fn enter(&self, _: &span::Id) {}
            fn exit(&self, _: &span::Id) {}
        }

        let probe = Arc::new(Probe(Mutex::new(Vec::new())));
        tracing::subscriber::with_default(probe.clone(), || {
            tracing::warn!(target: "siegel", "target says dependency, module says bedrock");
        });

        let observed = probe.0.lock().expect("probe lock").clone();
        assert!(
            !observed.is_empty() && observed.iter().all(|is_bedrock| *is_bedrock),
            "an in-crate event must be recognized as Bedrock's own: {observed:?}",
        );
    }

    /// Dependency noise below `WARN` is rejected at the callsite so it is never even
    /// formatted; raising the floor silently would flood the host logger.
    #[test]
    fn only_warn_and_above_forward_from_dependencies() {
        use super::is_forwardable_dependency_level;
        use tracing::Level;

        assert!(is_forwardable_dependency_level(Level::ERROR));
        assert!(is_forwardable_dependency_level(Level::WARN));
        assert!(!is_forwardable_dependency_level(Level::INFO));
        assert!(!is_forwardable_dependency_level(Level::DEBUG));
        assert!(!is_forwardable_dependency_level(Level::TRACE));
    }

    /// Pins the shapes `__bedrock_log!` has to accept. The token muncher picks its
    /// arm by shape alone, so a regression here is a silent mis-parse: fields landing
    /// in the message, or a form that stops compiling for every call site using it.
    #[test]
    #[serial]
    fn macros_accept_every_supported_call_shape() {
        capture_records();

        let owned = String::from("owned");
        let borrowed: &str = "borrowed";

        // Fields followed by a format string with its own positional arguments.
        crate::info!(a = 1, "shape-args {} {}", owned, borrowed);
        // A field whose value expression contains a comma.
        crate::info!(b = u32::max(1, 2), "shape-comma");
        // Field values that are a moved-from local and a reference, alongside a
        // message that captures the same locals inline.
        crate::info!(c = owned, d = borrowed, "shape-capture {owned} {borrowed}");
        // Named format arguments after the format string are not fields.
        crate::info!("shape-named {named}", named = 7);

        let (_, message, attributes) = captured_record("shape-args");
        assert_eq!(message, "shape-args owned borrowed");
        assert_eq!(attributes.get("a").map(String::as_str), Some("1"));

        let (_, _, attributes) = captured_record("shape-comma");
        assert_eq!(attributes.get("b").map(String::as_str), Some("2"));

        let (_, message, attributes) = captured_record("shape-capture");
        assert_eq!(message, "shape-capture owned borrowed");
        assert_eq!(attributes.get("c").map(String::as_str), Some("owned"));
        assert_eq!(attributes.get("d").map(String::as_str), Some("borrowed"));

        let (_, message, attributes) = captured_record("shape-named");
        assert_eq!(message, "shape-named 7");
        assert_eq!(
            attributes.len(),
            1,
            "a named format argument must not become an attribute"
        );
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

    /// Without a host logger the record is dropped, and building its attributes must
    /// be skipped too: a structured call site is expected to be free at rest, so an
    /// expensive (or side-effecting) `Display` impl is never run.
    #[test]
    fn attributes_are_not_built_without_a_logger() {
        let built = std::cell::Cell::new(false);

        log_to(None, LogLevel::Info, format_args!("dropped"), || {
            built.set(true);
            HashMap::new()
        });

        assert!(
            !built.get(),
            "attributes must not be built without a logger"
        );
    }

    /// The counterpart to [`attributes_are_not_built_without_a_logger`]: with a logger
    /// present the closure runs and its fields reach the host.
    #[test]
    fn attributes_are_built_once_a_logger_is_present() {
        let capturing = Arc::new(CapturingLogger::default());
        let logger: Arc<dyn Logger> = capturing.clone();

        log_to(Some(&logger), LogLevel::Info, format_args!("kept"), || {
            HashMap::from([("chain_id".to_owned(), "480".to_owned())])
        });

        let records = capturing.records.lock().unwrap().clone();
        assert_eq!(records.len(), 1);
        let (level, message, attrs) = &records[0];
        assert!(matches!(level, LogLevel::Info));
        assert_eq!(message, "kept");
        assert_eq!(attrs.get("chain_id").map(String::as_str), Some("480"));
        assert_eq!(
            attrs.get(VERSION_ATTRIBUTE_KEY).map(String::as_str),
            Some(env!("CARGO_PKG_VERSION")),
        );
    }

    #[test]
    fn event_visitor_keeps_strings_unquoted() {
        use std::sync::Mutex;

        // A minimal subscriber that runs a real `tracing` event through
        // `EventVisitor`, so field recording exercises the same
        // `record_str`/`record_debug` dispatch as the dependency-log path.
        struct Capture(Mutex<Vec<(String, HashMap<String, String>)>>);

        impl Subscriber for Capture {
            fn enabled(&self, _: &Metadata<'_>) -> bool {
                true
            }
            fn new_span(&self, _: &span::Attributes<'_>) -> span::Id {
                span::Id::from_u64(1)
            }
            fn record(&self, _: &span::Id, _: &span::Record<'_>) {}
            fn record_follows_from(&self, _: &span::Id, _: &span::Id) {}
            fn event(&self, event: &Event<'_>) {
                let mut visitor = EventVisitor::default();
                event.record(&mut visitor);
                self.0
                    .lock()
                    .unwrap()
                    .push((visitor.message, visitor.attributes));
            }
            fn enter(&self, _: &span::Id) {}
            fn exit(&self, _: &span::Id) {}
        }

        let capture = Arc::new(Capture(Mutex::new(Vec::new())));
        tracing::subscriber::with_default(capture.clone(), || {
            tracing::info!(
                path = "/foo/bar",
                attempts = 3,
                ok = true,
                "deserialize failed"
            );
        });

        let events = capture.0.lock().unwrap().clone();
        assert_eq!(events.len(), 1);
        let (message, attrs) = &events[0];
        assert_eq!(message, "deserialize failed");
        // String fields are stored without surrounding quotes.
        assert_eq!(attrs.get("path").map(String::as_str), Some("/foo/bar"));
        // Numbers and booleans render bare via the `record_debug` fallback.
        assert_eq!(attrs.get("attempts").map(String::as_str), Some("3"));
        assert_eq!(attrs.get("ok").map(String::as_str), Some("true"));
    }
}
