use std::cell::RefCell;
use std::{sync::Arc, sync::OnceLock};

thread_local! {
    static THREAD_LOG_CONTEXT: RefCell<Option<String>> = const { RefCell::new(None) };
}

tokio::task_local! {
    /// Task-local logging context, set by the `bedrock_export` proc macro for async functions.
    pub static LOG_CONTEXT: RefCell<Option<String>>;
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

/// A logger that forwards log messages to a user-provided `Logger` implementation.
///
/// This struct implements the `log::Log` trait and integrates with the Rust `log` crate.
struct ForeignLogger;

impl log::Log for ForeignLogger {
    /// Determines if a log message with the specified metadata should be logged.
    ///
    /// This implementation logs all messages. Modify this method to implement log level filtering.
    ///
    /// # Arguments
    ///
    /// * `_metadata` - Metadata about the log message.
    fn enabled(&self, _metadata: &log::Metadata) -> bool {
        // Currently, we log all messages. Adjust this if you need to filter messages.
        true
    }

    /// Logs a record.
    ///
    /// This method is called by the `log` crate when a log message needs to be logged.
    /// It forwards the log message to the user-provided `Logger` implementation if available.
    ///
    /// # Arguments
    ///
    /// * `record` - The log record containing the message and metadata.
    fn log(&self, record: &log::Record) {
        // Determine if the record originates from the "bedrock" module.
        let is_record_from_bedrock = record
            .module_path()
            .is_some_and(|module_path| module_path.starts_with("bedrock"));

        // Determine if the log level is Debug or Trace.
        let is_debug_or_trace_level =
            record.level() == log::Level::Debug || record.level() == log::Level::Trace;

        // Skip logging Debug or Trace level messages that are not from the "bedrock" module.
        if is_debug_or_trace_level && !is_record_from_bedrock {
            return;
        }

        // Forward the log message to the user-provided logger if available.
        if let Some(logger) = LOGGER_INSTANCE.get() {
            let level = log_level(record.level());
            let message = format!("{}", record.args());
            logger.log(level, message);
        } else {
            // Handle the case when the logger is not set.
            eprintln!("Logger not set: {}", record.args());
        }
    }

    /// Flushes any buffered records.
    ///
    /// This implementation does nothing because buffering is not used.
    fn flush(&self) {}
}

/// Converts a `log::Level` to a `LogLevel`.
///
/// This function maps the log levels from the `log` crate to your own `LogLevel` enum.
///
/// # Arguments
///
/// * `level` - The `log::Level` to convert.
///
/// # Returns
///
/// A corresponding `LogLevel`.
const fn log_level(level: log::Level) -> LogLevel {
    match level {
        log::Level::Error => LogLevel::Error,
        log::Level::Warn => LogLevel::Warn,
        log::Level::Info => LogLevel::Info,
        log::Level::Debug => LogLevel::Debug,
        log::Level::Trace => LogLevel::Trace,
    }
}

/// A global instance of the user-provided logger.
///
/// This static variable holds the logger provided by the user and is accessed by `ForeignLogger` to forward log messages.
static LOGGER_INSTANCE: OnceLock<Arc<dyn Logger>> = OnceLock::new();

/// Sets the global logger.
///
/// This function allows you to provide your own implementation of the `Logger` trait.
/// It initializes the logging system and should be called before any logging occurs.
///
/// # Arguments
///
/// * `logger` - An `Arc` containing your logger implementation.
///
/// # Panics
///
/// Panics if the logger has already been set.
///
/// # Note
///
/// If the logger has already been set, this function will print a message and do nothing.
#[allow(clippy::module_name_repetitions)]
#[uniffi::export]
pub fn set_logger(logger: Arc<dyn Logger>) {
    match LOGGER_INSTANCE.set(logger) {
        Ok(()) => (),
        Err(_) => println!("Logger already set"),
    }

    // Initialize the logger system.
    init_logger().expect("Failed to set logger");
}

/// Initializes the logger system.
///
/// This function sets up the global logger with the `ForeignLogger` implementation and sets the maximum log level.
///
/// # Returns
///
/// A `Result` indicating success or failure.
///
/// # Errors
///
/// Returns a `log::SetLoggerError` if the logger could not be set (e.g., if a logger was already set).
fn init_logger() -> Result<(), log::SetLoggerError> {
    static LOGGER: ForeignLogger = ForeignLogger;
    log::set_logger(&LOGGER)?;
    log::set_max_level(log::LevelFilter::Trace);
    Ok(())
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
        if let Some(ctx) = $crate::primitives::logger::get_context() {
            log::trace!("{} {}", ctx, format_args!($($arg)*))
        } else {
            log::trace!($($arg)*)
        }
    };
}

/// Logs a debug-level message with automatic context prefixing
#[macro_export]
macro_rules! debug {
    ($($arg:tt)*) => {
        if let Some(ctx) = $crate::primitives::logger::get_context() {
            log::debug!("{} {}", ctx, format_args!($($arg)*))
        } else {
            log::debug!($($arg)*)
        }
    };
}

/// Logs an info-level message with automatic context prefixing
#[macro_export]
macro_rules! info {
    ($($arg:tt)*) => {
        if let Some(ctx) = $crate::primitives::logger::get_context() {
            log::info!("{} {}", ctx, format_args!($($arg)*))
        } else {
            log::info!($($arg)*)
        }
    };
}

/// Logs a warning-level message with automatic context prefixing
#[macro_export]
macro_rules! warn {
    ($($arg:tt)*) => {
        if let Some(ctx) = $crate::primitives::logger::get_context() {
            log::warn!("{} {}", ctx, format_args!($($arg)*))
        } else {
            log::warn!($($arg)*)
        }
    };
}

/// Logs an error-level message with automatic context prefixing
#[macro_export]
macro_rules! error {
    ($($arg:tt)*) => {
        if let Some(ctx) = $crate::primitives::logger::get_context() {
            log::error!("{} {}", ctx, format_args!($($arg)*))
        } else {
            log::error!($($arg)*)
        }
    };
}

/// Tracks which backing storage a [`LogContext`] used, so `Drop` restores the correct one.
enum LogContextStorage {
    TaskLocal,
    ThreadLocal,
}

/// A scope guard that sets a logging context and automatically clears it when dropped.
///
/// # Examples
///
/// ```rust
/// use bedrock::primitives::logger::LogContext;
///
/// {
///     let _bedrock_logger_ctx = LogContext::new("SmartAccount");
///     log::info!("This will be prefixed with [Bedrock][SmartAccount]");
///     log::debug!("This too!");
/// } // Context automatically cleared here
/// ```
pub struct LogContext {
    previous: Option<String>,
    storage: LogContextStorage,
}

impl LogContext {
    /// Creates a new logging context scope.
    ///
    /// The context will be active until this `LogContext` is dropped.
    #[must_use]
    pub fn new(module: &str) -> Self {
        let new_context = Some(format!("[Bedrock][{module}]"));

        // Prefer task_local (persists across .await points); fall back to thread_local for sync code.
        match LOG_CONTEXT.try_with(|ctx| {
            let mut ctx = ctx.borrow_mut();
            let prev = ctx.clone();
            *ctx = new_context.clone();
            prev
        }) {
            Ok(previous) => Self {
                previous,
                storage: LogContextStorage::TaskLocal,
            },
            Err(_) => {
                let previous = THREAD_LOG_CONTEXT.with(|ctx| {
                    let mut ctx = ctx.borrow_mut();
                    let prev = ctx.clone();
                    *ctx = new_context;
                    prev
                });
                Self {
                    previous,
                    storage: LogContextStorage::ThreadLocal,
                }
            }
        }
    }
}

impl Drop for LogContext {
    fn drop(&mut self) {
        match self.storage {
            LogContextStorage::TaskLocal => {
                let _ = LOG_CONTEXT.try_with(|ctx| {
                    (*ctx.borrow_mut()).clone_from(&self.previous);
                });
            }
            LogContextStorage::ThreadLocal => {
                THREAD_LOG_CONTEXT.with(|ctx| {
                    (*ctx.borrow_mut()).clone_from(&self.previous);
                });
            }
        }
    }
}

/// Gets the current logging context, if any.
#[must_use]
pub fn get_context() -> Option<String> {
    LOG_CONTEXT
        .try_with(|ctx| ctx.borrow().clone())
        .unwrap_or_else(|_| THREAD_LOG_CONTEXT.with(|ctx| ctx.borrow().clone()))
}

/// Macro to create a scoped logging context.
///
/// # Examples
///
/// ```rust
/// use bedrock::with_log_context;
///
/// with_log_context!("SmartAccount" => {
///     log::info!("This will be prefixed with [Bedrock][SmartAccount]");
///     log::debug!("This too!");
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
/// use bedrock::set_log_context;
///
/// let _bedrock_logger_ctx = set_log_context!("SmartAccount");
/// log::info!("This will be prefixed with [Bedrock][SmartAccount]");
/// ```
#[macro_export]
macro_rules! set_log_context {
    ($module:expr) => {
        $crate::primitives::logger::LogContext::new($module)
    };
}
