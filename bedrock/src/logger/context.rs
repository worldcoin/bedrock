use std::cell::RefCell;

thread_local! {
    static LOG_CONTEXT: RefCell<Option<String>> = RefCell::new(None);
}

/// A scope guard that sets a logging context and automatically clears it when dropped.
///
/// # Examples
///
/// ```rust
/// use bedrock::logger::LogContext;
///
/// {
///     let _ctx = LogContext::new("SmartAccount");
///     log::info!("This will be prefixed with [SmartAccount]");
///     log::debug!("This too!");
/// } // Context automatically cleared here
/// ```
pub struct LogContext {
    previous: Option<String>,
}

impl LogContext {
    /// Creates a new logging context scope.
    ///
    /// The context will be active until this `LogContext` is dropped.
    pub fn new(module: &str) -> Self {
        let previous = LOG_CONTEXT.with(|ctx| {
            let mut ctx = ctx.borrow_mut();
            let prev = ctx.clone();
            *ctx = Some(format!("[{}]", module));
            prev
        });

        Self { previous }
    }
}

impl Drop for LogContext {
    fn drop(&mut self) {
        LOG_CONTEXT.with(|ctx| {
            *ctx.borrow_mut() = self.previous.clone();
        });
    }
}

/// Gets the current logging context, if any.
pub fn get_context() -> Option<String> {
    LOG_CONTEXT.with(|ctx| ctx.borrow().clone())
}

/// Macro to create a scoped logging context.
///
/// # Examples
///
/// ```rust
/// use bedrock::with_log_context;
///
/// with_log_context!("SmartAccount" => {
///     log::info!("This will be prefixed with [SmartAccount]");
///     log::debug!("This too!");
/// });
/// ```
#[macro_export]
macro_rules! with_log_context {
    ($module:expr => $block:block) => {{
        let _ctx = $crate::logger::LogContext::new($module);
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
/// let _ctx = set_log_context!("SmartAccount");
/// log::info!("This will be prefixed with [SmartAccount]");
/// ```
#[macro_export]
macro_rules! set_log_context {
    ($module:expr) => {
        $crate::logger::LogContext::new($module)
    };
}

/// Context-aware logging macros that automatically use the current logging context.

/// Logs a trace-level message with automatic context prefixing
#[macro_export]
macro_rules! trace {
    ($($arg:tt)*) => {
        if let Some(ctx) = $crate::logger::get_context() {
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
        if let Some(ctx) = $crate::logger::get_context() {
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
        if let Some(ctx) = $crate::logger::get_context() {
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
        if let Some(ctx) = $crate::logger::get_context() {
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
        if let Some(ctx) = $crate::logger::get_context() {
            log::error!("{} {}", ctx, format_args!($($arg)*))
        } else {
            log::error!($($arg)*)
        }
    };
}
