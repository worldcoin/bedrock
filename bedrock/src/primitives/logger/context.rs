use std::cell::RefCell;

thread_local! {
    static LOG_CONTEXT: RefCell<Option<String>> = const { RefCell::new(None) };
}

/// A scope guard that sets a logging context and automatically clears it when dropped.
///
/// # Examples
///
/// ```rust
/// use bedrock::primitives::logger::LogContext;
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
    #[must_use]
    pub fn new(module: &str) -> Self {
        let previous = LOG_CONTEXT.with(|ctx| {
            let mut ctx = ctx.borrow_mut();
            let prev = ctx.clone();
            *ctx = Some(format!("[{module}]"));
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
        let _ctx = $crate::primitives::logger::LogContext::new($module);
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
        $crate::primitives::logger::LogContext::new($module)
    };
}
