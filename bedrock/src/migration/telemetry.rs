/// Classifies migration telemetry without changing execution or readiness.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum MigrationNamespace {
    /// Tasks the host waits for before reporting readiness.
    Blocking,
    /// Tasks the host runs without waiting to report readiness.
    NonBlocking,
}

impl MigrationNamespace {
    pub(super) const fn as_str(self) -> &'static str {
        match self {
            Self::Blocking => "blocking",
            Self::NonBlocking => "nonblocking",
        }
    }
}

macro_rules! migration_log {
    ($level:ident, $namespace:expr, $($args:tt)*) => {
        if let Some(namespace) = $namespace {
            crate::$level!(namespace = namespace.as_str(), $($args)*);
        } else {
            crate::$level!($($args)*);
        }
    };
}

pub(super) use migration_log;
