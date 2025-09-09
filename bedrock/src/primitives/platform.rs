use serde::{Deserialize, Serialize};

/// Platform enum as reported by clients
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, uniffi::Enum)]
pub enum PlatformKind {
    /// Android platform
    #[serde(rename = "android")]
    Android,
    /// iOS platform
    #[serde(rename = "ios")]
    Ios,
}

impl PlatformKind {
    #[must_use]
    /// Returns the lowercase string representation for wire format
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Android => "android",
            Self::Ios => "ios",
        }
    }
}
