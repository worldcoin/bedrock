use serde::{Deserialize, Serialize};
use std::sync::{Arc, OnceLock};

use crate::bedrock_export;

/// Global configuration for Bedrock
static CONFIG_INSTANCE: OnceLock<Arc<BedrockConfig>> = OnceLock::new();

/// Represents the environment for Bedrock operations
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum BedrockEnvironment {
    /// Staging environment  
    Staging,
    /// Production environment
    Production,
}

/// Platform enum as reported by clients
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, uniffi::Enum)]
pub enum Os {
    /// Android platform
    #[serde(rename = "android")]
    Android,
    /// iOS platform
    #[serde(rename = "ios")]
    Ios,
}

impl Os {
    #[must_use]
    /// Returns the lowercase string representation for wire format
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Android => "android",
            Self::Ios => "ios",
        }
    }
}

impl BedrockEnvironment {
    /// Returns the string representation of the environment
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Staging => "staging",
            Self::Production => "production",
        }
    }
}

/// Returns the current `BedrockEnvironment`, defaulting to `Production` if
/// the global configuration has not been initialized.
///
/// When the configuration has not been initialized, this will log an error
/// indicating that the default environment is being used.
#[must_use]
pub fn current_environment_or_default() -> BedrockEnvironment {
    match get_config() {
        Some(cfg) => cfg.environment(),
        None => {
            crate::error!(
                "Bedrock config not initialized, defaulting environment to Production"
            );
            BedrockEnvironment::Production
        }
    }
}

impl std::fmt::Display for BedrockEnvironment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Global configuration for Bedrock
#[derive(Debug, Clone, uniffi::Object)]
pub struct BedrockConfig {
    environment: BedrockEnvironment,
    os: Os,
}

#[bedrock_export]
impl BedrockConfig {
    /// Creates a new `BedrockConfig` with the specified environment
    ///
    /// # Arguments
    /// * `environment` - The environment to use for this configuration
    ///
    /// # Examples
    ///
    /// ## Swift
    ///
    /// ```swift
    /// let config = BedrockConfig(environment: .production)
    /// ```
    #[uniffi::constructor]
    #[must_use]
    pub fn new(environment: BedrockEnvironment, os: Os) -> Self {
        Self { environment, os }
    }

    /// Gets the current environment
    #[must_use]
    pub fn environment(&self) -> BedrockEnvironment {
        self.environment
    }

    /// Gets the current OS
    #[must_use]
    pub fn os(&self) -> Os {
        self.os
    }
}

/// Initializes the global Bedrock configuration.
///
/// This function should be called once at application startup before any other Bedrock operations.
/// Subsequent calls will be ignored and print a warning.
///
/// # Arguments
/// * `environment` - The environment to use for all Bedrock operations
///
/// # Examples
///
/// ## Swift
///
/// ```swift
/// import Bedrock
///
/// // In your app delegate or during app initialization
/// setConfig(environment: .staging)
/// ```
#[uniffi::export]
pub fn set_config(environment: BedrockEnvironment, os: Os) {
    let config = BedrockConfig::new(environment, os);

    match CONFIG_INSTANCE.set(Arc::new(config)) {
        Ok(()) => {
            crate::info!(
                "Bedrock config initialized with environment: {}",
                environment
            );
        }
        Err(_) => {
            crate::warn!("Bedrock config already initialized, ignoring");
        }
    }
}

/// Gets a reference to the global Bedrock configuration.
///
/// # Returns
/// An Option containing a reference to the config if initialized, None otherwise.
///
/// # Examples
///
/// ## Swift
///
/// ```swift
/// if let config = getConfig() {
///     print("Environment: \(config.environment())")
/// }
/// ```
#[uniffi::export]
#[must_use]
pub fn get_config() -> Option<Arc<BedrockConfig>> {
    CONFIG_INSTANCE.get().cloned()
}

/// Checks if the Bedrock configuration has been initialized.
///
/// # Returns
/// true if the config has been initialized, false otherwise.
#[uniffi::export]
#[must_use]
pub fn is_initialized() -> bool {
    CONFIG_INSTANCE.get().is_some()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_environment_display() {
        assert_eq!(BedrockEnvironment::Staging.as_str(), "staging");
        assert_eq!(BedrockEnvironment::Production.as_str(), "production");

        assert_eq!(BedrockEnvironment::Staging.to_string(), "staging");
        assert_eq!(BedrockEnvironment::Production.to_string(), "production");
    }
}
