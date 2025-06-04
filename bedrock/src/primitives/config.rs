use std::sync::OnceLock;

use crate::bedrock_export;

/// Global configuration for Bedrock
static CONFIG_INSTANCE: OnceLock<BedrockConfig> = OnceLock::new();

/// Represents the environment for Bedrock operations
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum BedrockEnvironment {
    /// Staging environment  
    Staging,
    /// Production environment
    Production,
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

impl std::fmt::Display for BedrockEnvironment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Global configuration for Bedrock
#[derive(Debug, Clone, uniffi::Object)]
pub struct BedrockConfig {
    environment: BedrockEnvironment,
}

#[bedrock_export]
impl BedrockConfig {
    /// Creates a new BedrockConfig with the specified environment
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
    pub fn new(environment: BedrockEnvironment) -> Self {
        Self { environment }
    }

    /// Gets the current environment
    #[must_use]
    pub fn environment(&self) -> BedrockEnvironment {
        self.environment
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
/// Bedrock.initBedrockConfig(environment: .staging)
/// ```
#[uniffi::export]
pub fn init_bedrock_config(environment: BedrockEnvironment) {
    let config = BedrockConfig::new(environment);

    match CONFIG_INSTANCE.set(config) {
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

/// Gets the current Bedrock environment.
///
/// # Returns
/// The current environment if config has been initialized, otherwise returns Production as a safe default.
///
/// # Examples
///
/// ## Swift
///
/// ```swift
/// let currentEnv = Bedrock.currentEnvironment()
///
/// switch currentEnv {
/// case .staging:
///     print("Running in staging environment")
/// case .production:
///     print("Running in production environment")
/// }
/// ```
#[must_use]
pub fn current_environment() -> BedrockEnvironment {
    CONFIG_INSTANCE.get().map_or_else(
        || {
            crate::warn!("Bedrock config not initialized, defaulting to Production");
            BedrockEnvironment::Production
        },
        BedrockConfig::environment,
    )
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
/// if let config = Bedrock.getConfig() {
///     print("Environment: \(config.environment())")
/// }
/// ```
#[must_use]
pub fn get_config() -> Option<&'static BedrockConfig> {
    CONFIG_INSTANCE.get()
}

/// Checks if the Bedrock configuration has been initialized.
///
/// # Returns
/// true if the config has been initialized, false otherwise.
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
