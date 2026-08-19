use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Once, OnceLock};

use crate::bedrock_export;
use crate::primitives::filesystem::{clear_stale_staged_writes, prepare_root};
use crate::primitives::PrimitiveError;

/// Global configuration for Bedrock
static CONFIG_INSTANCE: OnceLock<Arc<BedrockConfig>> = OnceLock::new();

/// Guards the one-time sweep of staged writes left by a previous process.
static FS_STAGED_SWEEP: Once = Once::new();

/// Represents the environment for Bedrock operations
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum BedrockEnvironment {
    /// Staging environment
    Staging,
    /// The sandbox environment is an externally available and reliable environment,
    /// and with a set of tools that allows breaking boxes and testing anything.
    ///
    /// The sandbox environment is available for TFH Apps (World App, World ID), and uses
    /// the `staging` environment of the World ID Protocol.
    ///
    /// Reference: <http://go/sandbox>
    Sandbox,
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
            Self::Sandbox => "sandbox",
            Self::Production => "production",
        }
    }

    /// Base URL of the [backup-service](https://github.com/worldcoin/backup-service)
    #[must_use]
    pub const fn backup_service_base_url(&self) -> &'static str {
        match self {
            Self::Production => "https://api-tfh-backup-prod.nethermind.io",
            Self::Staging | Self::Sandbox => {
                "https://backup-service.stage-crypto.worldcoin.org"
            }
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
    get_config().map_or_else(
        || {
            crate::error!(
                "Bedrock config not initialized, defaulting environment to Production"
            );
            BedrockEnvironment::Production
        },
        |cfg| cfg.environment(),
    )
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
    root_path: PathBuf,
}

#[bedrock_export]
impl BedrockConfig {
    /// Creates a new `BedrockConfig` with the specified environment
    ///
    /// # Arguments
    /// * `environment` - The environment to use for this configuration
    /// * `os` - The platform the app is running on
    /// * `root_path` - Absolute path to the directory Bedrock owns for its files. Should **NOT** be touched outside of Bedrock.
    ///
    /// # Examples
    ///
    /// ## Swift
    ///
    /// ```swift
    /// let config = BedrockConfig(environment: .production, os: .ios, rootPath: rootURL.path)
    /// ```
    #[uniffi::constructor]
    #[must_use]
    pub fn new(environment: BedrockEnvironment, os: Os, root_path: String) -> Self {
        Self {
            environment,
            os,
            root_path: PathBuf::from(root_path),
        }
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

impl BedrockConfig {
    /// The directory Bedrock resolves all of its file operations against.
    pub(crate) fn root_path(&self) -> &Path {
        &self.root_path
    }
}

/// Initializes the global Bedrock configuration.
///
/// This function should be called once at application startup before any other Bedrock operations.
/// Subsequent calls will be ignored and print a warning.
///
/// # Arguments
/// * `environment` - The environment to use for all Bedrock operations
/// * `os` - The platform the app is running on
/// * `root_path` - Absolute path to the directory Bedrock owns for its
/// files. Should **NOT** be touched outside of Bedrock.
///
/// # Errors
/// - Returns an error if `root_path` is not absolute or cannot be created.
/// - Returns an error if Bedrock is already configured. Call only once!
///
/// # Examples
///
/// ## Swift
///
/// ```swift
/// import Bedrock
///
/// // In your app delegate or during app initialization
/// try setConfig(environment: .staging, os: .ios, rootPath: rootURL.path)
/// ```
#[uniffi::export]
pub fn set_config(
    environment: BedrockEnvironment,
    os: Os,
    root_path: String,
) -> Result<(), PrimitiveError> {
    let config = BedrockConfig::new(environment, os, root_path);

    if CONFIG_INSTANCE.get().is_some() {
        return Err(PrimitiveError::Generic {
            error_message: "already initialized".to_string(),
        });
    }

    if let Err(error) = prepare_root(config.root_path()) {
        crate::critical!(
            "Bedrock root directory is unusable, config not applied: {error}"
        );
        return Err(error);
    }

    // Before the config becomes visible so there are no race conditions
    FS_STAGED_SWEEP.call_once(|| clear_stale_staged_writes(config.root_path()));

    if CONFIG_INSTANCE.set(Arc::new(config)).is_err() {
        return Err(PrimitiveError::Generic {
            error_message: "already initialized".to_string(),
        });
    }

    crate::debug!(
        "Bedrock config initialized with environment: {}",
        environment
    );
    Ok(())
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
