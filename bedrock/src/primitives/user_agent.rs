//! User-Agent helpers for HTTP requests issued through Bedrock consumers.

use std::fmt;

const WORLD_APP_USER_AGENT_PRODUCT: &str = "WorldApp";
const WORLD_ID_APP_USER_AGENT_PRODUCT: &str = "WorldID";
const WORLD_ID_ANDROID_CLIENT_NAME: &str = "android-id";
const WORLD_ID_IOS_CLIENT_NAME: &str = "ios-id";

/// Represents a complete HTTP `User-Agent` header value.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Object)]
pub struct UserAgent(String);

impl fmt::Display for UserAgent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[uniffi::export]
impl UserAgent {
    /// Returns the complete HTTP `User-Agent` header value.
    #[must_use]
    pub fn header_value(&self) -> String {
        self.0.clone()
    }
}

/// Builds the [`UserAgent`] string sent as the HTTP `User-Agent` header.
///
/// Starts empty; call [`Self::with_segment`] for arbitrary `name/version`
/// tokens and the Bedrock-specific helpers for app, library, and client
/// segments.
#[derive(Debug, Clone, Default, PartialEq, Eq, uniffi::Object)]
pub struct UserAgentBuilder {
    segments: Vec<String>,
}

#[uniffi::export]
impl UserAgentBuilder {
    /// Creates an empty [`UserAgentBuilder`].
    #[uniffi::constructor]
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Appends an arbitrary `name/version` segment.
    #[must_use]
    pub fn with_segment(&self, name: &str, version: &str) -> Self {
        let mut next = self.clone();
        next.segments.push(format!("{name}/{version}"));
        next
    }

    /// Appends the app product segment for the client name.
    ///
    /// Uses `WorldID/{app_version}` for World ID app clients
    /// (`android-id` / `ios-id`), and `WorldApp/{app_version}` for all
    /// other clients.
    #[must_use]
    pub fn with_app_segment_for_client(
        &self,
        app_version: &str,
        client_name: &str,
    ) -> Self {
        self.with_segment(user_agent_product_for_client(client_name), app_version)
    }

    /// Appends `bedrock/{crate version}`.
    #[must_use]
    pub fn with_bedrock_segment(&self) -> Self {
        self.with_segment("bedrock", env!("CARGO_PKG_VERSION"))
    }

    /// Appends `{client_name}/{os_version}` to match the app client suffix convention.
    #[must_use]
    pub fn with_client_segment(&self, client_name: &str, os_version: &str) -> Self {
        self.with_segment(client_name, os_version)
    }

    /// Finalizes the header value as [`UserAgent`].
    #[must_use]
    pub fn build(&self) -> UserAgent {
        UserAgent(self.segments.join(" "))
    }
}

fn user_agent_product_for_client(client_name: &str) -> &'static str {
    match client_name {
        WORLD_ID_ANDROID_CLIENT_NAME | WORLD_ID_IOS_CLIENT_NAME => {
            WORLD_ID_APP_USER_AGENT_PRODUCT
        }
        _ => WORLD_APP_USER_AGENT_PRODUCT,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn app_user_agent(
        app_version: &str,
        client_name: &str,
        os_version: &str,
    ) -> UserAgent {
        UserAgentBuilder::new()
            .with_app_segment_for_client(app_version, client_name)
            .with_bedrock_segment()
            .with_client_segment(client_name, os_version)
            .build()
    }

    #[test]
    fn user_agent_builder_starts_empty() {
        assert_eq!(UserAgentBuilder::new().build().to_string(), "");
    }

    #[test]
    fn user_agent_builder_appends_arbitrary_segments() {
        let user_agent = UserAgentBuilder::new()
            .with_segment("CLI", "1.2.3")
            .with_bedrock_segment()
            .build();

        assert_eq!(
            user_agent.to_string(),
            concat!("CLI/1.2.3 bedrock/", env!("CARGO_PKG_VERSION"))
        );
    }

    #[test]
    fn world_app_android_client_uses_world_app_product_name() {
        assert_eq!(
            app_user_agent("4.0.2500", "android", "15").to_string(),
            concat!(
                "WorldApp/4.0.2500 bedrock/",
                env!("CARGO_PKG_VERSION"),
                " android/15"
            )
        );
    }

    #[test]
    fn world_app_ios_client_uses_world_app_product_name() {
        assert_eq!(
            app_user_agent("4.0.2500", "ios", "26.4.2").to_string(),
            concat!(
                "WorldApp/4.0.2500 bedrock/",
                env!("CARGO_PKG_VERSION"),
                " ios/26.4.2"
            )
        );
    }

    #[test]
    fn world_id_android_client_uses_world_id_product_name() {
        assert_eq!(
            app_user_agent("1.0.100", "android-id", "15").to_string(),
            concat!(
                "WorldID/1.0.100 bedrock/",
                env!("CARGO_PKG_VERSION"),
                " android-id/15"
            )
        );
    }

    #[test]
    fn world_id_ios_client_uses_world_id_product_name() {
        assert_eq!(
            app_user_agent("1.0.100", "ios-id", "26.4.2").to_string(),
            concat!(
                "WorldID/1.0.100 bedrock/",
                env!("CARGO_PKG_VERSION"),
                " ios-id/26.4.2"
            )
        );
    }

    #[test]
    fn user_agent_exposes_header_value_for_ffi_consumers() {
        let user_agent = app_user_agent("1.0.100", "android-id", "15");

        assert_eq!(
            user_agent.header_value(),
            concat!(
                "WorldID/1.0.100 bedrock/",
                env!("CARGO_PKG_VERSION"),
                " android-id/15"
            )
        );
    }
}
