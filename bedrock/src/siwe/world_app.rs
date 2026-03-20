/// World App authentication flow variants used to construct SIWE messages.
#[derive(Debug, Clone, Copy, uniffi::Enum)]
pub enum WorldAppAuthFlow {
    /// User has a valid and non-expired refresh token
    Refresh,
    /// No refresh token, just access to wallet
    Restore,
    /// New account
    SignUp,
}

#[uniffi::export]
impl WorldAppAuthFlow {
    /// Returns the full SIWE URI for the given flow, appending the
    /// appropriate backend path to `base_url`.
    #[must_use]
    pub fn as_siwe_uri(&self, base_url: &str) -> String {
        let path = match self {
            Self::Refresh => "/public/v1/auth/refresh",
            Self::Restore => "/public/v1/auth/restore",
            Self::SignUp => "/public/v1/auth/sign-up",
        };
        format!("{}{path}", base_url.trim_end_matches('/'))
    }
}
