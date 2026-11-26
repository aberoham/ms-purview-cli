use thiserror::Error;

/// Every failure a command can return. A command that fails returns
/// `Err(PurviewError)`; the top-level printer in `cli` turns it into exit 1
/// and, under `--json`, into `{"error": {"code", "status", "message"}}`.
///
/// Control flow must use the variants and the predicates below, never the
/// rendered message.
#[derive(Debug, Error)]
pub enum PurviewError {
    #[error("{0}")]
    Message(String),

    #[error("{context}: {source}")]
    Context {
        context: String,
        #[source]
        source: Box<PurviewError>,
    },

    #[error("I/O operation failed: {0}")]
    Io(#[from] std::io::Error),

    #[error("JSON operation failed: {0}")]
    Json(#[from] serde_json::Error),

    /// A refusal from the identity platform. Only the allow-listed fields
    /// of the error body are kept (`docs/SPEC.md` section 6.8), and the
    /// description has been through the Redactor.
    #[error("{0}")]
    OAuth(Box<OAuthDetails>),

    /// The id token carried none of `preferred_username`, `upn` and
    /// `email`, so the account cannot be named.
    #[error(
        "the sign-in returned no account name: the id token has no preferred_username, upn or \
         email claim{}",
        .detail.as_deref().map(|detail| format!(" ({detail})")).unwrap_or_default()
    )]
    NoAccountClaim { detail: Option<String> },

    /// The account has no download token and one could not be obtained.
    #[error(
        "no download token for {account}: the app has no consent for the Purview eDiscovery \
         permission eDiscovery.Download.Read. Ask an administrator to grant it, then run \
         'purview auth refresh'"
    )]
    DownloadNotConsented { account: String },

    #[error("could not reach the identity platform: {0}")]
    Http(#[from] reqwest::Error),

    #[error("credential store operation failed: {0}")]
    Keyring(#[from] keyring::Error),

    #[error(
        "another purview process kept the credential lock {path} busy for over {seconds} \
         seconds; wait for it to finish and try again"
    )]
    CredentialLockBusy { path: String, seconds: u64 },

    #[error("could not {action} the credential lock file {path}: {source}")]
    CredentialLockFailed {
        action: &'static str,
        path: String,
        #[source]
        source: std::io::Error,
    },
}

/// The allow-listed fields of an identity-platform error body.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OAuthDetails {
    pub operation: String,
    pub status: u16,
    pub error: String,
    pub description: String,
    pub error_codes: Vec<i64>,
    pub trace_id: String,
    pub correlation_id: String,
    pub timestamp: String,
}

/// The operation, the status, the OAuth error and its description, then
/// the identifiers a support case needs.
impl std::fmt::Display for OAuthDetails {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "{} failed with HTTP {}: {}",
            self.operation, self.status, self.error
        )?;
        if !self.description.is_empty() {
            write!(formatter, ": {}", self.description)?;
        }
        let mut details = Vec::new();
        if !self.error_codes.is_empty() {
            let codes: Vec<String> = self.error_codes.iter().map(i64::to_string).collect();
            details.push(format!("error codes {}", codes.join(", ")));
        }
        for (label, value) in [
            ("trace id", &self.trace_id),
            ("correlation id", &self.correlation_id),
            ("timestamp", &self.timestamp),
        ] {
            if !value.is_empty() {
                details.push(format!("{label} {value}"));
            }
        }
        if !details.is_empty() {
            write!(formatter, " ({})", details.join("; "))?;
        }
        Ok(())
    }
}

impl PurviewError {
    pub fn message(value: impl Into<String>) -> Self {
        Self::Message(value.into())
    }

    pub fn context(self, context: impl Into<String>) -> Self {
        Self::Context {
            context: context.into(),
            source: Box::new(self),
        }
    }

    /// The machine-readable error code and HTTP status for JSON output.
    /// Failures with no code of their own, including argument errors, are
    /// `CommandFailed` with status 0. Context never changes the code.
    pub fn metadata(&self) -> (&str, u16) {
        match self {
            Self::Context { source, .. } => source.metadata(),
            // The OAuth error itself, such as `invalid_grant`, as in `entra`.
            Self::OAuth(details) => (details.error.as_str(), details.status),
            Self::NoAccountClaim { .. } => ("NoAccountClaim", 0),
            Self::DownloadNotConsented { .. } => ("DownloadNotConsented", 0),
            Self::CredentialLockBusy { .. } => ("CredentialLockBusy", 0),
            Self::CredentialLockFailed { .. } => ("CredentialLockFailed", 0),
            Self::Message(_) | Self::Io(_) | Self::Json(_) | Self::Http(_) | Self::Keyring(_) => {
                ("CommandFailed", 0)
            }
        }
    }

    /// Whether the identity platform refused because the app has no
    /// consent for the resource (`AADSTS65001`).
    pub fn is_consent_required(&self) -> bool {
        match self {
            Self::OAuth(details) => {
                details.error_codes.contains(&65001)
                    || details.description.starts_with("AADSTS65001")
            }
            Self::Context { source, .. } => source.is_consent_required(),
            _ => false,
        }
    }

    pub fn is_credential_lock_busy(&self) -> bool {
        match self {
            Self::CredentialLockBusy { .. } => true,
            Self::Context { source, .. } => source.is_credential_lock_busy(),
            _ => false,
        }
    }
}

impl From<&str> for PurviewError {
    fn from(value: &str) -> Self {
        Self::Message(value.to_owned())
    }
}

impl From<String> for PurviewError {
    fn from(value: String) -> Self {
        Self::Message(value)
    }
}

pub type Result<T> = std::result::Result<T, PurviewError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_plain_failure_is_command_failed_with_status_zero() {
        assert_eq!(
            PurviewError::message("no such thing").metadata(),
            ("CommandFailed", 0)
        );
        let io = PurviewError::from(std::io::Error::other("disk full"));
        assert_eq!(io.metadata(), ("CommandFailed", 0));
    }

    fn oauth(codes: Vec<i64>, description: &str) -> PurviewError {
        PurviewError::OAuth(Box::new(OAuthDetails {
            operation: "redeeming the refresh token".into(),
            status: 400,
            error: "invalid_grant".into(),
            description: description.into(),
            error_codes: codes,
            trace_id: "trace-0001".into(),
            ..OAuthDetails::default()
        }))
    }

    #[test]
    fn an_oauth_refusal_keeps_its_own_code_and_status_and_names_its_identifiers() {
        let error = oauth(vec![70000], "AADSTS70000: the grant is invalid");
        assert_eq!(error.metadata(), ("invalid_grant", 400));
        assert_eq!(
            error.to_string(),
            "redeeming the refresh token failed with HTTP 400: invalid_grant: AADSTS70000: the \
             grant is invalid (error codes 70000; trace id trace-0001)"
        );
        assert!(!error.is_consent_required());
    }

    #[test]
    fn consent_is_recognised_by_code_or_by_description_through_context() {
        assert!(oauth(vec![65001], "").is_consent_required());
        assert!(oauth(Vec::new(), "AADSTS65001: no consent")
            .context("signing in")
            .is_consent_required());
        assert!(!PurviewError::message("AADSTS65001").is_consent_required());
    }

    #[test]
    fn context_keeps_the_code_and_adds_to_the_message() {
        let error = PurviewError::message("permission denied").context("writing config.json");
        assert_eq!(error.metadata(), ("CommandFailed", 0));
        assert_eq!(error.to_string(), "writing config.json: permission denied");
    }
}
