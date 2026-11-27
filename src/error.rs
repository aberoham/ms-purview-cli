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

    /// A refusal from Microsoft Graph. Only the allow-listed fields of the
    /// error body are kept (`docs/SPEC.md` section 6.8), and the message has
    /// been through the Redactor.
    #[error("{0}")]
    Graph(Box<GraphErrorDetails>),

    /// The token provider could not supply a token for a request: the
    /// refresh was refused or failed, or its result could not be stored.
    /// Kept apart from the request's own failures, so that `auth status`
    /// can tell a broken sign-in from Graph's answer. The code and status
    /// are the source's.
    #[error("{0}")]
    TokenUnavailable(Box<PurviewError>),

    /// A URL from a response, such as a paging link, whose origin is not
    /// the one the client may send to. The URL has been through
    /// `redact::url`.
    #[error("Microsoft Graph returned a {what} on another origin ({url}); refusing to follow it")]
    ForeignOrigin { what: &'static str, url: String },

    /// A credential-store failure, kept as its rendered message only:
    /// `keyring::Error`'s `Debug` form can hold the stored bytes (as in
    /// `BadEncoding`), and this enum derives `Debug`.
    #[error("credential store operation failed: {0}")]
    Keyring(String),

    /// A Graph GET that got no complete response in any of its attempts:
    /// the connection failed, the request timed out or the body was cut
    /// off. Kept apart from Graph's own answers, so that polling can wait
    /// and try again.
    #[error("could not reach Microsoft Graph: {reason} ({attempts} attempts)")]
    GraphUnreachable { reason: String, attempts: u32 },

    /// A case name that matches more than one case. The message lists
    /// each match's id, status and creation date, never its name.
    #[error("{0}")]
    AmbiguousCase(String),

    /// A search name that matches more than one search in the case.
    #[error("{0}")]
    AmbiguousSearch(String),

    /// No case has the id or exact display name given.
    #[error("{0}")]
    CaseNotFound(String),

    /// No search in the case has the id or exact display name given.
    #[error("{0}")]
    SearchNotFound(String),

    /// A filter that needs each operation read on its own (`--resolve`),
    /// because the operation list cannot tell the actions apart.
    #[error("{0}")]
    ResolveRequired(String),

    /// The download service answered the download token with HTTP 401 or
    /// 403.
    #[error(
        "the download service refused the download token (HTTP {status}): the account needs \
         the Purview eDiscovery permission eDiscovery.Download.Read and an eDiscovery role; \
         run 'purview auth refresh' and try again"
    )]
    DownloadRefused { status: u16 },

    /// A download redirected to another origin. `target` is that origin
    /// alone (scheme, host and port), never its path or query.
    #[error("the download service redirected to another origin ({target}); refusing to follow it")]
    CrossOriginRedirect { target: String },

    /// A file of the operation that cannot be downloaded: no name, no
    /// `downloadUrl`, or one the download host rule refuses. The other
    /// files are still downloaded.
    #[error("{0}")]
    FileNotDownloadable(String),

    /// `--no-write` (or `PURVIEW_NO_WRITE`) refused a write command before
    /// sign-in.
    #[error(
        "this command changes Purview, and --no-write (or PURVIEW_NO_WRITE) refuses every \
         write; nothing was sent"
    )]
    WriteRefused,

    /// The account cannot write: it signed in with `--read-only`, or its
    /// credential predates the record of how it signed in. Refused before
    /// any network call.
    #[error("{0}")]
    ReadOnlySession(String),

    /// A POST whose outcome is unknown: no response, a timeout, HTTP 429
    /// or a 5xx. It is never sent again. `candidates` names what the
    /// command found that the request may have created.
    #[error(
        "the write may or may not have been applied: {reason}. It was not sent again{}",
        candidates_text(.candidates, .notes)
    )]
    WriteOutcomeUnknown {
        reason: String,
        candidates: Vec<String>,
        /// What the check found besides candidates, such as a list that
        /// stopped early.
        notes: Vec<String>,
    },

    /// The target exists and is not a verified download of the file.
    #[error(
        "{path} already exists and is not a verified download of this file; pass --overwrite to \
         replace it"
    )]
    TargetExists { path: String },

    /// Another writer created the target while the download ran. Its file
    /// is kept.
    #[error(
        "{path} was created by another writer while the download ran; it was kept, and the \
         download was not published"
    )]
    TargetAppeared { path: String },

    /// The file system cannot make the hard link that publishing without
    /// replacement needs.
    #[error(
        "the file system holding {path} does not support hard links, which publishing without \
         --overwrite needs; pass --overwrite to publish by renaming"
    )]
    PublishUnsupported { path: String },

    /// The file was published and verified, but the manifest could not be
    /// updated. The next download in the directory records it.
    #[error(
        "{path} was downloaded and verified, but manifest.json could not be updated ({reason}); \
         the next download in that directory records it"
    )]
    ManifestWriteFailed { path: String, reason: String },

    /// A stored password entry that its backend cannot decode (on Windows,
    /// a blob that is not UTF-16LE). Kept apart from access failures, so
    /// that a repair the ownership check authorised can replace it.
    #[error("a stored credential entry could not be decoded: {0}")]
    CredentialEncoding(String),

    #[error(
        "another purview process kept the credential lock {path} busy for over {seconds} \
         seconds; wait for it to finish and try again"
    )]
    CredentialLockBusy { path: String, seconds: u64 },

    /// A query the guard's parser does not accept (`docs/SPEC.md` section
    /// 6.3). `column` counts characters from 1. `reason` names the
    /// construct, and quotes the query's text only when it is one of the
    /// grammar's fixed symbols, never a word the user or the tenant wrote.
    /// No override accepts it.
    #[error("the query is not understood at column {column}: {reason}")]
    KqlNotUnderstood { column: usize, reason: String },

    /// A query that the guard does not find narrowed: some branch that can
    /// match a message has neither a specific term nor a `participants:`
    /// restriction on a full address.
    #[error("{0}")]
    GenericQuery(String),

    /// `case create` found cases with the display name it would use. The
    /// message lists each match's id and status, never the name.
    #[error("{0}")]
    CaseNameInUse(String),

    /// `search create` found a search in the case with the display name
    /// it would use. The message lists each match's id, never the name.
    #[error("{0}")]
    SearchNameInUse(String),

    /// A write that needs an active case found it in another status.
    #[error("{0}")]
    CaseNotActive(String),

    /// An action's search whose scope could not be shown to be every
    /// tenant mailbox and nothing else: `dataSourceScopes` absent, or a
    /// source list that could not be read to its end.
    #[error("{0}")]
    ScopeUnverified(String),

    /// An action's search with a `dataSourceScopes` other than
    /// `allTenantMailboxes`.
    #[error("{0}")]
    ScopeNotAllowed(String),

    /// An action's search with custodian, non-custodial or additional
    /// sources.
    #[error("{0}")]
    SearchHasSources(String),

    /// An action's search whose query, or the guard's verdict on it,
    /// changed between the plan and the send, while still passing the
    /// checks; a search that no longer passes gets that check's error.
    #[error("{0}")]
    SearchChanged(String),

    /// A 202 whose `Location` header does not name an operation of the
    /// case in a known form. The operation may still be running.
    #[error("{0}")]
    UnexpectedLocation(String),

    /// An action whose plan names an operation that may be a duplicate,
    /// without `--allow-concurrent` (`docs/SPEC.md` section 6.7).
    #[error("{0}")]
    ConcurrentOperation(String),

    /// A zip that is refused before or while it is read: not a zip, too
    /// many entries, a name that would leave its folder, or more bytes, or
    /// a higher ratio, than the limits allow. Never names an entry.
    #[error("refusing the zip: {0}")]
    HostileZip(String),

    /// A CSV record larger than `limits.csv_max_record_bytes`.
    #[error("a CSV record in {file} is larger than {limit} bytes (limits.csv_max_record_bytes)")]
    RecordTooLarge { file: String, limit: u64 },

    /// A zip that is not the kind the command reads, such as a zip with
    /// no `Locations-*.csv` for `parse locations`.
    #[error("{0}")]
    NotAReportZip(String),

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

/// The allow-listed fields of a Graph error body: `error.code`,
/// `error.message`, `error.innerError.request-id` and
/// `error.innerError.date`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GraphErrorDetails {
    pub status: u16,
    pub code: String,
    pub message: String,
    pub request_id: String,
    pub date: String,
    /// The wait Graph's `Retry-After` header asked for, if any. Not
    /// printed; polling uses it to space its next read.
    pub retry_after: Option<std::time::Duration>,
}

/// The status and Graph's code and message, then the identifiers a support
/// case needs.
impl std::fmt::Display for GraphErrorDetails {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "Microsoft Graph returned HTTP {}", self.status)?;
        if !self.code.is_empty() {
            write!(formatter, ": {}", self.code)?;
        }
        if !self.message.is_empty() {
            write!(formatter, ": {}", self.message)?;
        }
        let details: Vec<String> = [("request id", &self.request_id), ("date", &self.date)]
            .into_iter()
            .filter(|(_, value)| !value.is_empty())
            .map(|(label, value)| format!("{label} {value}"))
            .collect();
        if !details.is_empty() {
            write!(formatter, " ({})", details.join("; "))?;
        }
        Ok(())
    }
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
            Self::TokenUnavailable(source) => source.metadata(),
            // The OAuth error itself, such as `invalid_grant`, as in `entra`.
            Self::OAuth(details) => (details.error.as_str(), details.status),
            // Graph's own code, such as `Forbidden`, and the HTTP status.
            Self::Graph(details) if !details.code.is_empty() => {
                (details.code.as_str(), details.status)
            }
            Self::Graph(details) => ("GraphError", details.status),
            Self::ForeignOrigin { .. } => ("ForeignOrigin", 0),
            Self::NoAccountClaim { .. } => ("NoAccountClaim", 0),
            Self::DownloadNotConsented { .. } => ("DownloadNotConsented", 0),
            Self::CredentialLockBusy { .. } => ("CredentialLockBusy", 0),
            Self::CredentialLockFailed { .. } => ("CredentialLockFailed", 0),
            Self::AmbiguousCase(_) => ("AmbiguousCase", 0),
            Self::AmbiguousSearch(_) => ("AmbiguousSearch", 0),
            Self::CaseNotFound(_) => ("CaseNotFound", 0),
            Self::SearchNotFound(_) => ("SearchNotFound", 0),
            Self::ResolveRequired(_) => ("ResolveRequired", 0),
            Self::DownloadRefused { status } => ("DownloadRefused", *status),
            Self::CrossOriginRedirect { .. } => ("CrossOriginRedirect", 0),
            Self::FileNotDownloadable(_) => ("FileNotDownloadable", 0),
            Self::TargetExists { .. } => ("TargetExists", 0),
            Self::TargetAppeared { .. } => ("TargetAppeared", 0),
            Self::PublishUnsupported { .. } => ("PublishUnsupported", 0),
            Self::ManifestWriteFailed { .. } => ("ManifestWriteFailed", 0),
            Self::KqlNotUnderstood { .. } => ("KqlNotUnderstood", 0),
            Self::GenericQuery(_) => ("GenericQuery", 0),
            Self::CaseNameInUse(_) => ("CaseNameInUse", 0),
            Self::SearchNameInUse(_) => ("SearchNameInUse", 0),
            Self::CaseNotActive(_) => ("CaseNotActive", 0),
            Self::ConcurrentOperation(_) => ("ConcurrentOperation", 0),
            Self::ScopeUnverified(_) => ("ScopeUnverified", 0),
            Self::ScopeNotAllowed(_) => ("ScopeNotAllowed", 0),
            Self::SearchHasSources(_) => ("SearchHasSources", 0),
            Self::UnexpectedLocation(_) => ("UnexpectedLocation", 0),
            Self::SearchChanged(_) => ("SearchChanged", 0),
            Self::HostileZip(_) => ("HostileZip", 0),
            Self::RecordTooLarge { .. } => ("RecordTooLarge", 0),
            Self::NotAReportZip(_) => ("NotAReportZip", 0),
            Self::WriteRefused => ("WriteRefused", 0),
            Self::ReadOnlySession(_) => ("ReadOnlySession", 0),
            Self::WriteOutcomeUnknown { .. } => ("WriteOutcomeUnknown", 0),
            Self::Message(_)
            | Self::GraphUnreachable { .. }
            | Self::Io(_)
            | Self::Json(_)
            | Self::Http(_)
            | Self::Keyring(_)
            | Self::CredentialEncoding(_) => ("CommandFailed", 0),
        }
    }

    /// Whether the identity platform refused because the app has no
    /// consent for the resource (`AADSTS65001`).
    pub fn is_consent_required(&self) -> bool {
        match self {
            Self::OAuth(details) => {
                details.error_codes.contains(&65001)
                    || details
                        .description
                        .strip_prefix("AADSTS65001")
                        .is_some_and(|rest| !rest.starts_with(|c: char| c.is_ascii_digit()))
            }
            Self::Context { source, .. } | Self::TokenUnavailable(source) => {
                source.is_consent_required()
            }
            _ => false,
        }
    }

    /// Whether a stored entry could not be decoded, as opposed to the
    /// store failing to give access to it.
    pub fn is_credential_encoding(&self) -> bool {
        match self {
            Self::CredentialEncoding(_) => true,
            Self::Context { source, .. } => source.is_credential_encoding(),
            _ => false,
        }
    }

    /// Whether a request failed because no token could be had.
    pub fn is_token_unavailable(&self) -> bool {
        match self {
            Self::TokenUnavailable(_) => true,
            Self::Context { source, .. } => source.is_token_unavailable(),
            _ => false,
        }
    }

    /// The HTTP status of a Graph refusal, through any context.
    pub fn graph_status(&self) -> Option<u16> {
        match self {
            Self::Graph(details) => Some(details.status),
            Self::Context { source, .. } => source.graph_status(),
            _ => None,
        }
    }

    /// Whether a Graph read failed in a way that a later read may not:
    /// no complete response, HTTP 429, or any 5xx. Polling keeps waiting
    /// after such a failure.
    pub fn is_transient_graph_failure(&self) -> bool {
        match self {
            Self::GraphUnreachable { .. } => true,
            Self::Graph(details) => details.status == 429 || (500..=599).contains(&details.status),
            Self::Context { source, .. } => source.is_transient_graph_failure(),
            _ => false,
        }
    }

    /// The wait Graph asked for in `Retry-After`, through any context.
    pub fn retry_after(&self) -> Option<std::time::Duration> {
        match self {
            Self::Graph(details) => details.retry_after,
            Self::Context { source, .. } => source.retry_after(),
            _ => None,
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

impl From<keyring::Error> for PurviewError {
    fn from(error: keyring::Error) -> Self {
        Self::Keyring(error.to_string())
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

/// The candidates and notes of a `WriteOutcomeUnknown`, as the end of its
/// message.
fn candidates_text(candidates: &[String], notes: &[String]) -> String {
    let mut text = if candidates.is_empty() {
        ". Check in the Purview portal whether it took effect before running it again".to_owned()
    } else {
        format!(
            ". It may have created: {}. Check them before running the command again",
            candidates.join("; ")
        )
    };
    for note in notes {
        text.push_str(". ");
        text.push_str(note);
    }
    text
}

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
        // A longer code that begins with the same digits is another error.
        assert!(!oauth(vec![650011], "AADSTS650011: other").is_consent_required());
        assert!(oauth(Vec::new(), "AADSTS65001").is_consent_required());
    }

    #[test]
    fn a_keyring_error_keeps_no_stored_bytes() {
        let error = PurviewError::from(keyring::Error::BadEncoding(b"canary-bytes-0001".to_vec()));
        let message = keyring::Error::BadEncoding(Vec::new()).to_string();
        assert_eq!(format!("{error:?}"), format!("Keyring({message:?})"));
        assert_eq!(
            error.to_string(),
            format!("credential store operation failed: {message}")
        );
        // Neither form holds the bytes, as text or as the numbers a derived
        // Debug of a Vec<u8> would print.
        let numbers = format!("{:?}", b"canary-bytes-0001".to_vec());
        assert!(!format!("{error:?}").contains(numbers.trim_matches(['[', ']'])));
    }

    #[test]
    fn a_graph_refusal_keeps_graph_s_code_and_the_status_through_context() {
        let error = PurviewError::Graph(Box::new(GraphErrorDetails {
            status: 403,
            code: "Forbidden".into(),
            message: "no role".into(),
            request_id: "request-0001".into(),
            date: "2026-01-05T09:00:00".into(),
            retry_after: None,
        }))
        .context("checking the Purview role");
        assert_eq!(error.metadata(), ("Forbidden", 403));
        assert_eq!(error.graph_status(), Some(403));
        assert_eq!(
            error.to_string(),
            "checking the Purview role: Microsoft Graph returned HTTP 403: Forbidden: no role \
             (request id request-0001; date 2026-01-05T09:00:00)"
        );
        let bare = PurviewError::Graph(Box::new(GraphErrorDetails {
            status: 502,
            ..GraphErrorDetails::default()
        }));
        assert_eq!(bare.metadata(), ("GraphError", 502));
        assert_eq!(bare.to_string(), "Microsoft Graph returned HTTP 502");
        assert_eq!(PurviewError::message("x").graph_status(), None);
    }

    #[test]
    fn context_keeps_the_code_and_adds_to_the_message() {
        let error = PurviewError::message("permission denied").context("writing config.json");
        assert_eq!(error.metadata(), ("CommandFailed", 0));
        assert_eq!(error.to_string(), "writing config.json: permission denied");
    }
}
