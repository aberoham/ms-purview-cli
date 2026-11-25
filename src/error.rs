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
            Self::Message(_) | Self::Io(_) | Self::Json(_) => ("CommandFailed", 0),
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

    #[test]
    fn context_keeps_the_code_and_adds_to_the_message() {
        let error = PurviewError::message("permission denied").context("writing config.json");
        assert_eq!(error.metadata(), ("CommandFailed", 0));
        assert_eq!(error.to_string(), "writing config.json: permission denied");
    }
}
