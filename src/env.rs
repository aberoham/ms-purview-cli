//! `Env`: everything a command reads from or writes to outside its
//! arguments, injected so that `cli::execute_with` can run a whole command
//! in-process under test.
//!
//! Later releases add the Graph origin, the token endpoint, the download
//! host rule, the credential store and the clock here. The production
//! `Env` reads no environment variable that could change an endpoint.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fmt;
use std::io::{self, IsTerminal, Write};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use crate::redact::{RedactingWriter, Redactor};

#[doc(hidden)]
pub struct Env {
    /// Holds every secret seen, for the life of the process.
    pub redactor: Arc<Redactor>,
    /// Standard output, through the redactor.
    pub stdout: RedactingWriter,
    /// Standard error, through the redactor.
    pub stderr: RedactingWriter,
    pub stdin_is_terminal: bool,
    pub stdout_is_terminal: bool,
    pub stderr_is_terminal: bool,
    /// `PURVIEW_CONFIG_DIR`; `None` means the platform default.
    pub config_dir: Option<PathBuf>,
    /// The `PURVIEW_*` variables that set flag defaults, as captured by
    /// `production()`. Commands read flag defaults only from here, never
    /// from the process environment, so an in-process run does not depend
    /// on the shell that started the tests.
    pub vars: BTreeMap<String, OsString>,
}

/// The environment variables that give global flags their defaults.
pub const FLAG_VARIABLES: &[&str] = &["PURVIEW_JSON", "PURVIEW_RESULTS_ONLY", "PURVIEW_PLAIN"];

impl fmt::Debug for Env {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Env")
            .field("redactor", &self.redactor)
            .field("stdin_is_terminal", &self.stdin_is_terminal)
            .field("stdout_is_terminal", &self.stdout_is_terminal)
            .field("stderr_is_terminal", &self.stderr_is_terminal)
            .field("config_dir", &self.config_dir)
            .field("vars", &self.vars)
            .finish_non_exhaustive()
    }
}

impl Env {
    /// The process's own streams and terminal state.
    pub fn production() -> Self {
        let redactor = Arc::new(Redactor::new());
        Self {
            stdout: RedactingWriter::new(Box::new(io::stdout()), redactor.clone()),
            stderr: RedactingWriter::new(Box::new(io::stderr()), redactor.clone()),
            redactor,
            stdin_is_terminal: io::stdin().is_terminal(),
            stdout_is_terminal: io::stdout().is_terminal(),
            stderr_is_terminal: io::stderr().is_terminal(),
            config_dir: std::env::var_os("PURVIEW_CONFIG_DIR")
                .filter(|value| !value.is_empty())
                .map(PathBuf::from),
            vars: FLAG_VARIABLES
                .iter()
                .filter_map(|name| std::env::var_os(name).map(|value| ((*name).to_owned(), value)))
                .collect(),
        }
    }

    /// An `Env` whose stdout and stderr are kept in memory, with no
    /// terminal attached and no `PURVIEW_*` variables set, for in-process
    /// tests.
    #[doc(hidden)]
    pub fn in_memory() -> (Self, Captured) {
        let captured = Captured::default();
        let env = Self::with_writers(
            Box::new(captured.stdout.clone()),
            Box::new(captured.stderr.clone()),
        );
        (env, captured)
    }

    /// An `Env` over the given streams, with no terminal attached and no
    /// `PURVIEW_*` variables set, for tests of output failures.
    #[doc(hidden)]
    pub fn with_writers(stdout: Box<dyn Write + Send>, stderr: Box<dyn Write + Send>) -> Self {
        let redactor = Arc::new(Redactor::new());
        Self {
            stdout: RedactingWriter::new(stdout, redactor.clone()),
            stderr: RedactingWriter::new(stderr, redactor.clone()),
            redactor,
            stdin_is_terminal: false,
            stdout_is_terminal: false,
            stderr_is_terminal: false,
            config_dir: None,
            vars: BTreeMap::new(),
        }
    }
}

/// The streams of an in-memory `Env`, readable after the command ends.
#[doc(hidden)]
#[derive(Debug, Clone, Default)]
pub struct Captured {
    pub stdout: SharedBuffer,
    pub stderr: SharedBuffer,
}

#[doc(hidden)]
#[derive(Debug, Clone, Default)]
pub struct SharedBuffer(Arc<Mutex<Vec<u8>>>);

impl SharedBuffer {
    pub fn bytes(&self) -> Vec<u8> {
        self.0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.bytes()).into_owned()
    }
}

impl Write for SharedBuffer {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        self.0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .extend_from_slice(buffer);
        Ok(buffer.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
