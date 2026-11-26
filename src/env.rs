//! `Env`: everything a command reads from or writes to outside its
//! arguments, injected so that `cli::execute_with` can run a whole command
//! in-process under test.
//!
//! It carries the identity-platform base URL, the credential store and the
//! clock. Later releases add the Graph origin and the download host rule.
//! The production `Env` reads no environment variable that could change an
//! endpoint, so the release binary has no path that could send a token to
//! another host.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fmt;
use std::io::{self, IsTerminal, Write};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use url::Url;

use crate::redact::{RedactingWriter, Redactor};
use crate::secrets::{CredentialStore, KeyringStore, MemoryStore};

/// The Microsoft identity platform. The device-code and token endpoints
/// are `<tenant>/oauth2/v2.0/devicecode` and `<tenant>/oauth2/v2.0/token`
/// below it.
pub const IDENTITY_BASE: &str = "https://login.microsoftonline.com";

/// Wall-clock time and waiting, injected so that tests control expiry and
/// polling without sleeping.
#[async_trait]
pub trait Clock: Send + Sync {
    /// Wall-clock time, for token expiry stamps.
    fn now(&self) -> DateTime<Utc>;
    /// Monotonic time since the clock was made, for deadlines that a change
    /// to the wall clock must not move.
    fn elapsed(&self) -> Duration;
    async fn sleep(&self, duration: Duration);
}

/// The system clock and tokio's timer.
#[derive(Debug)]
pub struct SystemClock {
    started: tokio::time::Instant,
}

impl Default for SystemClock {
    fn default() -> Self {
        Self {
            started: tokio::time::Instant::now(),
        }
    }
}

#[async_trait]
impl Clock for SystemClock {
    fn now(&self) -> DateTime<Utc> {
        Utc::now()
    }

    fn elapsed(&self) -> Duration {
        self.started.elapsed()
    }

    async fn sleep(&self, duration: Duration) {
        tokio::time::sleep(duration).await;
    }
}

/// A clock for tests: time moves only when a test advances it or a
/// command sleeps, and sleeping returns at once.
#[doc(hidden)]
#[derive(Debug)]
pub struct ManualClock {
    now: Mutex<DateTime<Utc>>,
    elapsed: Mutex<Duration>,
    slept: Mutex<Vec<Duration>>,
}

#[doc(hidden)]
impl ManualClock {
    pub fn new(now: DateTime<Utc>) -> Self {
        Self {
            now: Mutex::new(now),
            elapsed: Mutex::default(),
            slept: Mutex::default(),
        }
    }

    /// Moves the wall clock and the monotonic clock forward together.
    pub fn advance(&self, duration: Duration) {
        let mut now = self
            .now
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        *now += chrono::Duration::from_std(duration).unwrap_or(chrono::Duration::MAX);
        *self
            .elapsed
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) += duration;
    }

    /// Every sleep a command asked for, in order.
    pub fn sleeps(&self) -> Vec<Duration> {
        self.slept
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }
}

#[async_trait]
impl Clock for ManualClock {
    fn now(&self) -> DateTime<Utc> {
        *self
            .now
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn elapsed(&self) -> Duration {
        *self
            .elapsed
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    async fn sleep(&self, duration: Duration) {
        self.slept
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .push(duration);
        self.advance(duration);
        tokio::task::yield_now().await;
    }
}

/// The instant an in-memory `Env`'s clock starts at.
#[doc(hidden)]
pub fn test_epoch() -> DateTime<Utc> {
    DateTime::parse_from_rfc3339("2026-01-05T09:00:00Z")
        .map(|value| value.with_timezone(&Utc))
        .unwrap_or(DateTime::<Utc>::UNIX_EPOCH)
}

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
    /// The identity platform: `IDENTITY_BASE` in production, a mock origin
    /// in tests.
    pub identity_base: Url,
    /// Where tokens persist: the operating-system store in production, a
    /// `MemoryStore` in tests.
    pub credentials: Arc<dyn CredentialStore>,
    pub clock: Arc<dyn Clock>,
    /// The timeout for each identity-platform request: `auth::REQUEST_TIMEOUT`
    /// in production; tests shorten it to exercise a stalled request.
    pub identity_timeout: Duration,
    /// Makes one of `auth login`'s writes fail before it is made, for tests
    /// of a sign-in that stops part way. Always `None` in production.
    #[doc(hidden)]
    pub login_write_fault: Option<LoginWrite>,
    /// The per-account locks that serialise login, logout and refresh
    /// commits across processes. `None` in `in_memory()` until a test sets
    /// them.
    pub account_locks: Option<crate::secrets::AccountLocks>,
}

/// One of the writes that store a sign-in, in the order they are made.
#[doc(hidden)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoginWrite {
    Credential,
    AccountFile,
    Config,
}

/// The environment variables that give flags their defaults.
pub const FLAG_VARIABLES: &[&str] = &[
    "PURVIEW_JSON",
    "PURVIEW_RESULTS_ONLY",
    "PURVIEW_PLAIN",
    "PURVIEW_SELECT",
    "PURVIEW_ACCOUNT",
    "PURVIEW_NO_INPUT",
    "PURVIEW_CLIENT_ID",
    "PURVIEW_TENANT_ID",
];

impl fmt::Debug for Env {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Env")
            .field("redactor", &self.redactor)
            .field("stdin_is_terminal", &self.stdin_is_terminal)
            .field("stdout_is_terminal", &self.stdout_is_terminal)
            .field("stderr_is_terminal", &self.stderr_is_terminal)
            .field("config_dir", &self.config_dir)
            // Names only: a value could be anything a user pasted.
            .field("vars", &self.vars.keys().collect::<Vec<_>>())
            .field("identity_base", &self.identity_base.as_str())
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
            identity_base: production_identity_base(),
            credentials: Arc::new(KeyringStore),
            clock: Arc::new(SystemClock::default()),
            identity_timeout: crate::auth::REQUEST_TIMEOUT,
            login_write_fault: None,
            account_locks: crate::secrets::AccountLocks::production(),
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

    /// An `Env` over the given streams, with no terminal attached, no
    /// `PURVIEW_*` variables set, an empty in-memory credential store, a
    /// manual clock at `test_epoch()`, and an identity platform that cannot
    /// be reached until a test points it at a mock.
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
            identity_base: unreachable_identity_base(),
            credentials: Arc::new(MemoryStore::default()),
            clock: Arc::new(ManualClock::new(test_epoch())),
            identity_timeout: crate::auth::REQUEST_TIMEOUT,
            login_write_fault: None,
            account_locks: None,
        }
    }
}

fn production_identity_base() -> Url {
    // A constant that parses; the test below proves it.
    Url::parse(IDENTITY_BASE).unwrap_or_else(|_| unreachable_identity_base())
}

/// A host under the reserved `.example` domain (RFC 2606), which a test
/// must replace with a mock origin.
fn unreachable_identity_base() -> Url {
    Url::parse("http://identity-unset.example")
        .unwrap_or_else(|_| unreachable!("a valid URL literal"))
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn production_endpoints_are_the_identity_platform() {
        assert_eq!(
            production_identity_base().as_str(),
            "https://login.microsoftonline.com/"
        );
    }

    #[tokio::test]
    async fn the_manual_clock_moves_only_when_told_or_slept() {
        let clock = ManualClock::new(test_epoch());
        assert_eq!(clock.now(), test_epoch());
        clock.sleep(Duration::from_secs(5)).await;
        clock.advance(Duration::from_secs(1));
        assert_eq!(clock.now(), test_epoch() + chrono::Duration::seconds(6));
        assert_eq!(clock.sleeps(), [Duration::from_secs(5)]);
    }

    #[test]
    fn the_debug_form_names_flag_variables_without_their_values() {
        let (mut env, _) = Env::in_memory();
        env.redactor.register("canary-plain-0001");
        env.vars
            .insert("PURVIEW_PLAIN".into(), "canary-plain-0001".into());
        let shown = format!("{env:?}");
        assert!(shown.contains("PURVIEW_PLAIN"), "{shown}");
        assert!(!shown.contains("canary"), "{shown}");
    }
}
