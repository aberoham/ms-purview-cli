//! Shared harness for in-process flows: an injected `Env` with an
//! in-memory credential store, a manual clock and a wiremock identity
//! platform; fixture loading; and the canary scanner.

#![allow(dead_code)]

use std::path::{Path, PathBuf};
use std::sync::Arc;

use base64::Engine;
use ms_purview_cli::cli::{execute_with, Outcome};
use ms_purview_cli::env::{test_epoch, Captured, Env, ManualClock};
use ms_purview_cli::secrets::{AccountLocks, MemoryStore};
use serde_json::Value;
use std::time::Duration;
use url::form_urlencoded;
use wiremock::{Match, MockServer, Request};

pub const CLIENT_ID: &str = "00000000-0000-4000-8000-000000000001";
pub const TENANT_ID: &str = "00000000-0000-4000-8000-000000000002";
pub const ALEX: &str = "alex.wilber@contoso.example";

/// Every token value the fixtures hand out. None may appear in output or
/// in a file under the configuration directory.
pub const CANARIES: &[&str] = &[
    "canary-device-code-0001",
    "canary-graph-access-0001",
    "canary-graph-access-0002",
    "canary-graph-access-0003",
    "canary-download-access-0001",
    "canary-download-access-0002",
    "canary-refresh-0001",
    "canary-refresh-0002",
    "canary-refresh-0003",
    "canary-refresh-0004",
];

pub fn fixture(name: &str) -> Value {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/auth")
        .join(name);
    serde_json::from_slice(&std::fs::read(&path).unwrap())
        .unwrap_or_else(|error| panic!("{}: {error}", path.display()))
}

/// An unsigned JSON Web Token carrying the claims in an id-claims fixture.
pub fn id_token(claims_fixture: &str) -> String {
    let encode =
        |value: &Value| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(value.to_string());
    format!(
        "{}.{}.",
        encode(&serde_json::json!({"alg": "none", "typ": "JWT"})),
        encode(&fixture(claims_fixture))
    )
}

/// `token-graph.json` with an id token for the given claims.
pub fn graph_token(claims_fixture: &str) -> Value {
    let mut body = fixture("token-graph.json");
    body["id_token"] = Value::from(id_token(claims_fixture));
    body
}

/// A token response with the given values, for refresh rounds.
pub fn token(access: &str, refresh: &str, scope: &str) -> Value {
    serde_json::json!({
        "token_type": "Bearer",
        "scope": scope,
        "expires_in": 3599,
        "access_token": access,
        "refresh_token": refresh,
    })
}

pub fn token_path(leaf: &str) -> String {
    format!("/{TENANT_ID}/oauth2/v2.0/{leaf}")
}

/// Matches a form body holding every given pair.
pub struct Form(pub Vec<(&'static str, String)>);

impl Form {
    pub fn new(pairs: &[(&'static str, &str)]) -> Self {
        Self(
            pairs
                .iter()
                .map(|(key, value)| (*key, (*value).to_owned()))
                .collect(),
        )
    }
}

impl Match for Form {
    fn matches(&self, request: &Request) -> bool {
        let pairs: Vec<(String, String)> =
            form_urlencoded::parse(&request.body).into_owned().collect();
        self.0.iter().all(|(key, value)| {
            pairs
                .iter()
                .any(|(name, found)| name == key && found == value)
        })
    }
}

/// The form fields of a recorded request.
pub fn form_of(request: &Request) -> Vec<(String, String)> {
    form_urlencoded::parse(&request.body).into_owned().collect()
}

/// One user's machine: a credential store, a clock and a configuration
/// directory that persist across commands, and a mock identity platform.
pub struct Harness {
    pub store: Arc<MemoryStore>,
    pub clock: Arc<ManualClock>,
    pub root: tempfile::TempDir,
    pub identity: MockServer,
}

impl Harness {
    pub async fn new() -> Self {
        Self::with_store(MemoryStore::default()).await
    }

    /// A harness over the given store, such as `MemoryStore::chunked`.
    pub async fn with_store(store: MemoryStore) -> Self {
        Self {
            store: Arc::new(store),
            clock: Arc::new(ManualClock::new(test_epoch())),
            root: tempfile::tempdir().unwrap(),
            identity: MockServer::start().await,
        }
    }

    /// The per-account locks every command of this harness takes.
    pub fn account_locks(&self) -> AccountLocks {
        AccountLocks {
            dir: self.root.path().join("locks"),
            wait: Duration::from_secs(5),
        }
    }

    /// The lock file `AccountLocks` uses for `email`.
    pub fn lock_path(&self, email: &str) -> PathBuf {
        self.account_locks().dir.join(format!("{email}.lock"))
    }

    pub fn config_dir(&self) -> PathBuf {
        self.root.path().join("purview")
    }

    pub fn env(&self) -> (Env, Captured) {
        let (mut env, captured) = Env::in_memory();
        env.credentials = self.store.clone();
        env.clock = self.clock.clone();
        env.config_dir = Some(self.config_dir());
        env.identity_base = url::Url::parse(&self.identity.uri()).unwrap();
        env.account_locks = Some(self.account_locks());
        (env, captured)
    }

    pub async fn run(&self, args: &[&str]) -> Run {
        let (env, captured) = self.env();
        let mut argv = vec!["purview"];
        argv.extend_from_slice(args);
        let outcome = execute_with(env, argv).await;
        Run { outcome, captured }
    }

    /// The stored credential for an account, parsed.
    pub fn stored(&self, email: &str) -> Option<Value> {
        let key = format!("purview:token:{email}");
        // A read or parse failure fails the test: it must never pass for
        // "nothing stored".
        let text = ms_purview_cli::secrets::find_value(self.store.as_ref(), &key)
            .unwrap_or_else(|error| panic!("reading {key}: {error}"))?;
        Some(
            serde_json::from_str(&text)
                .unwrap_or_else(|error| panic!("parsing the credential under {key}: {error}")),
        )
    }

    /// The accounts with a stored credential: the store's logical entries,
    /// whatever chunk keys the platform layout adds (Windows splits each
    /// credential into a header and chunks).
    pub fn credentials(&self) -> Vec<String> {
        let prefix = "purview:token:";
        let mut accounts: Vec<String> = self
            .store
            .keys()
            .iter()
            .filter_map(|key| key.strip_prefix(prefix))
            // Chunk keys add `:<n>` or `:s<slot>:<n>`; an account name can
            // never hold a colon (it is refused as a file name).
            .filter(|account| !account.contains(':'))
            .filter(|account| {
                let stored = self.stored(account).expect("a credential under its key");
                assert_eq!(stored["version"], 1, "{stored}");
                true
            })
            .map(str::to_owned)
            .collect();
        accounts.sort();
        accounts
    }

    /// Fails unless the store holds nothing at all: no header, no chunk.
    pub fn assert_store_empty(&self) {
        assert!(self.store.keys().is_empty(), "{:?}", self.store.keys());
    }

    pub fn config(&self) -> Value {
        let path = self.config_dir().join("config.json");
        serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
    }

    pub fn account_file(&self, email: &str) -> PathBuf {
        self.config_dir()
            .join("accounts")
            .join(format!("{email}.json"))
    }

    /// Fails if any canary is in the output or in any file under the
    /// configuration directory.
    pub fn assert_no_canaries(&self, run: &Run) {
        let mut sources = vec![
            ("stdout".to_owned(), run.captured.stdout.bytes()),
            ("stderr".to_owned(), run.captured.stderr.bytes()),
        ];
        for path in files_under(self.root.path()) {
            sources.push((path.display().to_string(), std::fs::read(&path).unwrap()));
        }
        for (name, bytes) in sources {
            for canary in CANARIES {
                assert!(
                    !bytes
                        .windows(canary.len())
                        .any(|window| window == canary.as_bytes()),
                    "{canary} found in {name}"
                );
            }
        }
    }
}

pub struct Run {
    pub outcome: Outcome,
    pub captured: Captured,
}

impl Run {
    pub fn json(&self) -> Value {
        serde_json::from_str(&self.captured.stdout.text())
            .unwrap_or_else(|error| panic!("{error}: {}", self.captured.stdout.text()))
    }

    pub fn stderr(&self) -> String {
        self.captured.stderr.text()
    }

    pub fn stdout(&self) -> String {
        self.captured.stdout.text()
    }
}

fn files_under(dir: &Path) -> Vec<PathBuf> {
    let mut files = Vec::new();
    let Ok(entries) = std::fs::read_dir(dir) else {
        return files;
    };
    for entry in entries {
        let path = entry.unwrap().path();
        if path.is_dir() {
            files.extend(files_under(&path));
        } else {
            files.push(path);
        }
    }
    files
}
