//! Shared harness for in-process flows: an injected `Env` with an
//! in-memory credential store, a manual clock, and wiremock origins for the
//! identity platform and Graph; fixture loading; and the canary scanner.

#![allow(dead_code)]

pub mod msggen;

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use base64::Engine;
use ms_purview_cli::cli::{execute_with, Outcome};
use ms_purview_cli::env::{test_epoch, BrowserOpener, Captured, Env, ManualClock};
use ms_purview_cli::secrets::{AccountLocks, MemoryStore};
use serde_json::Value;
use std::time::Duration;
use url::form_urlencoded;
use wiremock::matchers::{method, path};
use wiremock::{Match, Mock, MockServer, Request, ResponseTemplate};

pub const CLIENT_ID: &str = "00000000-0000-4000-8000-000000000001";
pub const TENANT_ID: &str = "00000000-0000-4000-8000-000000000002";
pub const ALEX: &str = "alex.wilber@contoso.example";

/// Every token value the fixtures hand out. None may appear in output or
/// in a file under the configuration directory.
pub const CANARIES: &[&str] = &[
    "canary-device-code-0001",
    "canary-auth-code-0001",
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

/// A Graph fixture with every `https://graph.microsoft.com/v1.0/` URL in
/// it moved to the mock origin `uri`, so paging links lead to the mock.
pub fn graph_fixture(name: &str, uri: &str) -> Value {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/graph")
        .join(name);
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("{}: {error}", path.display()));
    let text = text.replace("https://graph.microsoft.com/v1.0/", &format!("{uri}/v1.0/"));
    serde_json::from_str(&text).unwrap_or_else(|error| panic!("{}: {error}", path.display()))
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
    pub graph: MockServer,
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
            graph: MockServer::start().await,
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
        self.account_locks().path(email)
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
        env.graph_base = url::Url::parse(&format!("{}/v1.0/", self.graph.uri())).unwrap();
        env.account_locks = Some(self.account_locks());
        (env, captured)
    }

    pub async fn run(&self, args: &[&str]) -> Run {
        self.run_with(args, |_, _| {}).await
    }

    /// `run`, with the `Env` changed first, to set a browser or a timeout.
    /// The configuration also sees the streams the command will write to.
    pub async fn run_with(
        &self,
        args: &[&str],
        configure: impl FnOnce(&mut Env, &Captured),
    ) -> Run {
        let (mut env, captured) = self.env();
        configure(&mut env, &captured);
        let mut argv = vec!["purview"];
        argv.extend_from_slice(args);
        // A command that waits for something that never comes fails the
        // test rather than hanging it.
        let outcome = tokio::time::timeout(Duration::from_secs(60), execute_with(env, argv))
            .await
            .expect("the command finished within 60 seconds");
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
        self.assert_absent(run, CANARIES);
    }

    /// Fails if any of `values` is in the output or in the name or contents
    /// of any file under the harness's directory. The failure names the
    /// value's position in `values`, never the value.
    pub fn assert_absent(&self, run: &Run, values: &[&str]) {
        let mut sources = vec![
            ("stdout".to_owned(), run.captured.stdout.bytes()),
            ("stderr".to_owned(), run.captured.stderr.bytes()),
        ];
        // Names too, of files and directories: a name built from an
        // account claim could carry a token.
        for (index, path) in paths_under(self.root.path()).into_iter().enumerate() {
            sources.push((
                format!("the name of file {index}"),
                path.display().to_string().into_bytes(),
            ));
            if path.is_file() {
                sources.push((format!("file {index}"), std::fs::read(&path).unwrap()));
            }
        }
        for (name, bytes) in sources {
            for (index, value) in values.iter().enumerate() {
                assert!(
                    !bytes
                        .windows(value.len())
                        .any(|window| window == value.as_bytes()),
                    "value {index} found in {name}"
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

/// Every file and directory under `dir`, not following links.
fn paths_under(dir: &Path) -> Vec<PathBuf> {
    let mut paths = Vec::new();
    let Ok(entries) = std::fs::read_dir(dir) else {
        return paths;
    };
    for entry in entries {
        let path = entry.unwrap().path();
        paths.push(path.clone());
        if std::fs::symlink_metadata(&path).unwrap().is_dir() {
            paths.extend(paths_under(&path));
        }
    }
    paths
}

/// Plays the browser for `auth login --browser`: given the sign-in
/// address, it sends each visit to the loopback listener that the
/// address's `redirect_uri` names, over IPv4, as a browser following the
/// identity platform's redirect would. `{state}` in a visit becomes the
/// address's `state`. A visit of `<idle>` opens a connection that sends
/// nothing and stays open until the visits end, as a browser's speculative
/// connection does. It records the address and the status line of each
/// answer.
#[derive(Default)]
pub struct ScriptedBrowser {
    pub visits: Vec<String>,
    /// Report that the browser could not be opened, then make the visits
    /// once the command has printed its warning, as a person who opened the
    /// printed address would. Needs `stderr`.
    pub fail_open: bool,
    /// The command's stderr, which a `fail_open` browser watches.
    pub stderr: Mutex<Option<ms_purview_cli::env::SharedBuffer>>,
    pub opened: Mutex<Vec<url::Url>>,
    /// Each answer's status line, and how long after the browser opened it
    /// arrived, recorded together.
    pub answers: Arc<Mutex<Vec<(String, Duration)>>>,
}

impl ScriptedBrowser {
    pub fn new(visits: &[&str]) -> Arc<Self> {
        Arc::new(Self {
            visits: visits.iter().map(|visit| (*visit).to_owned()).collect(),
            ..Self::default()
        })
    }

    /// The one address the command asked the browser to open.
    pub fn opened(&self) -> url::Url {
        let opened = self.opened.lock().unwrap();
        assert_eq!(opened.len(), 1, "{opened:?}");
        opened[0].clone()
    }

    /// The status lines the listener answered with, once `count` have
    /// arrived. The browser runs on its own thread, and a command that
    /// fails at once can return before the browser has read its page.
    pub fn answers(&self, count: usize) -> Vec<String> {
        self.timed_answers(count)
            .into_iter()
            .map(|(status, _)| status)
            .collect()
    }

    /// `answers`, each with how long after the browser opened it arrived.
    pub fn timed_answers(&self, count: usize) -> Vec<(String, Duration)> {
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        loop {
            let answers = self.answers.lock().unwrap().clone();
            if answers.len() >= count || std::time::Instant::now() > deadline {
                return answers;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}

/// A query parameter of a URL, which must appear exactly once.
pub fn query_value(url: &url::Url, name: &str) -> String {
    let values: Vec<String> = url
        .query_pairs()
        .filter(|(key, _)| key == name)
        .map(|(_, value)| value.into_owned())
        .collect();
    assert_eq!(values.len(), 1, "{name} in {url}");
    values[0].clone()
}

impl BrowserOpener for ScriptedBrowser {
    fn open(&self, url: &url::Url) -> std::io::Result<()> {
        self.opened.lock().unwrap().push(url.clone());
        let redirect = url::Url::parse(&query_value(url, "redirect_uri")).unwrap();
        let port = redirect.port().expect("a loopback redirect names its port");
        let state = query_value(url, "state");
        let visits = self.visits.clone();
        let answers = self.answers.clone();
        let opened_at = std::time::Instant::now();
        let play = move || {
            let mut idle = Vec::new();
            for visit in visits {
                if visit == "<idle>" {
                    idle.push(std::net::TcpStream::connect(("127.0.0.1", port)).unwrap());
                    continue;
                }
                let target = visit.replace("{state}", &state);
                let mut stream = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(10)))
                    .unwrap();
                stream
                    .set_write_timeout(Some(Duration::from_secs(10)))
                    .unwrap();
                write!(
                    stream,
                    "GET {target} HTTP/1.1\r\nHost: localhost:{port}\r\n\r\n"
                )
                .unwrap();
                let mut answer = String::new();
                stream.read_to_string(&mut answer).unwrap();
                answers.lock().unwrap().push((
                    answer.lines().next().unwrap_or_default().to_owned(),
                    opened_at.elapsed(),
                ));
            }
        };
        if self.fail_open {
            let stderr = self
                .stderr
                .lock()
                .unwrap()
                .clone()
                .expect("a fail_open browser watches the command's stderr");
            std::thread::spawn(move || {
                let deadline = std::time::Instant::now() + Duration::from_secs(10);
                // Without the warning there is no visit, and the command's
                // own timeout fails the test.
                while !stderr.text().contains("could not open the browser") {
                    if std::time::Instant::now() > deadline {
                        return;
                    }
                    std::thread::sleep(Duration::from_millis(10));
                }
                play();
            });
            return Err(std::io::Error::other("no browser found"));
        }
        play();
        Ok(())
    }
}

pub fn json_response(status: u16, body: Value) -> ResponseTemplate {
    ResponseTemplate::new(status).set_body_json(body)
}

/// Mounts a device-code sign-in: the device code, one pending poll, the
/// Graph token with the given claims, then `download` for the download
/// redemption.
pub async fn mount_login(harness: &Harness, claims: &str, download: ResponseTemplate) {
    Mock::given(method("POST"))
        .and(path(token_path("devicecode")))
        .respond_with(json_response(200, fixture("device-code.json")))
        .expect(1)
        .mount(&harness.identity)
        .await;
    let device_grant = Form::new(&[
        ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
        ("device_code", "canary-device-code-0001"),
        ("client_id", CLIENT_ID),
    ]);
    Mock::given(method("POST"))
        .and(path(token_path("token")))
        .and(device_grant)
        .respond_with(json_response(400, fixture("authorization-pending.json")))
        .up_to_n_times(1)
        .with_priority(1)
        .mount(&harness.identity)
        .await;
    Mock::given(method("POST"))
        .and(path(token_path("token")))
        .and(Form::new(&[(
            "grant_type",
            "urn:ietf:params:oauth:grant-type:device_code",
        )]))
        .respond_with(json_response(200, graph_token(claims)))
        .with_priority(2)
        .mount(&harness.identity)
        .await;
    Mock::given(method("POST"))
        .and(path(token_path("token")))
        .and(Form::new(&[
            ("grant_type", "refresh_token"),
            ("refresh_token", "canary-refresh-0001"),
            (
                "scope",
                "b26e684c-5068-4120-a679-64a5d2c909d9/.default offline_access",
            ),
        ]))
        .respond_with(download)
        .expect(1)
        .mount(&harness.identity)
        .await;
}

pub async fn sign_in_alex(harness: &Harness) {
    mount_login(
        harness,
        "id-claims-preferred.json",
        json_response(200, fixture("token-download.json")),
    )
    .await;
    let run = harness
        .run(&[
            "auth",
            "login",
            "--client-id",
            CLIENT_ID,
            "--tenant-id",
            TENANT_ID,
        ])
        .await;
    assert_eq!(run.outcome.exit_code, 0, "{}", run.stderr());
    harness.identity.reset().await;
}
