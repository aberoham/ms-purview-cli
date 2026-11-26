//! Tokens at runtime (`docs/SPEC.md` section 4.5): the secret newtypes, the
//! stored credential and the `TokenProvider` that refreshes both resources
//! lazily from one refresh token.
//!
//! Every secret value seen here is registered with the Redactor as soon as
//! it is received, and stays registered until the process exits, including
//! refresh tokens that a rotation has superseded.

use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use chrono::{DateTime, SecondsFormat, Utc};
use serde::{Deserialize, Deserializer, Serialize};

use crate::auth::{self, IdentityClient, TokenResponse};
use crate::env::Clock;
use crate::error::{PurviewError, Result};
use crate::redact::{Redactor, REDACTED};
use crate::secrets::{find_value, store_value, token_key, CredentialStore};

/// The version of the stored credential's JSON shape.
pub const CREDENTIAL_VERSION: u32 = 1;

/// A secret string. Its `Debug` form is `[redacted]`; it has no `Display`
/// and no `Serialize`. The only place its value is serialised is the stored
/// credential, through `Credential::to_json`.
#[derive(Clone, PartialEq, Eq)]
pub struct SecretString(Box<str>);

impl SecretString {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into().into_boxed_str())
    }

    /// The secret itself, for the one request or store write that needs it.
    pub fn expose(&self) -> &str {
        &self.0
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl fmt::Debug for SecretString {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(REDACTED)
    }
}

/// Token endpoint responses deserialise straight into `SecretString`, so
/// the value is never held in a plain `String` field that a derived
/// `Debug` could print.
impl<'de> Deserialize<'de> for SecretString {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        String::deserialize(deserializer).map(Self::new)
    }
}

/// An access token for Microsoft Graph. It cannot be passed where a
/// download token is expected.
#[derive(Clone)]
pub struct GraphToken(SecretString);

/// An access token for the Purview eDiscovery download service.
#[derive(Clone)]
pub struct DownloadToken(SecretString);

impl GraphToken {
    pub fn expose(&self) -> &str {
        self.0.expose()
    }
}

impl DownloadToken {
    pub fn expose(&self) -> &str {
        self.0.expose()
    }
}

impl fmt::Debug for GraphToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "GraphToken({REDACTED})")
    }
}

impl fmt::Debug for DownloadToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "DownloadToken({REDACTED})")
    }
}

/// Supplies tokens to the Graph and download clients, which never hold a
/// token string of their own.
#[async_trait]
pub trait TokenProvider: Send + Sync {
    /// A Graph token valid for at least `min_validity`, refreshed first if
    /// it would not be.
    async fn graph(&self, min_validity: Duration) -> Result<GraphToken>;
    /// A download token valid for at least `min_validity`. A credential
    /// with no download token gets one silent attempt to obtain one.
    async fn download(&self, min_validity: Duration) -> Result<DownloadToken>;
    /// Forgets the Graph token, so the next `graph` call refreshes. Used
    /// after a 401.
    async fn invalidate_graph(&self);
}

/// One access token as stored.
#[derive(Clone)]
pub struct AccessToken {
    pub token: SecretString,
    pub expires_at: DateTime<Utc>,
    pub scope: String,
}

impl AccessToken {
    /// From a token endpoint response, expiring `expires_in` seconds after
    /// `now`. A missing scope falls back to the one requested.
    pub fn from_response(response: &TokenResponse, now: DateTime<Utc>, requested: &str) -> Self {
        Self {
            token: response.access_token.clone(),
            expires_at: now + chrono::Duration::seconds(response.lifetime_seconds()),
            scope: if response.scope.trim().is_empty() {
                requested.to_owned()
            } else {
                response.scope.clone()
            },
        }
    }

    fn valid_for(&self, now: DateTime<Utc>, min_validity: Duration) -> bool {
        let margin = chrono::Duration::from_std(min_validity).unwrap_or(chrono::Duration::MAX);
        now.checked_add_signed(margin)
            .is_some_and(|deadline| self.expires_at > deadline)
    }

    pub fn expires_at_text(&self) -> String {
        self.expires_at.to_rfc3339_opts(SecondsFormat::Secs, true)
    }
}

impl fmt::Debug for AccessToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AccessToken")
            .field("token", &self.token)
            .field("expires_at", &self.expires_at)
            .field("scope", &self.scope)
            .finish()
    }
}

/// The credential stored for one account (`docs/SPEC.md` section 5.1):
/// the newest refresh token, the Graph token and, once consent allows, the
/// download token.
#[derive(Clone)]
pub struct Credential {
    pub email: String,
    pub refresh_token: SecretString,
    pub graph: AccessToken,
    pub download: Option<AccessToken>,
}

impl fmt::Debug for Credential {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Credential")
            .field("email", &self.email)
            .field("refresh_token", &self.refresh_token)
            .field("graph", &self.graph)
            .field("download", &self.download)
            .finish()
    }
}

/// The stored JSON shape. It borrows the secrets only for the moment of
/// serialisation.
#[derive(Serialize)]
struct StoredRecord<'a> {
    version: u32,
    email: &'a str,
    refresh_token: &'a str,
    graph: StoredToken<'a>,
    #[serde(skip_serializing_if = "Option::is_none")]
    download: Option<StoredToken<'a>>,
}

#[derive(Serialize)]
struct StoredToken<'a> {
    access_token: &'a str,
    expires_at: String,
    scope: &'a str,
}

#[derive(Deserialize)]
struct LoadedRecord {
    version: u32,
    email: String,
    refresh_token: SecretString,
    graph: LoadedToken,
    #[serde(default)]
    download: Option<LoadedToken>,
}

#[derive(Deserialize)]
struct LoadedToken {
    access_token: SecretString,
    #[serde(default)]
    expires_at: String,
    #[serde(default)]
    scope: String,
}

impl LoadedToken {
    /// An expiry that cannot be read counts as already passed, so the
    /// token is refreshed rather than trusted.
    fn into_access_token(self) -> AccessToken {
        AccessToken {
            token: self.access_token,
            expires_at: DateTime::parse_from_rfc3339(&self.expires_at)
                .map(|value| value.with_timezone(&Utc))
                .unwrap_or(DateTime::<Utc>::UNIX_EPOCH),
            scope: self.scope,
        }
    }
}

impl Credential {
    /// The JSON written to the credential store.
    pub fn to_json(&self) -> Result<String> {
        fn stored(token: &AccessToken) -> StoredToken<'_> {
            StoredToken {
                access_token: token.token.expose(),
                expires_at: token.expires_at_text(),
                scope: &token.scope,
            }
        }
        let record = StoredRecord {
            version: CREDENTIAL_VERSION,
            email: &self.email,
            refresh_token: self.refresh_token.expose(),
            graph: stored(&self.graph),
            download: self.download.as_ref().map(stored),
        };
        Ok(serde_json::to_string(&record)?)
    }

    /// Parses a stored credential and registers its secrets with the
    /// Redactor. A parse error never quotes the stored text.
    pub fn from_json(text: &str, redactor: &Redactor) -> Result<Self> {
        let record: LoadedRecord = serde_json::from_str(text).map_err(|error| {
            PurviewError::message(format!(
                "the stored credential could not be read (line {}, column {}); run 'purview auth \
                 login' again",
                error.line(),
                error.column()
            ))
        })?;
        if record.version != CREDENTIAL_VERSION {
            return Err(PurviewError::message(format!(
                "the stored credential has version {}, which this release cannot read; run \
                 'purview auth login' again",
                record.version
            )));
        }
        let credential = Self {
            email: record.email,
            refresh_token: record.refresh_token,
            graph: record.graph.into_access_token(),
            download: record.download.map(LoadedToken::into_access_token),
        };
        credential.register(redactor);
        if credential.refresh_token.is_empty() {
            return Err(PurviewError::message(
                "the stored credential has no refresh token; run 'purview auth login' again",
            ));
        }
        Ok(credential)
    }

    /// The stored credential for `email`, or `None` when there is none.
    pub fn load(
        store: &dyn CredentialStore,
        email: &str,
        redactor: &Redactor,
    ) -> Result<Option<Self>> {
        match find_value(store, &token_key(email))? {
            Some(text) => Self::from_json(&text, redactor).map(Some),
            None => Ok(None),
        }
    }

    pub fn save(&self, store: &dyn CredentialStore) -> Result<()> {
        store_value(store, &token_key(&self.email), &self.to_json()?)
            .map_err(|error| error.context("storing the credential in the credential store"))
    }

    fn register(&self, redactor: &Redactor) {
        redactor.register(self.refresh_token.expose());
        redactor.register(self.graph.token.expose());
        if let Some(download) = &self.download {
            redactor.register(download.token.expose());
        }
    }

    /// Takes a rotated refresh token, if the response carried one.
    fn rotate(&mut self, response: &TokenResponse) {
        if let Some(refresh_token) = response.refresh_token.as_ref().filter(|t| !t.is_empty()) {
            self.refresh_token = refresh_token.clone();
        }
    }
}

/// What `TokenProvider::refresh_all` obtained.
#[derive(Debug)]
pub struct RefreshReport {
    pub credential: Credential,
    /// The download redemption was refused for want of consent; the
    /// credential then holds no download token.
    pub download_refused: Option<PurviewError>,
}

struct State {
    credential: Credential,
    /// A missing download token gets one silent attempt per process.
    download_attempted: bool,
}

/// The production `TokenProvider`: one account's stored credential,
/// refreshed against the identity platform and written back after every
/// rotation. Concurrent callers share one refresh, because the state lock
/// is held across the request.
pub struct StoredTokenProvider {
    identity: IdentityClient,
    store: Arc<dyn CredentialStore>,
    redactor: Arc<Redactor>,
    clock: Arc<dyn Clock>,
    state: tokio::sync::Mutex<State>,
    /// Store writes that failed after a background refresh. The refreshed
    /// token is still used; the caller may report these.
    warnings: std::sync::Mutex<Vec<String>>,
}

impl fmt::Debug for StoredTokenProvider {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StoredTokenProvider")
            .field("identity", &self.identity)
            .finish_non_exhaustive()
    }
}

impl StoredTokenProvider {
    pub fn new(
        identity: IdentityClient,
        store: Arc<dyn CredentialStore>,
        redactor: Arc<Redactor>,
        clock: Arc<dyn Clock>,
        credential: Credential,
    ) -> Self {
        // A credential built in memory has not been through `from_json`.
        credential.register(&redactor);
        Self {
            identity,
            store,
            redactor,
            clock,
            state: tokio::sync::Mutex::new(State {
                credential,
                download_attempted: false,
            }),
            warnings: std::sync::Mutex::default(),
        }
    }

    /// Store failures from background refreshes, oldest first.
    pub fn take_warnings(&self) -> Vec<String> {
        std::mem::take(
            &mut self
                .warnings
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner()),
        )
    }

    /// `auth refresh`: redeems the refresh token for both resources with
    /// the scopes already stored, then stores the result. A refusal of the
    /// download resource for want of consent is reported, not fatal, and
    /// leaves no download token. Any other failure, including the store
    /// write, is an error.
    pub async fn refresh_all(&self) -> Result<RefreshReport> {
        let mut state = self.state.lock().await;
        self.refresh_graph(&mut state.credential).await?;
        state.credential.save(self.store.as_ref())?;
        let download_refused = match self.refresh_download(&mut state.credential).await {
            Ok(()) => None,
            Err(error) if error.is_consent_required() => {
                state.credential.download = None;
                Some(error)
            }
            Err(error) => return Err(error),
        };
        state.download_attempted = true;
        state.credential.save(self.store.as_ref())?;
        Ok(RefreshReport {
            credential: state.credential.clone(),
            download_refused,
        })
    }

    async fn refresh_graph(&self, credential: &mut Credential) -> Result<()> {
        let scope = auth::graph_refresh_scope(&credential.graph.scope);
        let response = self
            .identity
            .redeem_refresh_token(
                &credential.refresh_token,
                &scope,
                "refreshing the Graph token",
            )
            .await?;
        credential.graph = AccessToken::from_response(&response, self.clock.now(), &scope);
        credential.rotate(&response);
        Ok(())
    }

    async fn refresh_download(&self, credential: &mut Credential) -> Result<()> {
        let scope = auth::download_scope();
        let response = self
            .identity
            .redeem_refresh_token(
                &credential.refresh_token,
                &scope,
                "redeeming the refresh token for the download token",
            )
            .await?;
        credential.download = Some(AccessToken::from_response(
            &response,
            self.clock.now(),
            &scope,
        ));
        credential.rotate(&response);
        Ok(())
    }

    /// Writes the credential after a background refresh. A failure is kept
    /// as a warning: the new tokens are still usable in this process, and
    /// the previous refresh token stays in the store.
    fn persist(&self, credential: &Credential) {
        if let Err(error) = credential.save(self.store.as_ref()) {
            self.warnings
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .push(self.redactor.redact(&error.to_string()));
        }
    }
}

#[async_trait]
impl TokenProvider for StoredTokenProvider {
    async fn graph(&self, min_validity: Duration) -> Result<GraphToken> {
        let mut state = self.state.lock().await;
        if !state
            .credential
            .graph
            .valid_for(self.clock.now(), min_validity)
        {
            self.refresh_graph(&mut state.credential).await?;
            self.persist(&state.credential);
        }
        Ok(GraphToken(state.credential.graph.token.clone()))
    }

    async fn download(&self, min_validity: Duration) -> Result<DownloadToken> {
        let mut state = self.state.lock().await;
        let now = self.clock.now();
        if let Some(download) = &state.credential.download {
            if download.valid_for(now, min_validity) {
                return Ok(DownloadToken(download.token.clone()));
            }
        } else if state.download_attempted {
            return Err(PurviewError::DownloadNotConsented {
                account: state.credential.email.clone(),
            });
        }
        match self.refresh_download(&mut state.credential).await {
            Ok(()) => {}
            // Only a consent refusal becomes `DownloadNotConsented`, and
            // only that refusal stops later attempts in this process; a
            // network failure or a revoked session keeps its own error,
            // whose remedy is different.
            Err(error) if error.is_consent_required() => {
                state.download_attempted = true;
                return Err(PurviewError::DownloadNotConsented {
                    account: state.credential.email.clone(),
                });
            }
            Err(error) => return Err(error),
        }
        self.persist(&state.credential);
        let download = state
            .credential
            .download
            .as_ref()
            .ok_or_else(|| PurviewError::message("the download token was not kept"))?;
        Ok(DownloadToken(download.token.clone()))
    }

    async fn invalidate_graph(&self) {
        let mut state = self.state.lock().await;
        state.credential.graph.expires_at = DateTime::<Utc>::UNIX_EPOCH;
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use serde_json::{json, Value};
    use wiremock::matchers::{body_string_contains, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;
    use crate::env::{test_epoch, ManualClock};
    use crate::secrets::MemoryStore;

    const CLIENT: &str = "00000000-0000-4000-8000-000000000001";
    const TENANT: &str = "00000000-0000-4000-8000-000000000002";
    const EMAIL: &str = "alex@contoso.example";

    fn token(seconds_left: i64, value: &str, scope: &str) -> AccessToken {
        AccessToken {
            token: SecretString::new(value),
            expires_at: test_epoch() + chrono::Duration::seconds(seconds_left),
            scope: scope.into(),
        }
    }

    fn credential(graph_seconds: i64, download: Option<i64>) -> Credential {
        Credential {
            email: EMAIL.into(),
            refresh_token: SecretString::new("canary-refresh-0001"),
            graph: token(
                graph_seconds,
                "canary-graph-0001",
                "eDiscovery.ReadWrite.All openid",
            ),
            download: download.map(|seconds| token(seconds, "canary-download-0001", "d")),
        }
    }

    struct Setup {
        server: MockServer,
        store: Arc<MemoryStore>,
        clock: Arc<ManualClock>,
        redactor: Arc<Redactor>,
        provider: Arc<StoredTokenProvider>,
    }

    async fn setup(credential: Credential) -> Setup {
        let server = MockServer::start().await;
        let store = Arc::new(MemoryStore::default());
        let clock = Arc::new(ManualClock::new(test_epoch()));
        let redactor = Arc::new(Redactor::new());
        let identity = IdentityClient::new(
            url::Url::parse(&server.uri()).unwrap(),
            CLIENT,
            TENANT,
            redactor.clone(),
        )
        .unwrap();
        credential.save(store.as_ref()).unwrap();
        let provider = Arc::new(StoredTokenProvider::new(
            identity,
            store.clone(),
            redactor.clone(),
            clock.clone(),
            credential,
        ));
        Setup {
            server,
            store,
            clock,
            redactor,
            provider,
        }
    }

    fn response(access: &str, refresh: &str) -> ResponseTemplate {
        ResponseTemplate::new(200).set_body_json(json!({
            "access_token": access,
            "refresh_token": refresh,
            "expires_in": 3600,
            "scope": "eDiscovery.ReadWrite.All openid",
        }))
    }

    fn stored(setup: &Setup) -> Value {
        let text = crate::secrets::get_value(setup.store.as_ref(), &token_key(EMAIL)).unwrap();
        serde_json::from_str(&text).unwrap()
    }

    #[test]
    fn debug_of_every_secret_holding_type_is_redacted() {
        let credential = credential(100, Some(100));
        let shown = [
            format!("{:?}", SecretString::new("canary-x")),
            format!("{:?}", GraphToken(SecretString::new("canary-x"))),
            format!("{:?}", DownloadToken(SecretString::new("canary-x"))),
            format!("{:?}", credential.graph),
            format!("{credential:?}"),
        ];
        for text in shown {
            assert!(!text.contains("canary"), "{text}");
            assert!(text.contains("[redacted]"), "{text}");
        }
    }

    #[test]
    fn the_stored_shape_is_version_one_and_round_trips() {
        let original = credential(3600, None);
        let value: Value = serde_json::from_str(&original.to_json().unwrap()).unwrap();
        assert_eq!(
            value,
            json!({
                "version": 1,
                "email": EMAIL,
                "refresh_token": "canary-refresh-0001",
                "graph": {
                    "access_token": "canary-graph-0001",
                    "expires_at": "2026-01-05T10:00:00Z",
                    "scope": "eDiscovery.ReadWrite.All openid",
                },
            })
        );
        let redactor = Redactor::new();
        let loaded = Credential::from_json(&original.to_json().unwrap(), &redactor).unwrap();
        assert_eq!(loaded.graph.expires_at, original.graph.expires_at);
        assert!(loaded.download.is_none());
        assert!(redactor.recognises("canary-refresh-0001"));
        assert!(redactor.recognises("canary-graph-0001"));
    }

    #[test]
    fn an_unreadable_or_newer_credential_is_refused_without_quoting_it() {
        let redactor = Redactor::new();
        let error = Credential::from_json("{\"canary-refresh-0001", &redactor).unwrap_err();
        assert!(!error.to_string().contains("canary"), "{error}");
        let newer = json!({"version": 2, "email": EMAIL, "refresh_token": "r",
                           "graph": {"access_token": "a"}});
        let error = Credential::from_json(&newer.to_string(), &redactor).unwrap_err();
        assert!(error.to_string().contains("version 2"), "{error}");
    }

    #[test]
    fn an_unreadable_expiry_counts_as_expired() {
        let text = json!({"version": 1, "email": EMAIL, "refresh_token": "r",
                          "graph": {"access_token": "a", "expires_at": "soon"}});
        let loaded = Credential::from_json(&text.to_string(), &Redactor::new()).unwrap();
        assert!(!loaded.graph.valid_for(test_epoch(), Duration::ZERO));
    }

    #[tokio::test]
    async fn graph_refreshes_only_inside_the_requested_margin_and_stores_the_rotation() {
        let setup = setup(credential(120, Some(3600))).await;
        Mock::given(method("POST"))
            .and(path(format!("/{TENANT}/oauth2/v2.0/token")))
            .and(body_string_contains("refresh_token=canary-refresh-0001"))
            .respond_with(response("canary-graph-0002", "canary-refresh-0002"))
            .expect(1)
            .mount(&setup.server)
            .await;
        let first = setup.provider.graph(Duration::from_secs(60)).await.unwrap();
        assert_eq!(first.expose(), "canary-graph-0001");
        setup.clock.advance(Duration::from_secs(70));
        let second = setup.provider.graph(Duration::from_secs(60)).await.unwrap();
        assert_eq!(second.expose(), "canary-graph-0002");
        let stored = stored(&setup);
        assert_eq!(stored["refresh_token"], "canary-refresh-0002");
        assert_eq!(stored["graph"]["access_token"], "canary-graph-0002");
        // The superseded values stay registered.
        assert!(setup.redactor.recognises("canary-refresh-0001"));
        assert!(setup.redactor.recognises("canary-graph-0002"));
    }

    #[tokio::test]
    async fn a_pre_post_margin_of_five_minutes_refreshes_a_token_valid_for_four() {
        let setup = setup(credential(360, None)).await;
        Mock::given(method("POST"))
            .respond_with(response("canary-graph-0002", "canary-refresh-0002"))
            .expect(1)
            .mount(&setup.server)
            .await;
        let margin = Duration::from_secs(300);
        assert_eq!(
            setup.provider.graph(margin).await.unwrap().expose(),
            "canary-graph-0001"
        );
        setup.clock.advance(Duration::from_secs(70));
        assert_eq!(
            setup.provider.graph(margin).await.unwrap().expose(),
            "canary-graph-0002"
        );
    }

    #[tokio::test]
    async fn concurrent_callers_share_one_refresh() {
        let setup = setup(credential(0, None)).await;
        Mock::given(method("POST"))
            .respond_with(
                response("canary-graph-0002", "canary-refresh-0002")
                    .set_delay(Duration::from_millis(100)),
            )
            .expect(1)
            .mount(&setup.server)
            .await;
        let calls: Vec<_> = (0..8)
            .map(|_| {
                let provider = setup.provider.clone();
                tokio::spawn(async move { provider.graph(Duration::from_secs(60)).await })
            })
            .collect();
        for call in calls {
            assert_eq!(call.await.unwrap().unwrap().expose(), "canary-graph-0002");
        }
    }

    #[tokio::test]
    async fn invalidating_the_graph_token_forces_one_refresh() {
        let setup = setup(credential(3600, None)).await;
        Mock::given(method("POST"))
            .respond_with(response("canary-graph-0002", "canary-refresh-0002"))
            .expect(1)
            .mount(&setup.server)
            .await;
        setup.provider.invalidate_graph().await;
        let token = setup.provider.graph(Duration::from_secs(60)).await.unwrap();
        assert_eq!(token.expose(), "canary-graph-0002");
        setup.provider.graph(Duration::from_secs(60)).await.unwrap();
    }

    #[tokio::test]
    async fn a_missing_download_token_gets_one_silent_attempt() {
        let setup = setup(credential(3600, None)).await;
        Mock::given(method("POST"))
            .and(body_string_contains(
                "scope=b26e684c-5068-4120-a679-64a5d2c909d9%2F.default",
            ))
            .respond_with(response("canary-download-0002", "canary-refresh-0002"))
            .expect(1)
            .mount(&setup.server)
            .await;
        let margin = Duration::from_secs(300);
        let token = setup.provider.download(margin).await.unwrap();
        assert_eq!(token.expose(), "canary-download-0002");
        setup.provider.download(margin).await.unwrap();
        assert_eq!(
            stored(&setup)["download"]["access_token"],
            "canary-download-0002"
        );
    }

    #[tokio::test]
    async fn a_consent_refusal_is_download_not_consented_and_is_not_retried() {
        let setup = setup(credential(3600, None)).await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(400).set_body_json(json!({
                "error": "invalid_grant",
                "error_description": "AADSTS65001: no consent",
                "error_codes": [65001],
            })))
            .expect(1)
            .mount(&setup.server)
            .await;
        for _ in 0..2 {
            let error = setup
                .provider
                .download(Duration::from_secs(300))
                .await
                .unwrap_err();
            assert_eq!(error.metadata(), ("DownloadNotConsented", 0));
            assert!(
                error.to_string().contains("purview auth refresh"),
                "{error}"
            );
        }
    }

    #[tokio::test]
    async fn another_download_failure_keeps_its_own_error_and_may_be_retried() {
        let setup = setup(credential(3600, None)).await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(400).set_body_json(json!({
                "error": "invalid_grant",
                "error_description": "AADSTS700082: the refresh token has expired",
                "error_codes": [700082],
            })))
            .expect(2)
            .mount(&setup.server)
            .await;
        for _ in 0..2 {
            let error = setup
                .provider
                .download(Duration::from_secs(300))
                .await
                .unwrap_err();
            assert_eq!(error.metadata(), ("invalid_grant", 400));
        }
    }

    #[tokio::test]
    async fn a_store_failure_after_a_background_refresh_is_a_warning() {
        let setup = setup(credential(0, None)).await;
        Mock::given(method("POST"))
            .respond_with(response("canary-graph-0002", "canary-refresh-0002"))
            .mount(&setup.server)
            .await;
        setup.store.fail_writes(true);
        let token = setup.provider.graph(Duration::from_secs(60)).await.unwrap();
        assert_eq!(token.expose(), "canary-graph-0002");
        let warnings = setup.provider.take_warnings();
        assert_eq!(warnings.len(), 1, "{warnings:?}");
        assert!(
            warnings[0].contains("storing the credential"),
            "{warnings:?}"
        );
        assert_eq!(stored(&setup)["refresh_token"], "canary-refresh-0001");
    }
}
