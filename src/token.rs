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
/// the app registration that issued it, the newest refresh token, the
/// Graph token and, once consent allows, the download token. Every
/// redemption uses the registration recorded here, so tokens and
/// registration cannot come apart.
#[derive(Clone)]
pub struct Credential {
    pub email: String,
    pub client_id: String,
    pub tenant_id: String,
    pub refresh_token: SecretString,
    pub graph: AccessToken,
    pub download: Option<AccessToken>,
}

impl fmt::Debug for Credential {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Credential")
            .field("email", &self.email)
            .field("client_id", &self.client_id)
            .field("tenant_id", &self.tenant_id)
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
    client_id: &'a str,
    tenant_id: &'a str,
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
    #[serde(default)]
    client_id: String,
    #[serde(default)]
    tenant_id: String,
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
            client_id: &self.client_id,
            tenant_id: &self.tenant_id,
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
            client_id: record.client_id,
            tenant_id: record.tenant_id,
            refresh_token: record.refresh_token,
            graph: record.graph.into_access_token(),
            // A download entry that cannot be used counts as absent, so the
            // provider obtains a new one rather than sending an empty token.
            download: record
                .download
                .map(LoadedToken::into_access_token)
                .filter(|token| !token.token.is_empty()),
        };
        credential.register(redactor);
        let damaged = |what: &str| {
            PurviewError::message(format!(
                "the stored credential {what}; run 'purview auth login' again"
            ))
        };
        if credential.email.trim().is_empty() {
            return Err(damaged("names no account"));
        }
        // A credential that does not say which registration issued it
        // cannot be redeemed safely, so it is treated as needing sign-in.
        if auth::validate_client_id(&credential.client_id).is_err()
            || auth::validate_tenant_id(&credential.tenant_id).is_err()
        {
            return Err(damaged(
                "does not record the app registration that issued it",
            ));
        }
        if credential.refresh_token.is_empty() {
            return Err(damaged("has no refresh token"));
        }
        if credential.graph.token.is_empty() {
            return Err(damaged("has no Graph token"));
        }
        if !auth::has_graph_permission(&credential.graph.scope) {
            return Err(damaged("records no Graph permission"));
        }
        Ok(credential)
    }

    /// The stored credential for `email`, or `None` when there is none.
    pub fn load(
        store: &dyn CredentialStore,
        email: &str,
        redactor: &Redactor,
    ) -> Result<Option<Self>> {
        let Some(text) = find_value(store, &token_key(email))? else {
            return Ok(None);
        };
        let credential = Self::from_json(&text, redactor)?;
        // `save` writes under the embedded address, so a mismatch would
        // move the credential to another account's key.
        if !credential.email.eq_ignore_ascii_case(email.trim()) {
            return Err(PurviewError::message(format!(
                "the credential stored for {} names another account; run 'purview auth login' \
                 again",
                crate::output::sanitize(email)
            )));
        }
        Ok(Some(credential))
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

struct State {
    credential: Credential,
    /// A consent refusal for the download resource was seen in this
    /// process, and no download token has been stored since; `download`
    /// fails at once.
    download_refused: bool,
    /// A store write failed after it may have taken effect (a macOS label
    /// failure, a Windows clean-up failure), so the store may hold a newer
    /// credential than `credential`. The next call reads it again first.
    reload: bool,
}

/// The production `TokenProvider`: one account's stored credential,
/// refreshed against the identity platform through the app registration
/// recorded in that credential. Every refresh is written to the store
/// before its tokens are used: a refresh works on a copy, and the copy
/// replaces the provider's state only once the store has accepted it. A
/// store failure is the caller's error, and the rotated refresh token is
/// not used. Concurrent callers share one refresh, because the state lock
/// is held across the request.
pub struct StoredTokenProvider {
    identity: IdentityClient,
    store: Arc<dyn CredentialStore>,
    redactor: Arc<Redactor>,
    clock: Arc<dyn Clock>,
    state: tokio::sync::Mutex<State>,
}

impl fmt::Debug for StoredTokenProvider {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StoredTokenProvider")
            .field("identity", &self.identity)
            .finish_non_exhaustive()
    }
}

/// Where a provider sends its redemptions.
#[derive(Debug, Clone)]
pub struct IdentityEndpoint {
    pub base: url::Url,
    pub request_timeout: Duration,
}

impl StoredTokenProvider {
    /// A provider for `credential`, redeeming through the app registration
    /// the credential records, never one from elsewhere.
    pub fn new(
        endpoint: &IdentityEndpoint,
        store: Arc<dyn CredentialStore>,
        redactor: Arc<Redactor>,
        clock: Arc<dyn Clock>,
        credential: Credential,
    ) -> Result<Self> {
        // A credential built in memory has not been through `from_json`.
        credential.register(&redactor);
        let identity = IdentityClient::new(
            endpoint.base.clone(),
            &credential.client_id,
            &credential.tenant_id,
            endpoint.request_timeout,
            redactor.clone(),
        )?;
        Ok(Self {
            identity,
            store,
            redactor,
            clock,
            state: tokio::sync::Mutex::new(State {
                credential,
                download_refused: false,
                reload: false,
            }),
        })
    }

    /// `auth refresh`: redeems the refresh token for both resources with
    /// the scopes already stored, storing each result before the next step.
    /// It returns the stored credential only if both redemptions and both
    /// store writes succeed. A consent refusal for the download resource
    /// keeps the stored Graph rotation, stores the credential without its
    /// download token, and fails with `DownloadNotConsented`.
    pub async fn refresh_all(&self) -> Result<Credential> {
        let mut state = self.state.lock().await;
        self.reload_if_needed(&mut state)?;
        let refreshed = self.refresh_graph(&state.credential).await?;
        self.commit(&mut state, refreshed)?;
        match self.refresh_download(&state.credential).await {
            Ok(refreshed) => {
                self.commit(&mut state, refreshed)?;
                state.download_refused = false;
            }
            Err(error) if error.is_consent_required() => {
                self.refuse_download(&mut state)?;
                return Err(self.not_consented(&state));
            }
            Err(error) => return Err(error),
        }
        Ok(state.credential.clone())
    }

    /// A copy of `credential` with a new Graph token and any rotated
    /// refresh token. A response whose Graph permissions differ from the
    /// stored ones is refused: a refresh must neither widen nor narrow a
    /// session, and the stored scope must describe the token in use. The
    /// error names neither set: a scope string comes from the response and
    /// could carry anything, including a value the Redactor would not see
    /// once escaped.
    async fn refresh_graph(&self, credential: &Credential) -> Result<Credential> {
        let scope = auth::graph_refresh_scope(&credential.graph.scope);
        let response = self
            .identity
            .redeem_refresh_token(
                &credential.refresh_token,
                &scope,
                "refreshing the Graph token",
            )
            .await?;
        let mut refreshed = credential.clone();
        refreshed.graph =
            AccessToken::from_response(&response, self.clock.now(), &credential.graph.scope);
        if auth::graph_permissions(&credential.graph.scope)
            != auth::graph_permissions(&refreshed.graph.scope)
        {
            return Err(PurviewError::message(
                "the Graph refresh returned a different set of permissions from the one stored \
                 for this account, so nothing was stored. The app's permissions or consent \
                 changed; run 'purview auth login' to sign in with the permissions it has now",
            ));
        }
        refreshed.rotate(&response);
        Ok(refreshed)
    }

    async fn refresh_download(&self, credential: &Credential) -> Result<Credential> {
        let scope = auth::download_scope();
        let response = self
            .identity
            .redeem_refresh_token(
                &credential.refresh_token,
                &scope,
                "redeeming the refresh token for the download token",
            )
            .await?;
        let mut refreshed = credential.clone();
        refreshed.download = Some(AccessToken::from_response(
            &response,
            self.clock.now(),
            &scope,
        ));
        refreshed.rotate(&response);
        Ok(refreshed)
    }

    /// Stores `refreshed`, then makes it the provider's state. If the store
    /// reports a failure, the state keeps the previous credential and is
    /// marked for reloading, since a failure can follow a write that took
    /// effect.
    fn commit(&self, state: &mut State, refreshed: Credential) -> Result<()> {
        if let Err(error) = refreshed.save(self.store.as_ref()) {
            state.reload = true;
            return Err(error);
        }
        state.credential = refreshed;
        Ok(())
    }

    /// After a store failure, reads the credential the store holds now, so
    /// the next redemption uses the newest refresh token it has.
    fn reload_if_needed(&self, state: &mut State) -> Result<()> {
        if !state.reload {
            return Ok(());
        }
        let email = state.credential.email.clone();
        let loaded =
            Credential::load(self.store.as_ref(), &email, &self.redactor)?.ok_or_else(|| {
                PurviewError::message(format!(
                    "the credential for {} is no longer in the credential store; run 'purview \
                     auth login' again",
                    crate::output::sanitize(&email)
                ))
            })?;
        if !loaded
            .client_id
            .eq_ignore_ascii_case(&state.credential.client_id)
            || !loaded
                .tenant_id
                .eq_ignore_ascii_case(&state.credential.tenant_id)
        {
            return Err(PurviewError::message(
                "the stored credential now belongs to another app registration; run the \
                 command again",
            ));
        }
        state.credential = loaded;
        state.reload = false;
        Ok(())
    }

    /// After a consent refusal: the download entry is cleared and the
    /// credential stored without it, so no later call in this process, nor
    /// a later process, renews a token the app may no longer get.
    fn refuse_download(&self, state: &mut State) -> Result<()> {
        state.download_refused = true;
        if state.credential.download.is_some() {
            let mut cleared = state.credential.clone();
            cleared.download = None;
            self.commit(state, cleared)?;
        }
        Ok(())
    }

    fn not_consented(&self, state: &State) -> PurviewError {
        PurviewError::DownloadNotConsented {
            account: state.credential.email.clone(),
        }
    }
}

#[async_trait]
impl TokenProvider for StoredTokenProvider {
    async fn graph(&self, min_validity: Duration) -> Result<GraphToken> {
        let mut state = self.state.lock().await;
        self.reload_if_needed(&mut state)?;
        if !state
            .credential
            .graph
            .valid_for(self.clock.now(), min_validity)
        {
            let refreshed = self.refresh_graph(&state.credential).await?;
            self.commit(&mut state, refreshed)?;
        }
        Ok(GraphToken(state.credential.graph.token.clone()))
    }

    /// Only a consent refusal becomes `DownloadNotConsented`, and only that
    /// refusal stops later attempts in this process. A network failure or
    /// a revoked session keeps its own error, whose remedy is different.
    async fn download(&self, min_validity: Duration) -> Result<DownloadToken> {
        let mut state = self.state.lock().await;
        self.reload_if_needed(&mut state)?;
        if state.download_refused {
            return Err(self.not_consented(&state));
        }
        if let Some(download) = &state.credential.download {
            if download.valid_for(self.clock.now(), min_validity) {
                return Ok(DownloadToken(download.token.clone()));
            }
        }
        match self.refresh_download(&state.credential).await {
            Ok(refreshed) => self.commit(&mut state, refreshed)?,
            Err(error) if error.is_consent_required() => {
                self.refuse_download(&mut state)?;
                return Err(self.not_consented(&state));
            }
            Err(error) => return Err(error),
        }
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
            client_id: CLIENT.into(),
            tenant_id: TENANT.into(),
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
        /// The store the provider writes to.
        store: Arc<dyn CredentialStore>,
        /// The memory store underneath it, for failure switches.
        memory: Arc<MemoryStore>,
        clock: Arc<ManualClock>,
        redactor: Arc<Redactor>,
        provider: Arc<StoredTokenProvider>,
    }

    async fn setup(credential: Credential) -> Setup {
        let memory = Arc::new(MemoryStore::default());
        setup_with(credential, memory.clone(), memory).await
    }

    async fn setup_with(
        credential: Credential,
        store: Arc<dyn CredentialStore>,
        memory: Arc<MemoryStore>,
    ) -> Setup {
        let server = MockServer::start().await;
        let clock = Arc::new(ManualClock::new(test_epoch()));
        let redactor = Arc::new(Redactor::new());
        credential.save(store.as_ref()).unwrap();
        let provider = Arc::new(
            StoredTokenProvider::new(
                &IdentityEndpoint {
                    base: url::Url::parse(&server.uri()).unwrap(),
                    request_timeout: Duration::from_secs(5),
                },
                store.clone(),
                redactor.clone(),
                clock.clone(),
                credential,
            )
            .unwrap(),
        );

        Setup {
            server,
            store,
            memory,
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
        assert_eq!(format!("{:?}", SecretString::new("x")), "[redacted]");
        assert_eq!(
            format!("{:?}", GraphToken(SecretString::new("x"))),
            "GraphToken([redacted])"
        );
        assert_eq!(
            format!("{:?}", DownloadToken(SecretString::new("x"))),
            "DownloadToken([redacted])"
        );
        assert_eq!(
            format!("{:?}", credential.graph),
            "AccessToken { token: [redacted], expires_at: 2026-01-05T09:01:40Z, scope: \
             \"eDiscovery.ReadWrite.All openid\" }"
        );
        let shown = format!("{credential:?}");
        assert!(
            shown.starts_with(&format!(
                "Credential {{ email: \"{EMAIL}\", client_id: \"{CLIENT}\", tenant_id: \
                 \"{TENANT}\", refresh_token: [redacted], graph: AccessToken {{ token: \
                 [redacted],"
            )),
            "{shown}"
        );
        assert!(
            shown.contains("download: Some(AccessToken { token: [redacted],"),
            "{shown}"
        );
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
                "client_id": CLIENT,
                "tenant_id": TENANT,
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
        let text = json!({"version": 1, "email": EMAIL, "client_id": CLIENT, "tenant_id": TENANT,
                          "refresh_token": "r",
                          "graph": {"access_token": "a", "expires_at": "soon",
                                    "scope": "eDiscovery.ReadWrite.All"}});
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
    async fn a_store_failure_after_a_refresh_is_an_error_and_the_rotation_is_not_used() {
        let setup = setup(credential(0, None)).await;
        Mock::given(method("POST"))
            .and(body_string_contains("refresh_token=canary-refresh-0001"))
            .respond_with(response("canary-graph-0002", "canary-refresh-0002"))
            .expect(2)
            .mount(&setup.server)
            .await;
        setup.memory.fail_writes(true);
        let error = setup
            .provider
            .graph(Duration::from_secs(60))
            .await
            .unwrap_err();
        assert!(
            error.to_string().contains("storing the credential"),
            "{error}"
        );
        // The next attempt still redeems the stored refresh token, not the
        // rotated one the store never accepted.
        setup.memory.fail_writes(false);
        let token = setup.provider.graph(Duration::from_secs(60)).await.unwrap();
        assert_eq!(token.expose(), "canary-graph-0002");
        assert_eq!(stored(&setup)["refresh_token"], "canary-refresh-0002");
    }

    #[tokio::test]
    async fn refresh_all_on_a_consent_refusal_keeps_the_graph_rotation_and_fails() {
        let setup = setup(credential(3600, Some(3600))).await;
        Mock::given(method("POST"))
            .and(body_string_contains("refresh_token=canary-refresh-0001"))
            .respond_with(response("canary-graph-0002", "canary-refresh-0002"))
            .expect(1)
            .mount(&setup.server)
            .await;
        Mock::given(method("POST"))
            .and(body_string_contains("refresh_token=canary-refresh-0002"))
            .respond_with(ResponseTemplate::new(400).set_body_json(json!({
                "error": "invalid_grant",
                "error_codes": [65001],
            })))
            .expect(1)
            .mount(&setup.server)
            .await;
        let error = setup.provider.refresh_all().await.unwrap_err();
        assert_eq!(error.metadata(), ("DownloadNotConsented", 0));
        let stored = stored(&setup);
        assert_eq!(stored["refresh_token"], "canary-refresh-0002");
        assert_eq!(stored["graph"]["access_token"], "canary-graph-0002");
        assert!(stored.get("download").is_none(), "{stored}");
        // The refusal holds for the rest of the process.
        let error = setup
            .provider
            .download(Duration::from_secs(300))
            .await
            .unwrap_err();
        assert_eq!(error.metadata(), ("DownloadNotConsented", 0));
    }

    #[tokio::test]
    async fn a_consent_refusal_renewing_an_expired_download_token_clears_it() {
        let setup = setup(credential(3600, Some(10))).await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(400).set_body_json(json!({
                "error": "invalid_grant",
                "error_description": "AADSTS65001: consent was withdrawn",
            })))
            .expect(1)
            .mount(&setup.server)
            .await;
        for _ in 0..3 {
            let error = setup
                .provider
                .download(Duration::from_secs(300))
                .await
                .unwrap_err();
            assert_eq!(error.metadata(), ("DownloadNotConsented", 0));
        }
        assert!(stored(&setup).get("download").is_none());
    }

    #[tokio::test]
    async fn a_refresh_that_changes_the_graph_permissions_is_refused() {
        let setup = setup(credential(0, None)).await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "access_token": "canary-graph-0002",
                "refresh_token": "canary-refresh-0002",
                "expires_in": 3600,
                "scope": "eDiscovery.Read.All openid profile",
            })))
            .mount(&setup.server)
            .await;
        let error = setup
            .provider
            .graph(Duration::from_secs(60))
            .await
            .unwrap_err();
        let message = error.to_string();
        assert!(
            message.contains("different set of permissions"),
            "{message}"
        );
        assert!(
            !message.to_ascii_lowercase().contains("read.all"),
            "{message}"
        );
        assert!(message.contains("purview auth login"), "{message}");
        assert_eq!(stored(&setup)["refresh_token"], "canary-refresh-0001");
        assert_eq!(stored(&setup)["graph"]["access_token"], "canary-graph-0001");
    }

    #[tokio::test]
    async fn a_response_without_a_scope_keeps_the_stored_permissions() {
        let setup = setup(credential(0, None)).await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "access_token": "canary-graph-0002",
                "expires_in": 3600,
            })))
            .mount(&setup.server)
            .await;
        setup.provider.graph(Duration::from_secs(60)).await.unwrap();
        let stored = stored(&setup);
        assert_eq!(stored["graph"]["scope"], "eDiscovery.ReadWrite.All openid");
        // No rotation came back, so the stored refresh token stays.
        assert_eq!(stored["refresh_token"], "canary-refresh-0001");
    }

    #[test]
    fn a_loaded_credential_must_be_usable_and_belong_to_its_key() {
        let redactor = Redactor::new();
        let base = json!({"version": 1, "email": EMAIL, "client_id": CLIENT, "tenant_id": TENANT,
                          "refresh_token": "r",
                          "graph": {"access_token": "a", "expires_at": "2026-01-05T10:00:00Z",
                                    "scope": "eDiscovery.ReadWrite.All"}});
        for (pointer, value, expected) in [
            ("/graph/access_token", json!(""), "no Graph token"),
            (
                "/graph/scope",
                json!("openid offline_access"),
                "no Graph permission",
            ),
            ("/email", json!(" "), "names no account"),
            (
                "/client_id",
                json!(""),
                "does not record the app registration",
            ),
            (
                "/tenant_id",
                json!("organizations"),
                "does not record the app registration",
            ),
            (
                "/graph/scope",
                json!("https://api.contoso.example/Mail.Read openid"),
                "no Graph permission",
            ),
        ] {
            let mut damaged = base.clone();
            *damaged.pointer_mut(pointer).unwrap() = value;
            let error = Credential::from_json(&damaged.to_string(), &redactor).unwrap_err();
            assert!(error.to_string().contains(expected), "{pointer}: {error}");
        }
        let mut with_empty_download = base.clone();
        with_empty_download["download"] = json!({"access_token": "", "scope": "d"});
        let loaded = Credential::from_json(&with_empty_download.to_string(), &redactor).unwrap();
        assert!(loaded.download.is_none());

        let store = MemoryStore::default();
        crate::secrets::store_value(&store, &token_key("sam@contoso.example"), &base.to_string())
            .unwrap();
        let error = Credential::load(&store, "sam@contoso.example", &redactor).unwrap_err();
        assert!(
            error.to_string().contains("names another account"),
            "{error}"
        );
    }

    #[test]
    fn a_credential_without_its_registration_needs_sign_in() {
        let text = json!({"version": 1, "email": EMAIL, "refresh_token": "r",
                          "graph": {"access_token": "a", "scope": "eDiscovery.ReadWrite.All"}});
        let error = Credential::from_json(&text.to_string(), &Redactor::new()).unwrap_err();
        let message = error.to_string();
        assert!(
            message.contains("does not record the app registration"),
            "{message}"
        );
        assert!(message.contains("purview auth login"), "{message}");
    }

    /// Writes the value, then reports a failure once, as a macOS label
    /// failure or a Windows clean-up failure does after the item is live.
    struct CommitsThenFails {
        inner: Arc<MemoryStore>,
        fail_once: std::sync::atomic::AtomicBool,
    }

    impl CredentialStore for CommitsThenFails {
        fn get_password(&self, key: &str) -> Result<Option<String>> {
            self.inner.get_password(key)
        }
        fn set_password(&self, key: &str, value: &str) -> Result<()> {
            self.inner.set_password(key, value)?;
            if self
                .fail_once
                .swap(false, std::sync::atomic::Ordering::SeqCst)
            {
                return Err(PurviewError::message("labelling the item failed"));
            }
            Ok(())
        }
        fn get_secret(&self, key: &str) -> Result<Option<Vec<u8>>> {
            self.inner.get_secret(key)
        }
        fn set_secret(&self, key: &str, value: &[u8]) -> Result<()> {
            self.inner.set_secret(key, value)
        }
        fn delete(&self, key: &str) -> Result<bool> {
            self.inner.delete(key)
        }
    }

    #[tokio::test]
    async fn after_a_store_error_that_committed_the_next_call_reloads_the_store() {
        let memory = Arc::new(MemoryStore::default());
        let store = Arc::new(CommitsThenFails {
            inner: memory.clone(),
            fail_once: std::sync::atomic::AtomicBool::new(false),
        });
        let setup = setup_with(credential(0, None), store.clone(), memory).await;
        store
            .fail_once
            .store(true, std::sync::atomic::Ordering::SeqCst);
        Mock::given(method("POST"))
            .and(body_string_contains("refresh_token=canary-refresh-0001"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "access_token": "canary-graph-0002",
                "refresh_token": "canary-refresh-0002",
                "expires_in": 1,
                "scope": "eDiscovery.ReadWrite.All openid",
            })))
            .expect(1)
            .mount(&setup.server)
            .await;
        Mock::given(method("POST"))
            .and(body_string_contains("refresh_token=canary-refresh-0002"))
            .respond_with(response("canary-graph-0003", "canary-refresh-0003"))
            .expect(1)
            .mount(&setup.server)
            .await;
        let error = setup
            .provider
            .graph(Duration::from_secs(60))
            .await
            .unwrap_err();
        assert!(
            error.to_string().contains("labelling the item failed"),
            "{error}"
        );
        // The store took the rotation, so the next redemption must use it.
        let token = setup.provider.graph(Duration::from_secs(60)).await.unwrap();
        assert_eq!(token.expose(), "canary-graph-0003");
        assert_eq!(stored(&setup)["refresh_token"], "canary-refresh-0003");
    }

    #[tokio::test]
    async fn a_successful_refresh_after_a_refusal_lets_downloads_through_again() {
        let setup = setup(credential(3600, None)).await;
        let refusal = Mock::given(method("POST"))
            .and(body_string_contains("b26e684c"))
            .respond_with(ResponseTemplate::new(400).set_body_json(json!({
                "error": "invalid_grant",
                "error_codes": [65001],
            })))
            .up_to_n_times(1)
            .with_priority(1);
        refusal.mount(&setup.server).await;
        Mock::given(method("POST"))
            .and(body_string_contains("b26e684c"))
            .respond_with(response("canary-download-0002", "canary-refresh-0003"))
            .with_priority(2)
            .mount(&setup.server)
            .await;
        Mock::given(method("POST"))
            .and(body_string_contains("graph.microsoft.com"))
            .respond_with(response("canary-graph-0002", "canary-refresh-0002"))
            .mount(&setup.server)
            .await;
        let margin = Duration::from_secs(300);
        let error = setup.provider.download(margin).await.unwrap_err();
        assert_eq!(error.metadata(), ("DownloadNotConsented", 0));
        // Consent is granted, and an explicit refresh succeeds.
        setup.provider.refresh_all().await.unwrap();
        let token = setup.provider.download(margin).await.unwrap();
        assert_eq!(token.expose(), "canary-download-0002");
    }
}
