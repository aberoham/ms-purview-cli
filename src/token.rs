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
use crate::secrets::{
    entry_exists, find_value, store_value, token_key, AccountLocks, CredentialStore,
};

/// What the entry under an account key says about its owner.
#[derive(Clone, PartialEq, Eq)]
pub enum StoredPrincipal {
    /// Nothing is stored under the key.
    Absent,
    /// The ids the entry records; either may be empty.
    Recorded { tid: String, oid: String },
    /// Something is stored, but it cannot be read as a credential.
    Unreadable,
}

/// Names the case and whether each id is recorded, never the ids: a
/// damaged entry could hold anything in them, a token included.
impl fmt::Debug for StoredPrincipal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Absent => formatter.write_str("Absent"),
            Self::Unreadable => formatter.write_str("Unreadable"),
            Self::Recorded { tid, oid } => formatter
                .debug_struct("Recorded")
                .field("tid_recorded", &!tid.is_empty())
                .field("oid_recorded", &!oid.is_empty())
                .finish(),
        }
    }
}

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
    /// For a `TokenProvider` other than `StoredTokenProvider`, such as a
    /// test's.
    pub fn new(token: SecretString) -> Self {
        Self(token)
    }

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
    /// What the provider did since the last call, one line each, for
    /// `--verbose`: each redemption, the scope it returned and whether the
    /// refresh token rotated. Never a token.
    fn take_notes(&self) -> Vec<String> {
        Vec::new()
    }
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
/// the principal it belongs to, the app registration that issued it, the
/// newest refresh token, the Graph token and, once consent allows, the
/// download token. Every redemption uses the registration recorded here,
/// so tokens and registration cannot come apart, and the principal binds
/// the account key to one identity.
#[derive(Clone)]
pub struct Credential {
    pub email: String,
    /// The `tid` and `oid` claims of the identity the tokens belong to.
    pub tid: String,
    pub oid: String,
    pub client_id: String,
    pub tenant_id: String,
    pub refresh_token: SecretString,
    pub graph: AccessToken,
    pub download: Option<AccessToken>,
    /// How the account signed in, which decides whether it may write. The
    /// token's scope cannot: the identity platform grants every consented
    /// permission whatever was asked for (Observed, PR 1.4). `None` for a
    /// credential stored before this was recorded, which may not write.
    pub access: Option<Access>,
    /// A random id made at sign-in, which refreshes keep. A refresh stores
    /// its tokens only over the same sign-in, so a session that another
    /// `auth login` replaced while it ran (with another access, scope or
    /// registration) cannot write its older credential back. `None` for a
    /// credential stored before this was recorded.
    pub sign_in: Option<String>,
}

/// Whether a sign-in may write to Purview: `auth login` without or with
/// `--read-only`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Access {
    ReadWrite,
    ReadOnly,
}

impl Access {
    pub fn from_read_only(read_only: bool) -> Self {
        if read_only {
            Self::ReadOnly
        } else {
            Self::ReadWrite
        }
    }

    /// The stored form.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ReadWrite => "read-write",
            Self::ReadOnly => "read-only",
        }
    }

    /// The stored form read back; anything else is unrecorded.
    fn parse(text: &str) -> Option<Self> {
        match text {
            "read-write" => Some(Self::ReadWrite),
            "read-only" => Some(Self::ReadOnly),
            _ => None,
        }
    }
}

impl fmt::Debug for Credential {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Credential")
            .field("email", &self.email)
            // The principal ids are left out: a damaged entry could hold
            // anything in them, a token included.
            .field("client_id", &self.client_id)
            .field("tenant_id", &self.tenant_id)
            .field("refresh_token", &self.refresh_token)
            .field("graph", &self.graph)
            .field("download", &self.download)
            .field("access", &self.access)
            .finish()
    }
}

/// The stored JSON shape. It borrows the secrets only for the moment of
/// serialisation.
#[derive(Serialize)]
struct StoredRecord<'a> {
    version: u32,
    email: &'a str,
    tid: &'a str,
    oid: &'a str,
    client_id: &'a str,
    tenant_id: &'a str,
    refresh_token: &'a str,
    graph: StoredToken<'a>,
    #[serde(skip_serializing_if = "Option::is_none")]
    download: Option<StoredToken<'a>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    access: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    sign_in: Option<&'a str>,
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
    tid: String,
    #[serde(default)]
    oid: String,
    #[serde(default)]
    client_id: String,
    #[serde(default)]
    tenant_id: String,
    refresh_token: SecretString,
    graph: LoadedToken,
    #[serde(default)]
    download: Option<LoadedToken>,
    /// Not required, and read leniently: a credential without it, or with
    /// a value this release does not know, can read but not write.
    #[serde(default)]
    access: Option<serde_json::Value>,
    #[serde(default)]
    sign_in: Option<serde_json::Value>,
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
    /// Whether `tid` and `oid` name the identity this credential belongs
    /// to, ignoring case.
    pub fn belongs_to(&self, tid: &str, oid: &str) -> bool {
        self.tid.eq_ignore_ascii_case(tid.trim()) && self.oid.eq_ignore_ascii_case(oid.trim())
    }

    /// Whether `other` belongs to the same principal through the same app
    /// registration.
    pub fn same_owner(&self, other: &Credential) -> bool {
        self.belongs_to(&other.tid, &other.oid)
            && self.client_id.eq_ignore_ascii_case(&other.client_id)
            && self.tenant_id.eq_ignore_ascii_case(&other.tenant_id)
    }

    /// What is stored under `email`'s key says about its owner, read
    /// leniently, so that a credential this release cannot use still says
    /// whom it belonged to. Existence is checked raw first, so a damaged
    /// entry, or chunks without a header, count as stored. Token fields
    /// are registered with the Redactor as they are seen.
    pub fn stored_principal(
        store: &dyn CredentialStore,
        email: &str,
        redactor: &Redactor,
    ) -> Result<StoredPrincipal> {
        let key = token_key(email);
        if !entry_exists(store, &key)? {
            return Ok(StoredPrincipal::Absent);
        }
        let Ok(Some(text)) = find_value(store, &key) else {
            return Ok(StoredPrincipal::Unreadable);
        };
        let Ok(value) = serde_json::from_str::<serde_json::Value>(&text) else {
            return Ok(StoredPrincipal::Unreadable);
        };
        for pointer in [
            "/refresh_token",
            "/graph/access_token",
            "/download/access_token",
        ] {
            if let Some(secret) = value.pointer(pointer).and_then(serde_json::Value::as_str) {
                redactor.register(secret);
            }
        }
        let text_at = |name: &str| {
            value
                .get(name)
                .and_then(serde_json::Value::as_str)
                .unwrap_or_default()
                .trim()
                .to_owned()
        };
        Ok(StoredPrincipal::Recorded {
            tid: text_at("tid"),
            oid: text_at("oid"),
        })
    }

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
            tid: &self.tid,
            oid: &self.oid,
            client_id: &self.client_id,
            tenant_id: &self.tenant_id,
            refresh_token: self.refresh_token.expose(),
            graph: stored(&self.graph),
            download: self.download.as_ref().map(stored),
            access: self.access.map(Access::as_str),
            sign_in: self.sign_in.as_deref(),
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
            tid: record.tid,
            oid: record.oid,
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
            access: record
                .access
                .as_ref()
                .and_then(serde_json::Value::as_str)
                .and_then(Access::parse),
            sign_in: record
                .sign_in
                .as_ref()
                .and_then(serde_json::Value::as_str)
                .filter(|id| !id.trim().is_empty())
                .map(str::to_owned),
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
        // Without the principal, the key cannot be tied to one identity.
        if credential.tid.trim().is_empty() || credential.oid.trim().is_empty() {
            return Err(damaged("does not record the identity it belongs to"));
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

    /// `save` for a sign-in the ownership check has authorised to replace
    /// a damaged entry under the key.
    pub fn save_repairing(&self, store: &dyn CredentialStore) -> Result<()> {
        crate::secrets::store_value_repairing(store, &token_key(&self.email), &self.to_json()?)
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

/// What a store write that reported a failure was doing. The write may
/// still have taken effect (a macOS label failure or a Windows clean-up
/// failure comes after the item is live), unlike a write the store refused
/// outright; the next call reads the store again and reconciles against
/// this.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WriteKind {
    /// A refreshed Graph token and any rotated refresh token.
    Graph,
    /// A newly granted download token.
    StoreDownload,
    /// Removing a download token after a consent refusal.
    ClearDownload,
}

struct Uncertain {
    kind: WriteKind,
    written: Credential,
}

struct State {
    credential: Credential,
    /// A consent refusal for the download resource was seen in this
    /// process, and no download token has been stored since; `download`
    /// fails at once.
    download_refused: bool,
    /// A write that reported a failure, which the next call reconciles.
    uncertain: Option<Uncertain>,
    /// The Graph token `invalidate_graph` was called for, until a refresh
    /// is stored. A reload that reads that same token back keeps it
    /// expired; a different token was stored after it and is left alone.
    invalidated_graph: Option<SecretString>,
}

/// The production `TokenProvider`: one account's stored credential,
/// refreshed against the identity platform through the app registration
/// recorded in that credential. Every refresh is written to the store
/// before its tokens are used: a refresh works on a copy, and the copy
/// replaces the provider's state only once the store has accepted it.
/// Before each write, under the account lock, the provider checks that the
/// key still holds a credential of the same principal and registration, so
/// a concurrent sign-in by someone else is never overwritten. A failed
/// write is the caller's error, and its rotated refresh token is not used.
/// Concurrent callers in one process share one refresh, because the state
/// lock is held across the request.
pub struct StoredTokenProvider {
    identity: IdentityClient,
    store: Arc<dyn CredentialStore>,
    redactor: Arc<Redactor>,
    clock: Arc<dyn Clock>,
    account_locks: Option<AccountLocks>,
    state: tokio::sync::Mutex<State>,
    notes: std::sync::Mutex<Vec<String>>,
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
            account_locks: None,
            state: tokio::sync::Mutex::new(State {
                credential,
                download_refused: false,
                uncertain: None,
                invalidated_graph: None,
            }),
            notes: std::sync::Mutex::default(),
        })
    }

    /// The credential in use now, after any refresh this provider made.
    pub async fn credential(&self) -> Credential {
        self.state.lock().await.credential.clone()
    }

    /// Records one redemption for `take_notes`. The scope is the
    /// response's own, or "none" when it sent none; it is not a secret.
    fn note(&self, operation: &str, response: &TokenResponse, previous: &SecretString) {
        let rotated = response
            .refresh_token
            .as_ref()
            .is_some_and(|token| !token.is_empty() && token != previous);
        let scope = response.scope.trim();
        self.notes
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .push(format!(
                "{operation}: returned scope {}; refresh token rotated: {}",
                if scope.is_empty() { "none" } else { scope },
                if rotated { "yes" } else { "no" }
            ));
    }

    /// Takes the account lock around each store write.
    pub fn with_account_locks(mut self, locks: Option<AccountLocks>) -> Self {
        self.account_locks = locks;
        self
    }

    /// `auth refresh`: redeems the refresh token for both resources with
    /// the scopes already stored, storing each result before the next step.
    /// It returns the stored credential only if both redemptions and both
    /// store writes succeed. A consent refusal for the download resource
    /// keeps the stored Graph rotation, stores the credential without its
    /// download token, and fails with `DownloadNotConsented`.
    pub async fn refresh_all(&self) -> Result<Credential> {
        let mut state = self.state.lock().await;
        self.reconcile(&mut state)?;
        let refreshed = self.refresh_graph(&state.credential).await?;
        self.commit(&mut state, refreshed, WriteKind::Graph).await?;
        match self.refresh_download(&state.credential).await {
            Ok(refreshed) => {
                self.commit(&mut state, refreshed, WriteKind::StoreDownload)
                    .await?;
            }
            Err(error) if error.is_consent_required() => {
                self.refuse_download(&mut state).await?;
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
        self.note(
            "refreshed the Graph token",
            &response,
            &credential.refresh_token,
        );
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
        self.note(
            "redeemed the download token",
            &response,
            &credential.refresh_token,
        );
        let mut refreshed = credential.clone();
        refreshed.download = Some(AccessToken::from_response(
            &response,
            self.clock.now(),
            &scope,
        ));
        refreshed.rotate(&response);
        Ok(refreshed)
    }

    /// Stores `refreshed`, then makes it the provider's state. Under the
    /// account lock, the key must still hold this principal's credential
    /// through this registration. A write the store refuses leaves the
    /// state as it was; a failure reported after the write may have taken
    /// effect is recorded, and the next call reconciles it.
    async fn commit(
        &self,
        state: &mut State,
        refreshed: Credential,
        kind: WriteKind,
    ) -> Result<()> {
        let _lock = match &self.account_locks {
            Some(locks) => Some(locks.lock(&refreshed.email).await?),
            None => None,
        };
        self.verify_owner(&state.credential)?;
        if let Err(error) = refreshed.save(self.store.as_ref()) {
            state.uncertain = Some(Uncertain {
                kind,
                written: refreshed,
            });
            return Err(error);
        }
        if kind == WriteKind::Graph {
            state.invalidated_graph = None;
        }
        if kind == WriteKind::StoreDownload {
            state.download_refused = false;
        }
        state.credential = refreshed;
        Ok(())
    }

    /// Refuses to write over the key unless it holds a credential of the
    /// same principal through the same registration as `expected`, from the
    /// same sign-in: a sign-in made while this provider ran (`--read-only`,
    /// or with other permissions) must not be undone by an older session's
    /// refresh.
    fn verify_owner(&self, expected: &Credential) -> Result<()> {
        let stored = Credential::load(self.store.as_ref(), &expected.email, &self.redactor)
            .ok()
            .flatten();
        match stored {
            Some(stored) if stored.same_owner(expected) && stored.sign_in == expected.sign_in => {
                Ok(())
            }
            _ => Err(PurviewError::message(format!(
                "the credential for {} was replaced or removed by another command while this \
                 one ran, so nothing was stored; run the command again",
                crate::output::sanitize(&expected.email)
            ))),
        }
    }

    /// After a write that reported a failure, reads the credential the
    /// store holds now, so the next redemption uses the newest refresh
    /// token it has, and reconciles against what that write was doing.
    fn reconcile(&self, state: &mut State) -> Result<()> {
        // The pending write stays recorded until the store has been read,
        // checked and reconciled, so a failed read is retried next time
        // rather than leaving the cached tokens in use.
        let Some(uncertain) = state.uncertain.as_ref() else {
            return Ok(());
        };
        let kind = uncertain.kind;
        let written_download = uncertain.written.download.as_ref().map(|t| t.token.clone());
        let email = state.credential.email.clone();
        let loaded =
            Credential::load(self.store.as_ref(), &email, &self.redactor)?.ok_or_else(|| {
                PurviewError::message(format!(
                    "the credential for {} is no longer in the credential store; run 'purview \
                     auth login' again",
                    crate::output::sanitize(&email)
                ))
            })?;
        // The same person signed in again while this command ran, through
        // any registration: that sign-in stands, and this command's session
        // does not. Checked before the registration, so the advice does not
        // remove the newer sign-in.
        if loaded.belongs_to(&state.credential.tid, &state.credential.oid)
            && loaded.sign_in != state.credential.sign_in
        {
            return Err(PurviewError::message(
                "this account signed in again while the command ran, so it stopped; nothing \
                 was sent. Run the command again",
            ));
        }
        if !loaded.same_owner(&state.credential) {
            // Refused before any redemption with someone else's tokens.
            return Err(PurviewError::message(
                "the stored credential now belongs to another app registration or identity; \
                 nothing was sent. Run 'purview auth logout' for this account, then sign in \
                 again",
            ));
        }
        let mut loaded = loaded;
        match kind {
            WriteKind::StoreDownload => {
                if loaded.download.as_ref().map(|token| &token.token) == written_download.as_ref() {
                    state.download_refused = false;
                }
            }
            WriteKind::ClearDownload => {
                // The refusal stands whether or not the removal landed; a
                // token it did not remove is not used.
                loaded.download = None;
            }
            WriteKind::Graph => {}
        }
        if let Some(invalidated) = &state.invalidated_graph {
            if &loaded.graph.token == invalidated {
                loaded.graph.expires_at = DateTime::<Utc>::UNIX_EPOCH;
            } else {
                state.invalidated_graph = None;
            }
        }
        state.credential = loaded;
        state.uncertain = None;
        Ok(())
    }

    /// After a consent refusal: the download entry is cleared and the
    /// credential stored without it, so no later call in this process, nor
    /// a later process, renews a token the app may no longer get.
    async fn refuse_download(&self, state: &mut State) -> Result<()> {
        state.download_refused = true;
        if state.credential.download.is_some() {
            let mut cleared = state.credential.clone();
            cleared.download = None;
            self.commit(state, cleared, WriteKind::ClearDownload)
                .await?;
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
        self.reconcile(&mut state)?;
        if !state
            .credential
            .graph
            .valid_for(self.clock.now(), min_validity)
        {
            let refreshed = self.refresh_graph(&state.credential).await?;
            self.commit(&mut state, refreshed, WriteKind::Graph).await?;
            // The new token is stored either way, but a request that needs
            // it to last longer than the identity platform gave is not sent.
            if !state
                .credential
                .graph
                .valid_for(self.clock.now(), min_validity)
            {
                return Err(PurviewError::message(format!(
                    "the refreshed Graph token is valid for less than the {} seconds this \
                     request needs, so it was not sent; try again later",
                    min_validity.as_secs()
                )));
            }
        }
        Ok(GraphToken(state.credential.graph.token.clone()))
    }

    /// Only a consent refusal becomes `DownloadNotConsented`, and only that
    /// refusal stops later attempts in this process. A network failure or
    /// a revoked session keeps its own error, whose remedy is different.
    async fn download(&self, min_validity: Duration) -> Result<DownloadToken> {
        let mut state = self.state.lock().await;
        self.reconcile(&mut state)?;
        if state.download_refused {
            return Err(self.not_consented(&state));
        }
        if let Some(download) = &state.credential.download {
            if download.valid_for(self.clock.now(), min_validity) {
                return Ok(DownloadToken(download.token.clone()));
            }
        }
        match self.refresh_download(&state.credential).await {
            Ok(refreshed) => {
                self.commit(&mut state, refreshed, WriteKind::StoreDownload)
                    .await?
            }
            Err(error) if error.is_consent_required() => {
                self.refuse_download(&mut state).await?;
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
        state.invalidated_graph = Some(state.credential.graph.token.clone());
        state.credential.graph.expires_at = DateTime::<Utc>::UNIX_EPOCH;
    }

    fn take_notes(&self) -> Vec<String> {
        std::mem::take(
            &mut *self
                .notes
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner()),
        )
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
    const OID: &str = "00000000-0000-4000-8000-000000000011";

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
            tid: TENANT.into(),
            oid: OID.into(),
            client_id: CLIENT.into(),
            tenant_id: TENANT.into(),
            refresh_token: SecretString::new("canary-refresh-0001"),
            graph: token(
                graph_seconds,
                "canary-graph-0001",
                "eDiscovery.ReadWrite.All openid",
            ),
            download: download.map(|seconds| token(seconds, "canary-download-0001", "d")),
            access: Some(Access::ReadWrite),
            sign_in: Some("sign-in-0001".into()),
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
        // Canaries in the principal ids, which a damaged entry could hold.
        let mut credential = credential;
        credential.tid = "canary-tid-0001".into();
        credential.oid = "canary-oid-0001".into();
        assert_eq!(
            format!("{credential:?}"),
            format!(
                "Credential {{ email: \"{EMAIL}\", client_id: \"{CLIENT}\", tenant_id: \
                 \"{TENANT}\", refresh_token: [redacted], graph: AccessToken {{ token: \
                 [redacted], expires_at: 2026-01-05T09:01:40Z, scope: \"eDiscovery.ReadWrite.All \
                 openid\" }}, download: Some(AccessToken {{ token: [redacted], expires_at: \
                 2026-01-05T09:01:40Z, scope: \"d\" }}), access: Some(ReadWrite) }}"
            )
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
                "tid": TENANT,
                "oid": OID,
                "client_id": CLIENT,
                "tenant_id": TENANT,
                "refresh_token": "canary-refresh-0001",
                "graph": {
                    "access_token": "canary-graph-0001",
                    "expires_at": "2026-01-05T10:00:00Z",
                    "scope": "eDiscovery.ReadWrite.All openid",
                },
                "access": "read-write",
                "sign_in": "sign-in-0001",
            })
        );
        let redactor = Redactor::new();
        let loaded = Credential::from_json(&original.to_json().unwrap(), &redactor).unwrap();
        assert_eq!(loaded.access, Some(Access::ReadWrite));
        assert_eq!(loaded.graph.expires_at, original.graph.expires_at);
        assert!(loaded.download.is_none());
        assert!(redactor.recognises("canary-refresh-0001"));
        assert!(redactor.recognises("canary-graph-0001"));
    }

    #[test]
    fn access_is_read_back_and_anything_unknown_is_unrecorded() {
        let redactor = Redactor::new();
        let stored = |access: Option<Value>| {
            let mut value: Value =
                serde_json::from_str(&credential(3600, None).to_json().unwrap()).unwrap();
            match access {
                Some(access) => value["access"] = access,
                None => {
                    value.as_object_mut().unwrap().remove("access");
                }
            }
            Credential::from_json(&value.to_string(), &redactor)
                .unwrap()
                .access
        };
        assert_eq!(stored(Some(json!("read-write"))), Some(Access::ReadWrite));
        assert_eq!(stored(Some(json!("read-only"))), Some(Access::ReadOnly));
        for unrecorded in [
            None,
            Some(json!("Read-Write")),
            Some(json!(true)),
            Some(Value::Null),
        ] {
            assert_eq!(stored(unrecorded.clone()), None, "{unrecorded:?}");
        }
        let mut read_only = credential(3600, None);
        read_only.access = Some(Access::ReadOnly);
        let value: Value = serde_json::from_str(&read_only.to_json().unwrap()).unwrap();
        assert_eq!(value["access"], "read-only");
        read_only.access = None;
        let value: Value = serde_json::from_str(&read_only.to_json().unwrap()).unwrap();
        assert!(value.get("access").is_none());
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
                          "tid": TENANT, "oid": OID,
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
        assert_eq!(
            setup.provider.take_notes(),
            ["refreshed the Graph token: returned scope none; refresh token rotated: no"]
        );
        assert!(setup.provider.take_notes().is_empty());
    }

    #[tokio::test]
    async fn the_notes_say_whether_a_redemption_rotated_the_refresh_token() {
        let setup = setup(credential(0, None)).await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "access_token": "canary-download-0002",
                "refresh_token": "canary-refresh-0001",
                "scope": "b26e684c-5068-4120-a679-64a5d2c909d9/eDiscovery.Download.Read",
                "expires_in": 3600,
            })))
            .mount(&setup.server)
            .await;
        setup
            .provider
            .download(Duration::from_secs(300))
            .await
            .unwrap();
        // The same refresh token handed back is not a rotation.
        assert_eq!(
            setup.provider.take_notes(),
            ["redeemed the download token: returned scope \
              b26e684c-5068-4120-a679-64a5d2c909d9/eDiscovery.Download.Read; refresh token \
              rotated: no"]
        );
    }

    #[test]
    fn a_loaded_credential_must_be_usable_and_belong_to_its_key() {
        let redactor = Redactor::new();
        let base = json!({"version": 1, "email": EMAIL, "client_id": CLIENT, "tenant_id": TENANT,
                          "tid": TENANT, "oid": OID,
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
            ("/oid", json!(""), "does not record the identity"),
            ("/tid", json!(" "), "does not record the identity"),
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
        /// The write, counting from 1, that reports a failure after it
        /// takes effect; 0 for none. Counted down as writes happen.
        fail_at: std::sync::atomic::AtomicUsize,
    }

    impl CommitsThenFails {
        fn new(inner: Arc<MemoryStore>) -> Self {
            Self {
                inner,
                fail_at: std::sync::atomic::AtomicUsize::new(0),
            }
        }

        fn fail_write(&self, nth: usize) {
            self.fail_at.store(nth, std::sync::atomic::Ordering::SeqCst);
        }
    }

    impl CredentialStore for CommitsThenFails {
        fn get_password(&self, key: &str) -> Result<Option<String>> {
            self.inner.get_password(key)
        }
        fn set_password(&self, key: &str, value: &str) -> Result<()> {
            use std::sync::atomic::Ordering;
            self.inner.set_password(key, value)?;
            let left = self.fail_at.load(Ordering::SeqCst);
            if left > 0 {
                self.fail_at.store(left - 1, Ordering::SeqCst);
                if left == 1 {
                    return Err(PurviewError::message("labelling the item failed"));
                }
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
        let store = Arc::new(CommitsThenFails::new(memory.clone()));
        let setup = setup_with(credential(0, None), store.clone(), memory).await;
        store.fail_write(1);
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

    #[tokio::test]
    async fn a_reload_after_a_refusal_finds_a_later_download_token() {
        let memory = Arc::new(MemoryStore::default());
        let store = Arc::new(CommitsThenFails::new(memory.clone()));
        let setup = setup_with(credential(3600, None), store.clone(), memory).await;
        Mock::given(method("POST"))
            .and(body_string_contains("b26e684c"))
            .respond_with(ResponseTemplate::new(400).set_body_json(json!({
                "error": "invalid_grant",
                "error_codes": [65001],
            })))
            .up_to_n_times(1)
            .with_priority(1)
            .mount(&setup.server)
            .await;
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
        // 1. Consent is refused.
        let error = setup.provider.download(margin).await.unwrap_err();
        assert_eq!(error.metadata(), ("DownloadNotConsented", 0));
        // 2. After consent, an explicit refresh stores the download token,
        //    but the store reports a failure after the write took effect.
        store.fail_write(2);
        let error = setup.provider.refresh_all().await.unwrap_err();
        assert!(
            error.to_string().contains("labelling the item failed"),
            "{error}"
        );
        assert_eq!(
            stored(&setup)["download"]["access_token"],
            "canary-download-0002"
        );
        // 3. The next download reloads, finds that token and uses it.
        let token = setup.provider.download(margin).await.unwrap();
        assert_eq!(token.expose(), "canary-download-0002");
    }

    #[tokio::test]
    async fn a_pending_reload_keeps_an_invalidated_graph_token_invalid() {
        let memory = Arc::new(MemoryStore::default());
        let store = Arc::new(CommitsThenFails::new(memory.clone()));
        let setup = setup_with(credential(3600, None), store.clone(), memory).await;
        Mock::given(method("POST"))
            .and(body_string_contains("b26e684c"))
            .respond_with(response("canary-download-0002", "canary-refresh-0001"))
            .mount(&setup.server)
            .await;
        Mock::given(method("POST"))
            .and(body_string_contains("graph.microsoft.com"))
            .respond_with(response("canary-graph-0002", "canary-refresh-0002"))
            .expect(1)
            .mount(&setup.server)
            .await;
        // A download whose store write commits and then fails leaves a
        // reload pending.
        store.fail_write(1);
        assert!(setup
            .provider
            .download(Duration::from_secs(300))
            .await
            .is_err());
        // The service refuses the Graph token, so it is invalidated; the
        // reload must not bring back the stored (unexpired) copy.
        setup.provider.invalidate_graph().await;
        let token = setup.provider.graph(Duration::from_secs(60)).await.unwrap();
        assert_eq!(token.expose(), "canary-graph-0002");
    }

    #[test]
    fn a_stored_principal_is_read_even_from_a_credential_this_release_refuses() {
        let store = MemoryStore::default();
        let redactor = Redactor::new();
        assert_eq!(
            Credential::stored_principal(&store, EMAIL, &redactor).unwrap(),
            StoredPrincipal::Absent
        );
        let text = json!({"version": 1, "email": EMAIL, "tid": TENANT, "oid": OID,
                          "refresh_token": "canary-refresh-0009", "graph": {"access_token": "a"}});
        crate::secrets::store_value(&store, &token_key(EMAIL), &text.to_string()).unwrap();
        assert_eq!(
            Credential::stored_principal(&store, EMAIL, &redactor).unwrap(),
            StoredPrincipal::Recorded {
                tid: TENANT.to_owned(),
                oid: OID.to_owned()
            }
        );
        assert!(redactor.recognises("canary-refresh-0009"));
    }

    #[tokio::test]
    async fn a_reload_that_finds_another_principal_is_refused_before_any_redemption() {
        let memory = Arc::new(MemoryStore::default());
        let store = Arc::new(CommitsThenFails::new(memory.clone()));
        let setup = setup_with(credential(0, None), store.clone(), memory.clone()).await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "access_token": "canary-graph-0002",
                "refresh_token": "canary-refresh-0002",
                "expires_in": 1,
                "scope": "eDiscovery.ReadWrite.All openid",
            })))
            .expect(1)
            .mount(&setup.server)
            .await;
        store.fail_write(1);
        assert!(setup.provider.graph(Duration::from_secs(60)).await.is_err());
        // Someone else's credential, through the same registration, now
        // holds the key.
        let mut other = credential(3600, None);
        other.oid = "00000000-0000-4000-8000-000000000099".into();
        other.save(memory.as_ref()).unwrap();
        let error = setup
            .provider
            .graph(Duration::from_secs(60))
            .await
            .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("another app registration or identity"),
            "{error}"
        );
        // The mock's expect(1) proves no second redemption was sent.
    }

    #[tokio::test]
    async fn a_refused_clearing_write_does_not_bring_back_the_refused_download_token() {
        // A download token with four minutes left.
        let setup = setup(credential(3600, Some(240))).await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(400).set_body_json(json!({
                "error": "invalid_grant",
                "error_codes": [65001],
            })))
            // One refusal: the later call must not ask again, nor use the
            // token the refusal was about.
            .expect(1)
            .mount(&setup.server)
            .await;
        // Renewal is refused for want of consent, and the write that would
        // clear the token is refused too.
        setup.memory.fail_writes(true);
        assert!(setup
            .provider
            .download(Duration::from_secs(300))
            .await
            .is_err());
        setup.memory.fail_writes(false);
        assert!(stored(&setup).get("download").is_some());
        // With a margin the old token would meet, it is still not used.
        let error = setup
            .provider
            .download(Duration::from_secs(60))
            .await
            .unwrap_err();
        assert_eq!(error.metadata(), ("DownloadNotConsented", 0));
    }

    #[tokio::test]
    async fn a_reload_refuses_a_credential_from_a_newer_sign_in() {
        let memory = Arc::new(MemoryStore::default());
        let store = Arc::new(CommitsThenFails::new(memory.clone()));
        let setup = setup_with(credential(0, None), store.clone(), memory).await;
        Mock::given(method("POST"))
            .respond_with(response("canary-graph-0002", "canary-refresh-0002"))
            .expect(1)
            .mount(&setup.server)
            .await;
        // The refresh is stored, and the store then reports a failure.
        store.fail_write(1);
        assert!(setup.provider.graph(Duration::from_secs(60)).await.is_err());
        // Before the next call reloads, the person signs in again.
        // Through another app registration, so the registration differs too.
        let mut newer = credential(3600, None);
        newer.sign_in = Some("sign-in-0004".into());
        newer.client_id = "00000000-0000-4000-8000-000000000071".into();
        newer.refresh_token = SecretString::new("canary-refresh-0095");
        newer.save(setup.memory.as_ref()).unwrap();
        let error = setup
            .provider
            .graph(Duration::from_secs(60))
            .await
            .unwrap_err();
        assert!(error.to_string().contains("signed in again"), "{error}");
        assert!(!error.to_string().contains("logout"), "{error}");
        assert_eq!(stored(&setup)["sign_in"], "sign-in-0004");
    }

    #[tokio::test]
    async fn a_reload_leaves_a_graph_token_stored_after_the_invalidation_alone() {
        let memory = Arc::new(MemoryStore::default());
        let store = Arc::new(CommitsThenFails::new(memory.clone()));
        let setup = setup_with(credential(3600, None), store.clone(), memory).await;
        Mock::given(method("POST"))
            .respond_with(response("canary-graph-0002", "canary-refresh-0002"))
            .expect(1)
            .mount(&setup.server)
            .await;
        setup.provider.invalidate_graph().await;
        // The refresh is stored, and the store then reports a failure.
        store.fail_write(1);
        assert!(setup.provider.graph(Duration::from_secs(60)).await.is_err());
        // The token read back is the new one, not the invalidated one, so
        // it is used without another redemption.
        let token = setup.provider.graph(Duration::from_secs(60)).await.unwrap();
        assert_eq!(token.expose(), "canary-graph-0002");
    }

    #[tokio::test]
    async fn a_rotation_is_not_committed_over_another_principal_s_credential() {
        let setup = setup(credential(0, None)).await;
        Mock::given(method("POST"))
            .respond_with(response("canary-graph-0002", "canary-refresh-0002"))
            .expect(1)
            .mount(&setup.server)
            .await;
        // While this provider runs, another sign-in stores someone else's
        // credential under the key.
        let mut other = credential(3600, None);
        other.oid = "00000000-0000-4000-8000-000000000099".into();
        other.refresh_token = SecretString::new("canary-refresh-0099");
        other.save(setup.memory.as_ref()).unwrap();
        let error = setup
            .provider
            .graph(Duration::from_secs(60))
            .await
            .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("replaced or removed by another command"),
            "{error}"
        );
        assert_eq!(stored(&setup)["refresh_token"], "canary-refresh-0099");
    }

    #[tokio::test]
    async fn a_refreshed_token_too_short_for_the_request_is_not_used() {
        let setup = setup(credential(0, None)).await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "access_token": "canary-graph-0002",
                "refresh_token": "canary-refresh-0002",
                "expires_in": 120,
                "scope": "eDiscovery.ReadWrite.All openid",
            })))
            .expect(1)
            .mount(&setup.server)
            .await;
        let error = setup
            .provider
            .graph(Duration::from_secs(300))
            .await
            .unwrap_err();
        assert!(
            error.to_string().contains("less than the 300 seconds"),
            "{error}"
        );
        // The rotation was stored, so the newest refresh token is kept.
        assert_eq!(stored(&setup)["refresh_token"], "canary-refresh-0002");
        // A request that needs less can use it, without another redemption.
        let token = setup.provider.graph(Duration::from_secs(60)).await.unwrap();
        assert_eq!(token.expose(), "canary-graph-0002");
    }

    #[tokio::test]
    async fn a_refresh_is_not_committed_over_a_sign_in_that_changed_access() {
        let setup = setup(credential(0, None)).await;
        Mock::given(method("POST"))
            .respond_with(response("canary-graph-0002", "canary-refresh-0002"))
            .expect(1)
            .mount(&setup.server)
            .await;
        // While this read-write provider runs, the same person signs in
        // again with --read-only through the same registration.
        let mut read_only = credential(3600, None);
        read_only.access = Some(Access::ReadOnly);
        read_only.sign_in = Some("sign-in-0002".into());
        read_only.refresh_token = SecretString::new("canary-refresh-0098");
        read_only.save(setup.memory.as_ref()).unwrap();
        let error = setup
            .provider
            .graph(Duration::from_secs(60))
            .await
            .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("replaced or removed by another command"),
            "{error}"
        );
        let stored = stored(&setup);
        assert_eq!(stored["access"], "read-only");
        assert_eq!(stored["refresh_token"], "canary-refresh-0098");
    }

    #[tokio::test]
    async fn a_refresh_is_not_committed_over_a_newer_sign_in_with_other_permissions() {
        let setup = setup(credential(0, None)).await;
        Mock::given(method("POST"))
            .respond_with(response("canary-graph-0002", "canary-refresh-0002"))
            .expect(1)
            .mount(&setup.server)
            .await;
        // A newer read-write sign-in whose token lacks the write permission.
        let mut newer = credential(3600, None);
        newer.sign_in = Some("sign-in-0003".into());
        newer.graph.scope = "eDiscovery.Read.All openid".into();
        newer.refresh_token = SecretString::new("canary-refresh-0097");
        newer.save(setup.memory.as_ref()).unwrap();
        assert!(setup.provider.graph(Duration::from_secs(60)).await.is_err());
        let stored = stored(&setup);
        assert_eq!(stored["graph"]["scope"], "eDiscovery.Read.All openid");
        assert_eq!(stored["sign_in"], "sign-in-0003");
    }

    #[tokio::test]
    async fn a_refresh_of_the_same_sign_in_by_another_command_is_kept() {
        let setup = setup(credential(0, None)).await;
        Mock::given(method("POST"))
            .respond_with(response("canary-graph-0002", "canary-refresh-0002"))
            .expect(1)
            .mount(&setup.server)
            .await;
        // Another command refreshed the same sign-in: same id, new tokens.
        let mut refreshed = credential(10, None);
        refreshed.refresh_token = SecretString::new("canary-refresh-0096");
        refreshed.save(setup.memory.as_ref()).unwrap();
        let token = setup.provider.graph(Duration::from_secs(60)).await.unwrap();
        assert_eq!(token.expose(), "canary-graph-0002");
        assert_eq!(stored(&setup)["sign_in"], "sign-in-0001");
    }

    #[test]
    fn a_stored_principal_debug_names_no_id() {
        let principal = StoredPrincipal::Recorded {
            tid: "canary-tid-0001".into(),
            oid: String::new(),
        };
        assert_eq!(
            format!("{principal:?}"),
            "Recorded { tid_recorded: true, oid_recorded: false }"
        );
        assert_eq!(format!("{:?}", StoredPrincipal::Unreadable), "Unreadable");
    }

    #[tokio::test]
    async fn a_failed_reload_is_retried_and_the_cached_token_is_never_returned() {
        for damage in ["remove", "corrupt"] {
            let memory = Arc::new(MemoryStore::default());
            let store = Arc::new(CommitsThenFails::new(memory.clone()));
            let setup = setup_with(credential(0, None), store.clone(), memory.clone()).await;
            Mock::given(method("POST"))
                .respond_with(response("canary-graph-0002", "canary-refresh-0002"))
                .expect(1)
                .mount(&setup.server)
                .await;
            store.fail_write(1);
            assert!(setup.provider.graph(Duration::from_secs(60)).await.is_err());
            if damage == "remove" {
                crate::secrets::delete_value(memory.as_ref(), &token_key(EMAIL)).unwrap();
            } else {
                crate::secrets::store_value(memory.as_ref(), &token_key(EMAIL), "{damaged")
                    .unwrap();
            }
            for _ in 0..2 {
                assert!(
                    setup.provider.graph(Duration::from_secs(60)).await.is_err(),
                    "{damage}: a cached token was returned"
                );
            }
        }
    }
}
