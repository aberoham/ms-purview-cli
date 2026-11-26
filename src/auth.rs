//! Sign-in against the Microsoft identity platform: the device-code flow,
//! the browser flow (authorization code with PKCE on a loopback redirect),
//! refresh-token redemption for the two resources, and the account claims
//! read from the id token.
//!
//! The device-code and token-endpoint handling is adapted from
//! `aberoham/ms-entra-cli` (`src/auth.rs`) and maintained separately. It
//! differs in three ways: the account comes from id-token claims rather
//! than `/me`, one refresh token is redeemed for a second resource (the
//! Purview eDiscovery app), and every secret is held as a `SecretString`
//! and registered with the Redactor as soon as it arrives.

use std::fmt;
use std::io::Write;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::time::Duration;

use base64::Engine;
use reqwest::StatusCode;
use serde::{Deserialize, Deserializer};
use serde_json::Value;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use url::Url;
use uuid::Uuid;

use crate::config::AccountRecord;
use crate::env::{BrowserOpener, Clock};
use crate::error::{OAuthDetails, PurviewError, Result};
use crate::output::sanitize;
use crate::redact::Redactor;
use crate::token::{AccessToken, Credential, SecretString};

/// Microsoft Graph, the prefix of its delegated scopes.
pub const GRAPH_RESOURCE: &str = "https://graph.microsoft.com/";
/// The Purview eDiscovery application, which issues the download token.
pub const EDISCOVERY_APP_ID: &str = "b26e684c-5068-4120-a679-64a5d2c909d9";
pub const SCOPE_READ_WRITE: &str = "eDiscovery.ReadWrite.All";
pub const SCOPE_READ: &str = "eDiscovery.Read.All";
/// Scopes that name no resource: OpenID Connect and refresh tokens.
const RESOURCELESS_SCOPES: &[&str] = &["offline_access", "openid", "profile", "email"];
const SIGN_IN_EXTRAS: &str = "offline_access openid profile";

const MAX_OAUTH_RESPONSE: usize = 100 * 1024;
/// The timeout for each request to the identity platform.
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const DEVICE_CODE_GRANT: &str = "urn:ietf:params:oauth:grant-type:device_code";

/// The Graph scopes for `auth login` (`docs/SPEC.md` section 5.1).
pub fn login_scope(read_only: bool) -> String {
    let permission = if read_only {
        SCOPE_READ
    } else {
        SCOPE_READ_WRITE
    };
    format!("{GRAPH_RESOURCE}{permission} {SIGN_IN_EXTRAS}")
}

/// The scope for the download token: everything the app holds on the
/// eDiscovery app, plus `offline_access` so that the response carries a
/// rotated refresh token.
pub fn download_scope() -> String {
    format!("{EDISCOVERY_APP_ID}/.default offline_access")
}

/// The scope for a Graph refresh, built from the scopes stored with the
/// token: each short Graph permission name gets the Graph resource prefix,
/// entries that repeat (ignoring case) are dropped, and `offline_access` is
/// added if the list lacks it. No permission is added or removed, so the
/// request asks for the stored permission set; `StoredTokenProvider`
/// refuses a response that grants a different one.
pub fn graph_refresh_scope(stored: &str) -> String {
    let mut scopes: Vec<String> = Vec::new();
    for scope in stored.split_whitespace() {
        let lower = scope.to_ascii_lowercase();
        let full = if RESOURCELESS_SCOPES.contains(&lower.as_str()) || scope.contains('/') {
            scope.to_owned()
        } else {
            format!("{GRAPH_RESOURCE}{scope}")
        };
        if !scopes.iter().any(|known| known.eq_ignore_ascii_case(&full)) {
            scopes.push(full);
        }
    }
    if !scopes
        .iter()
        .any(|scope| scope.eq_ignore_ascii_case("offline_access"))
    {
        scopes.push("offline_access".to_owned());
    }
    scopes.join(" ")
}

/// The Graph permissions in a scope list, as lowercase short names: the
/// OpenID Connect and `offline_access` entries are left out, and the Graph
/// resource prefix is removed. A permission for another resource keeps its
/// prefix. Two lists grant the same permissions when these sets are equal.
pub fn graph_permissions(scope: &str) -> std::collections::BTreeSet<String> {
    scope
        .split_whitespace()
        .map(str::to_ascii_lowercase)
        .filter(|item| !RESOURCELESS_SCOPES.contains(&item.as_str()))
        .map(|item| match item.strip_prefix(GRAPH_RESOURCE) {
            Some(short) => short.to_owned(),
            None => item,
        })
        .filter(|item| !item.is_empty())
        .collect()
}

/// Whether a scope list holds at least one Microsoft Graph permission. A
/// list with only OpenID Connect entries, or only permissions for another
/// resource, cannot be refreshed into a Graph token.
pub fn has_graph_permission(scope: &str) -> bool {
    graph_permissions(scope)
        .iter()
        .any(|permission| !permission.contains('/') && !permission.contains(':'))
}

/// An application (client) id must be a GUID.
pub fn validate_client_id(value: &str) -> Result<String> {
    Uuid::parse_str(value.trim())
        .map(|id| id.to_string())
        .map_err(|_| {
            PurviewError::message(format!(
                "invalid client id {:?}: it must be the application (client) id, a GUID",
                sanitize(value)
            ))
        })
}

/// A tenant id must be a GUID. The app registration is single-tenant, so
/// `common` and `organizations` cannot sign in to it.
pub fn validate_tenant_id(value: &str) -> Result<String> {
    Uuid::parse_str(value.trim())
        .map(|id| id.to_string())
        .map_err(|_| {
            PurviewError::message(format!(
                "invalid tenant id {:?}: it must be the directory (tenant) id, a GUID",
                sanitize(value)
            ))
        })
}

/// A token endpoint response. The secrets deserialise straight into
/// `SecretString`, so the derived `Debug` cannot print them.
#[derive(Debug, Clone, Deserialize)]
pub struct TokenResponse {
    pub access_token: SecretString,
    #[serde(default)]
    pub refresh_token: Option<SecretString>,
    #[serde(default)]
    pub id_token: Option<SecretString>,
    #[serde(default, deserialize_with = "seconds")]
    pub expires_in: Option<u64>,
    #[serde(default)]
    pub scope: String,
}

impl TokenResponse {
    /// The lifetime to record. A missing, zero or implausibly long value is
    /// taken as one hour, as in `entra`.
    pub fn lifetime_seconds(&self) -> i64 {
        match self.expires_in {
            Some(value @ 1..=86_400) => value as i64,
            _ => 3_600,
        }
    }

    fn register(&self, redactor: &Redactor) {
        redactor.register(self.access_token.expose());
        for secret in [&self.refresh_token, &self.id_token].into_iter().flatten() {
            redactor.register(secret.expose());
        }
    }
}

#[derive(Debug, Deserialize)]
struct DeviceCodeResponse {
    device_code: SecretString,
    user_code: String,
    verification_uri: String,
    #[serde(default, deserialize_with = "seconds")]
    expires_in: Option<u64>,
    #[serde(default, deserialize_with = "seconds")]
    interval: Option<u64>,
}

/// The allow-listed fields of an OAuth error body (`docs/SPEC.md`
/// section 6.8). Everything else in the body is dropped.
#[derive(Debug, Default, Deserialize)]
struct OAuthErrorBody {
    #[serde(default)]
    error: String,
    #[serde(default)]
    error_description: String,
    #[serde(default)]
    error_codes: Vec<i64>,
    #[serde(default)]
    trace_id: String,
    #[serde(default)]
    correlation_id: String,
    #[serde(default)]
    timestamp: String,
}

/// Seconds as a JSON number or, as some endpoints send them, a string.
fn seconds<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<Option<u64>, D::Error> {
    Ok(match Option::<Value>::deserialize(deserializer)? {
        Some(Value::Number(number)) => number.as_u64(),
        Some(Value::String(text)) => text.trim().parse().ok(),
        _ => None,
    })
}

/// A client for one app registration in one tenant, against the identity
/// platform base the `Env` names.
#[derive(Clone)]
pub struct IdentityClient {
    http: reqwest::Client,
    base: Url,
    client_id: String,
    tenant_id: String,
    redactor: Arc<Redactor>,
}

impl fmt::Debug for IdentityClient {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("IdentityClient")
            .field("base", &self.base.as_str())
            .field("client_id", &self.client_id)
            .field("tenant_id", &self.tenant_id)
            .finish_non_exhaustive()
    }
}

impl IdentityClient {
    pub fn new(
        base: Url,
        client_id: &str,
        tenant_id: &str,
        request_timeout: Duration,
        redactor: Arc<Redactor>,
    ) -> Result<Self> {
        Ok(Self {
            http: reqwest::Client::builder()
                .timeout(request_timeout)
                .redirect(reqwest::redirect::Policy::none())
                .build()?,
            base,
            client_id: validate_client_id(client_id)?,
            tenant_id: validate_tenant_id(tenant_id)?,
            redactor,
        })
    }

    pub fn client_id(&self) -> &str {
        &self.client_id
    }

    pub fn tenant_id(&self) -> &str {
        &self.tenant_id
    }

    /// Redeems a refresh token for `scope`. The response's secrets are
    /// registered with the Redactor before it is returned.
    pub async fn redeem_refresh_token(
        &self,
        refresh_token: &SecretString,
        scope: &str,
        operation: &str,
    ) -> Result<TokenResponse> {
        let form = [
            ("client_id", self.client_id.as_str()),
            ("grant_type", "refresh_token"),
            ("refresh_token", refresh_token.expose()),
            ("scope", scope),
        ];
        let (status, body) = self.post("token", &form).await?;
        if status != StatusCode::OK {
            return Err(self.oauth_error(operation, status, &body));
        }
        self.token_response(&body, operation)
    }

    async fn request_device_code(&self, scope: &str) -> Result<DeviceCodeResponse> {
        let operation = "requesting a device code";
        let form = [("client_id", self.client_id.as_str()), ("scope", scope)];
        let (status, body) = self.post("devicecode", &form).await?;
        if status != StatusCode::OK {
            return Err(self.oauth_error(operation, status, &body));
        }
        let code: DeviceCodeResponse =
            serde_json::from_slice(&body).map_err(|_| unreadable_response(operation))?;
        self.redactor.register(code.device_code.expose());
        if code.device_code.is_empty() || code.user_code.trim().is_empty() {
            return Err(PurviewError::message(
                "the device code response had no device code or user code",
            ));
        }
        Ok(code)
    }

    /// Polls the token endpoint until the user finishes signing in, the
    /// code expires, or the identity platform refuses.
    ///
    /// `deadline` is on the clock's monotonic scale, taken when the code
    /// arrived, so neither a slow prompt nor a change to the wall clock can
    /// extend it. It bounds every sleep and request, and a success that
    /// arrives after it is refused. Each request also has the client's own
    /// timeout, which reports a stalled request as a transport failure.
    async fn poll_device_code(
        &self,
        code: &DeviceCodeResponse,
        deadline: Duration,
        clock: &dyn Clock,
    ) -> Result<TokenResponse> {
        let operation = "signing in with the device code";
        let mut interval = code.interval.unwrap_or(5).clamp(1, 120);
        let remaining = || deadline.saturating_sub(clock.elapsed());
        loop {
            clock
                .sleep(Duration::from_secs(interval).min(remaining()))
                .await;
            if remaining().is_zero() {
                return Err(expired_device_code());
            }
            let form = [
                ("client_id", self.client_id.as_str()),
                ("grant_type", DEVICE_CODE_GRANT),
                ("device_code", code.device_code.expose()),
            ];
            let (status, body) =
                tokio::time::timeout(poll_bound(remaining()), self.post("token", &form))
                    .await
                    .map_err(|_| expired_device_code())??;
            if remaining().is_zero() {
                return Err(expired_device_code());
            }
            if status == StatusCode::OK {
                return self.token_response(&body, operation);
            }
            let reason = serde_json::from_slice::<OAuthErrorBody>(&body)
                .map(|parsed| parsed.error)
                .unwrap_or_default();
            match reason.as_str() {
                "authorization_pending" => {}
                "slow_down" => interval = (interval + 5).min(120),
                "expired_token" => return Err(expired_device_code()),
                _ => return Err(self.oauth_error(operation, status, &body)),
            }
        }
    }

    fn token_response(&self, body: &[u8], operation: &str) -> Result<TokenResponse> {
        let response: TokenResponse =
            serde_json::from_slice(body).map_err(|_| unreadable_response(operation))?;
        response.register(&self.redactor);
        if response.access_token.is_empty() {
            return Err(PurviewError::message(format!(
                "{operation}: the response held an empty access token"
            )));
        }
        Ok(response)
    }

    async fn post(&self, leaf: &str, form: &[(&str, &str)]) -> Result<(StatusCode, Vec<u8>)> {
        let response = self
            .http
            .post(self.endpoint(leaf)?)
            .form(form)
            .send()
            .await
            .map_err(|error| PurviewError::message(transport_failure(&error)))?;
        let status = response.status();
        let body = bounded_body(response, MAX_OAUTH_RESPONSE).await?;
        self.register_body_secrets(&body);
        Ok((status, body))
    }

    /// Registers every token-shaped field of a response body, whatever its
    /// status, before anything reads it: an error body that hands out a
    /// token and also quotes it in `error_description` must not carry it
    /// to output.
    fn register_body_secrets(&self, body: &[u8]) {
        const SECRET_FIELDS: &[&str] =
            &["access_token", "refresh_token", "id_token", "device_code"];
        if let Ok(Value::Object(fields)) = serde_json::from_slice::<Value>(body) {
            for name in SECRET_FIELDS {
                if let Some(Value::String(secret)) = fields.get(*name) {
                    self.redactor.register(secret);
                }
            }
        }
    }

    fn endpoint(&self, leaf: &str) -> Result<Url> {
        let mut url = self.base.clone();
        url.path_segments_mut()
            .map_err(|_| PurviewError::message("the identity platform URL cannot hold a path"))?
            .pop_if_empty()
            .push(&self.tenant_id)
            .push("oauth2")
            .push("v2.0")
            .push(leaf);
        Ok(url)
    }

    /// An `OAuth` error from the allow-listed fields of the body, with the
    /// description redacted. A body that is not an OAuth error gives the
    /// status alone; the body is never quoted.
    fn oauth_error(&self, operation: &str, status: StatusCode, body: &[u8]) -> PurviewError {
        match serde_json::from_slice::<OAuthErrorBody>(body) {
            Ok(parsed) if !parsed.error.is_empty() => {
                let clean = |text: &str| sanitize(&self.redactor.redact(text));
                PurviewError::OAuth(Box::new(OAuthDetails {
                    operation: operation.to_owned(),
                    status: status.as_u16(),
                    error: clean(&parsed.error),
                    description: clean(&parsed.error_description),
                    error_codes: parsed.error_codes,
                    trace_id: clean(&parsed.trace_id),
                    correlation_id: clean(&parsed.correlation_id),
                    timestamp: clean(&parsed.timestamp),
                }))
            }
            _ => PurviewError::message(format!("{operation} failed with HTTP {}", status.as_u16())),
        }
    }
}

/// How long the outer timer lets one poll run: exactly what is left of the
/// device code's lifetime. It has no shorter cap of its own; the client's
/// own request timeout reports a stalled request as a transport failure,
/// and a cap here would report it as an expired code instead.
fn poll_bound(remaining: Duration) -> Duration {
    remaining
}

fn expired_device_code() -> PurviewError {
    PurviewError::message(
        "the device code expired before sign-in finished; run 'purview auth login' again",
    )
}

fn unreadable_response(operation: &str) -> PurviewError {
    PurviewError::message(format!(
        "{operation}: the identity platform's response could not be read"
    ))
}

/// A request that never got a response. reqwest's message names the URL,
/// which holds no secret here (tokens travel in the form body), but the
/// error chain is kept short and plain.
fn transport_failure(error: &reqwest::Error) -> String {
    let kind = if error.is_timeout() {
        "the request timed out"
    } else if error.is_connect() {
        "the connection failed"
    } else {
        "the request failed"
    };
    format!("could not reach the identity platform: {kind}")
}

async fn bounded_body(mut response: reqwest::Response, maximum: usize) -> Result<Vec<u8>> {
    let too_large = || {
        PurviewError::message(format!(
            "the identity platform's response exceeds {maximum} bytes"
        ))
    };
    if response
        .content_length()
        .is_some_and(|length| length > maximum as u64)
    {
        return Err(too_large());
    }
    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|error| PurviewError::message(transport_failure(&error)))?
    {
        if body.len().saturating_add(chunk.len()) > maximum {
            return Err(too_large());
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

/// What the id token says about the account (`docs/SPEC.md` section 5.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountClaims {
    /// `preferred_username`, else `upn`, else `email`, lowercased.
    pub account: String,
    pub upn: Option<String>,
    pub oid: String,
    pub tid: String,
    pub name: Option<String>,
}

/// Reads the account claims from an id token. The token comes straight
/// from the token endpoint over TLS and only labels the account, so its
/// signature is not checked.
pub fn account_claims(id_token: Option<&SecretString>) -> Result<AccountClaims> {
    let undecodable = |detail: &str| PurviewError::NoAccountClaim {
        detail: Some(detail.to_owned()),
    };
    let token = id_token.ok_or_else(|| undecodable("the token response held no id token"))?;
    let payload = token
        .expose()
        .split('.')
        .nth(1)
        .ok_or_else(|| undecodable("the id token could not be decoded"))?;
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload.trim_end_matches('='))
        .map_err(|_| undecodable("the id token could not be decoded"))?;
    let claims: serde_json::Map<String, Value> = serde_json::from_slice(&bytes)
        .map_err(|_| undecodable("the id token could not be decoded"))?;
    let text = |name: &str| {
        claims
            .get(name)
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_owned)
    };
    let account = text("preferred_username")
        .or_else(|| text("upn"))
        .or_else(|| text("email"))
        .ok_or(PurviewError::NoAccountClaim { detail: None })?
        .to_ascii_lowercase();
    Ok(AccountClaims {
        account,
        upn: text("upn"),
        oid: text("oid").unwrap_or_default(),
        tid: text("tid").unwrap_or_default(),
        name: text("name"),
    })
}

/// A completed device-code sign-in, not yet stored.
#[derive(Debug)]
pub struct LoginOutcome {
    pub credential: Credential,
    pub record: AccountRecord,
    /// The download redemption was refused for want of consent
    /// (`AADSTS65001`); the credential then holds no download token.
    pub download_refused: Option<PurviewError>,
}

/// Signs in with a device code (`docs/SPEC.md` section 3.5, `auth login`):
/// a Graph token with the login scopes, then the refresh token redeemed for
/// the download token. The prompt goes to `prompt` (the command's redacted
/// stderr). Nothing is stored here; the caller stores the outcome.
pub async fn login_device_code(
    identity: &IdentityClient,
    clock: &dyn Clock,
    read_only: bool,
    prompt: &mut dyn Write,
) -> Result<LoginOutcome> {
    let scope = login_scope(read_only);
    let code = identity.request_device_code(&scope).await?;
    let lifetime = Duration::from_secs(code.expires_in.unwrap_or(900).clamp(1, 3_600));
    let deadline = clock.elapsed() + lifetime;
    writeln!(
        prompt,
        "To sign in, open {} in a browser and enter the code {}\nWaiting for sign-in...",
        sanitize(&code.verification_uri),
        sanitize(&code.user_code)
    )?;
    prompt.flush()?;
    let token = identity.poll_device_code(&code, deadline, clock).await?;
    complete_login(identity, clock, token, &scope).await
}

/// The part of a sign-in after the Graph token arrives, whichever flow
/// obtained it: the account claims, the principal check, then the
/// refresh token redeemed for the download token.
async fn complete_login(
    identity: &IdentityClient,
    clock: &dyn Clock,
    token: TokenResponse,
    scope: &str,
) -> Result<LoginOutcome> {
    let claims = account_claims(token.id_token.as_ref())?;
    let refresh_token = token
        .refresh_token
        .clone()
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            PurviewError::message(
                "the sign-in returned no refresh token; the app needs the offline_access \
                 permission",
            )
        })?;
    // The principal binds the account key to one identity; without it the
    // key could later be taken over by someone else.
    if claims.tid.is_empty() || claims.oid.is_empty() {
        return Err(PurviewError::message(
            "the sign-in returned an id token without the tid or oid claim, so the account \
             cannot be bound to one identity; nothing was stored",
        ));
    }
    let mut credential = Credential {
        email: claims.account.clone(),
        tid: claims.tid.clone(),
        oid: claims.oid.clone(),
        client_id: identity.client_id().to_owned(),
        tenant_id: identity.tenant_id().to_owned(),
        refresh_token,
        graph: AccessToken::from_response(&token, clock.now(), scope),
        download: None,
    };
    let download_scope = download_scope();
    let download_refused = match identity
        .redeem_refresh_token(
            &credential.refresh_token,
            &download_scope,
            "redeeming the refresh token for the download token",
        )
        .await
    {
        Ok(response) => {
            credential.download = Some(AccessToken::from_response(
                &response,
                clock.now(),
                &download_scope,
            ));
            if let Some(rotated) = response.refresh_token.filter(|value| !value.is_empty()) {
                credential.refresh_token = rotated;
            }
            None
        }
        Err(error) if error.is_consent_required() => Some(error),
        Err(error) => return Err(error),
    };
    let record = AccountRecord {
        email: claims.account,
        upn: claims.upn,
        oid: claims.oid,
        display_name: claims.name,
        tenant_id: claims.tid,
        client_id: identity.client_id().to_owned(),
        login_time: clock
            .now()
            .to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        extra: Default::default(),
    };
    Ok(LoginOutcome {
        credential,
        record,
        download_refused,
    })
}

/// The path of the redirect the app registration lists,
/// `http://localhost/callback` (`docs/SPEC.md` section 5.2). The identity
/// platform ignores the port of a loopback redirect when it compares it with
/// the registration (Docs), so the listener's port is added at run time.
/// The observed registration accepted it (Observed, `docs/api-notes.md`).
const REDIRECT_PATH: &str = "/callback";
/// The most of one request to the loopback listener that is read.
const MAX_CALLBACK_REQUEST: usize = 16 * 1024;
/// How long one connection to the listener may take to send its request, so
/// that a connection that sends nothing cannot hold up the sign-in.
const CALLBACK_READ_TIMEOUT: Duration = Duration::from_secs(10);
/// How long `auth login --browser` waits for the browser to come back.
pub const BROWSER_TIMEOUT: Duration = Duration::from_secs(900);
/// How many connections to the listener are served at once.
const MAX_CALLBACK_CONNECTIONS: usize = 16;
/// How long a refusal's description from the browser may be when quoted.
const MAX_CALLBACK_DESCRIPTION: usize = 1_000;

/// A Proof Key for Code Exchange (PKCE, RFC 7636) pair with the `S256`
/// method: the verifier stays in this process, and the authorization
/// request carries only the challenge.
struct Pkce {
    verifier: SecretString,
    challenge: String,
}

impl Pkce {
    /// A verifier of 32 random bytes, which is 43 base64url characters
    /// (RFC 7636 allows 43 to 128).
    fn generate() -> Result<Self> {
        let verifier = random_urlsafe(32)?;
        Ok(Self {
            challenge: pkce_challenge(&verifier),
            verifier: SecretString::new(verifier),
        })
    }
}

/// `BASE64URL(SHA256(verifier))` without padding (RFC 7636 section 4.2).
fn pkce_challenge(verifier: &str) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}

/// `bytes` random bytes from the operating system, as base64url text.
fn random_urlsafe(bytes: usize) -> Result<String> {
    let mut buffer = vec![0_u8; bytes];
    getrandom::fill(&mut buffer).map_err(|error| {
        PurviewError::message(format!("could not generate a random value: {error}"))
    })?;
    Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(buffer))
}

impl IdentityClient {
    /// The authorization request for the browser. `prompt=select_account`
    /// lets the person choose the account rather than reuse whichever one
    /// the browser is signed in as.
    fn authorization_url(
        &self,
        redirect_uri: &str,
        scope: &str,
        state: &str,
        challenge: &str,
    ) -> Result<Url> {
        let mut url = self.endpoint("authorize")?;
        url.query_pairs_mut()
            .append_pair("client_id", &self.client_id)
            .append_pair("response_type", "code")
            .append_pair("redirect_uri", redirect_uri)
            .append_pair("response_mode", "query")
            .append_pair("scope", scope)
            .append_pair("state", state)
            .append_pair("code_challenge", challenge)
            .append_pair("code_challenge_method", "S256")
            .append_pair("prompt", "select_account");
        Ok(url)
    }

    /// Redeems the authorization code with the PKCE verifier. The redirect
    /// and scope must be the ones the authorization request named.
    async fn exchange_code(
        &self,
        code: &SecretString,
        redirect_uri: &str,
        verifier: &SecretString,
        scope: &str,
    ) -> Result<TokenResponse> {
        let operation = "redeeming the browser sign-in's authorization code";
        let form = [
            ("client_id", self.client_id.as_str()),
            ("grant_type", "authorization_code"),
            ("code", code.expose()),
            ("redirect_uri", redirect_uri),
            ("code_verifier", verifier.expose()),
            ("scope", scope),
        ];
        let (status, body) = self.post("token", &form).await?;
        if status != StatusCode::OK {
            return Err(self.oauth_error(operation, status, &body));
        }
        self.token_response(&body, operation)
    }
}

/// The listener for the browser's redirect: `127.0.0.1` on a port the
/// system picks, and `::1` on the same port, because a browser may try
/// `localhost` over IPv6 first. A port whose IPv6 side another process
/// holds is given up for another, so that a redirect to `localhost` cannot
/// reach that process. Where IPv6 is unavailable, IPv4 alone is used.
struct Loopback {
    v4: TcpListener,
    v6: Option<TcpListener>,
    port: u16,
}

impl Loopback {
    async fn bind() -> Result<Self> {
        let unavailable = |error: std::io::Error| {
            PurviewError::Io(error).context(
                "could not listen on the loopback address for the browser sign-in; run \
                 'purview auth login' without --browser to use a device code",
            )
        };
        // Ports given up are held until binding ends, so that the system
        // cannot hand the same one out again.
        let mut given_up = Vec::new();
        for _ in 0..8 {
            let v4 = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
                .await
                .map_err(unavailable)?;
            let port = v4.local_addr().map_err(unavailable)?.port();
            match TcpListener::bind((Ipv6Addr::LOCALHOST, port)).await {
                Ok(v6) => {
                    return Ok(Self {
                        v4,
                        v6: Some(v6),
                        port,
                    })
                }
                Err(error) if ipv6_port_taken(error.kind()) => given_up.push(v4),
                Err(_) => return Ok(Self { v4, v6: None, port }),
            }
        }
        Err(PurviewError::message(
            "could not find a free loopback port for the browser sign-in; run 'purview auth \
             login' without --browser to use a device code",
        ))
    }

    fn redirect_uri(&self) -> String {
        format!("http://localhost:{}{REDIRECT_PATH}", self.port)
    }

    async fn accept(&self) -> std::io::Result<TcpStream> {
        let accepted = match &self.v6 {
            Some(v6) => tokio::select! {
                accepted = self.v4.accept() => accepted,
                accepted = v6.accept() => accepted,
            },
            None => self.v4.accept().await,
        };
        accepted.map(|(stream, _)| stream)
    }
}

/// Whether a failure to bind `::1` means another socket holds the port, so
/// that another port must be tried. Windows reports an address held with
/// `SO_EXCLUSIVEADDRUSE` as `WSAEACCES`, which is `PermissionDenied`. Any
/// other failure is taken to mean IPv6 loopback is unavailable.
fn ipv6_port_taken(kind: std::io::ErrorKind) -> bool {
    matches!(
        kind,
        std::io::ErrorKind::AddrInUse | std::io::ErrorKind::PermissionDenied
    )
}

/// What one request to the loopback listener means for the sign-in.
#[derive(Debug)]
enum Callback {
    /// Not the redirect: another path, another method, or not HTTP. A
    /// browser asks for `/favicon.ico`, for instance. Answered 404.
    Unrelated,
    /// The redirect path without this sign-in's `state`: a response meant
    /// for another sign-in, or a request from something other than the
    /// identity platform. Answered 400; the sign-in keeps waiting.
    Foreign,
    /// The identity platform's answer to this sign-in.
    Answer(Result<SecretString>),
}

/// Reads one request head: the request line, as the identity platform
/// puts the answer in the query string (`response_mode=query`). Only a
/// complete head whose request line is `GET /callback?… HTTP/1.x`, with the
/// path exactly as written, can be the redirect.
fn classify_callback(head: &str, expected_state: &str, redactor: &Redactor) -> Callback {
    if !head.ends_with("\r\n\r\n") && !head.ends_with("\n\n") {
        return Callback::Unrelated;
    }
    let line = head.lines().next().unwrap_or_default();
    let words: Vec<&str> = line.split(' ').collect();
    let [method, target, version] = words.as_slice() else {
        return Callback::Unrelated;
    };
    if *method != "GET" || !matches!(*version, "HTTP/1.1" | "HTTP/1.0") {
        return Callback::Unrelated;
    }
    let (raw_path, query) = target.split_once('?').unwrap_or((target, ""));
    if raw_path != REDIRECT_PATH {
        return Callback::Unrelated;
    }
    let Ok(url) = Url::parse(&format!("http://localhost{REDIRECT_PATH}?{query}")) else {
        return Callback::Unrelated;
    };
    let pairs: Vec<(String, String)> = url.query_pairs().into_owned().collect();
    let values = |name: &str| -> Vec<&str> {
        pairs
            .iter()
            .filter(|(key, _)| key == name)
            .map(|(_, value)| value.as_str())
            .collect()
    };
    // The identity platform returns `state` with errors as well as codes, so
    // it is checked first, and exactly one copy is accepted. A foreign
    // request's values are dropped unread.
    if values("state") != [expected_state] {
        return Callback::Foreign;
    }
    let (codes, errors) = (values("code"), values("error"));
    // A code is a secret from the moment it is accepted.
    for code in &codes {
        redactor.register(code);
    }
    let answer = match (codes.as_slice(), errors.as_slice()) {
        ([], [error]) => {
            let clean = |text: &str| {
                let text = sanitize(&redactor.redact(text));
                match text.char_indices().nth(MAX_CALLBACK_DESCRIPTION) {
                    Some((end, _)) => format!("{}…", &text[..end]),
                    None => text,
                }
            };
            let description = values("error_description")
                .first()
                .map(|text| format!(": {}", clean(text)))
                .unwrap_or_default();
            Err(PurviewError::message(format!(
                "the browser sign-in was refused: {}{description}",
                clean(error)
            )))
        }
        ([code], []) if !code.is_empty() => Ok(SecretString::new(*code)),
        ([], []) => Err(PurviewError::message(
            "the browser came back without an authorization code",
        )),
        _ => Err(PurviewError::message(
            "the browser came back with an unreadable answer: it held more than one code or \
             error, or an empty code",
        )),
    };
    Callback::Answer(answer)
}

/// Reads a request head, up to the blank line that ends it, the size
/// limit, or the end of the stream.
async fn read_request_head(stream: &mut TcpStream) -> std::io::Result<String> {
    let mut head = Vec::new();
    let mut buffer = [0_u8; 2048];
    while head.len() < MAX_CALLBACK_REQUEST {
        let read = stream.read(&mut buffer).await?;
        if read == 0 {
            break;
        }
        head.extend_from_slice(&buffer[..read]);
        // Bytes after the blank line (a body, or a second request) are not
        // part of the head and are dropped.
        if let Some(end) = head_end(&head) {
            head.truncate(end);
            break;
        }
    }
    head.truncate(MAX_CALLBACK_REQUEST);
    Ok(String::from_utf8_lossy(&head).into_owned())
}

/// Where a request head ends: just after its first blank line, `\r\n\r\n`
/// or a bare `\n\n`, whichever comes first.
fn head_end(bytes: &[u8]) -> Option<usize> {
    let crlf = bytes
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|start| start + 4);
    let lf = bytes
        .windows(2)
        .position(|window| window == b"\n\n")
        .map(|start| start + 2);
    match (crlf, lf) {
        (Some(a), Some(b)) => Some(a.min(b)),
        (found, None) | (None, found) => found,
    }
}

async fn respond(stream: &mut TcpStream, status: &str, body: &str) {
    let response = format!(
        "HTTP/1.1 {status}\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: {}\r\n\
         Cache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\nConnection: close\r\n\r\n\
         {body}",
        body.len()
    );
    // The browser page is a courtesy; a failure to write it changes nothing.
    let _ = stream.write_all(response.as_bytes()).await;
    let _ = stream.shutdown().await;
}

/// Reads and answers one connection to the listener. It gives the sign-in's
/// answer if the request carried this sign-in's `state`, and nothing for
/// any other request, or for a connection that sent no complete request
/// within `CALLBACK_READ_TIMEOUT`.
async fn answer_connection(
    mut stream: TcpStream,
    expected_state: &str,
    redactor: &Redactor,
) -> Option<Result<SecretString>> {
    let head =
        match tokio::time::timeout(CALLBACK_READ_TIMEOUT, read_request_head(&mut stream)).await {
            Ok(Ok(head)) => head,
            _ => return None,
        };
    match classify_callback(&head, expected_state, redactor) {
        Callback::Unrelated => {
            respond(&mut stream, "404 Not Found", "Not found.").await;
            None
        }
        Callback::Foreign => {
            respond(
                &mut stream,
                "400 Bad Request",
                "This answer does not belong to the purview sign-in in progress.",
            )
            .await;
            None
        }
        Callback::Answer(answer) => {
            let (status, body) = match &answer {
                Ok(_) => (
                    "200 OK",
                    "Answer received. Return to the terminal to see whether sign-in \
                     finished, then close this window.",
                ),
                Err(_) => (
                    "400 Bad Request",
                    "The sign-in did not finish. Return to the terminal for the reason.",
                ),
            };
            respond(&mut stream, status, body).await;
            Some(answer)
        }
    }
}

/// Answers connections to the listener until one carries this sign-in's
/// `state`, and returns its authorization code or refusal. Connections are
/// served side by side, because a browser can open a connection it never
/// uses, and that connection must not hold up the one that carries the
/// answer. Past `MAX_CALLBACK_CONNECTIONS` at once, a new connection is
/// closed unread.
async fn receive_callback(
    loopback: &Loopback,
    expected_state: &str,
    redactor: &Arc<Redactor>,
) -> Result<SecretString> {
    let expected_state: Arc<str> = Arc::from(expected_state);
    let mut connections = tokio::task::JoinSet::new();
    loop {
        tokio::select! {
            Some(served) = connections.join_next() => {
                if let Ok(Some(answer)) = served {
                    return answer;
                }
            }
            accepted = loopback.accept() => {
                let stream = match accepted {
                    Ok(stream) => stream,
                    // A connection that went away before it was accepted.
                    Err(error)
                        if matches!(
                            error.kind(),
                            std::io::ErrorKind::ConnectionAborted
                                | std::io::ErrorKind::ConnectionReset
                        ) =>
                    {
                        continue
                    }
                    Err(error) => {
                        return Err(PurviewError::Io(error)
                            .context("the loopback listener for the browser sign-in failed"))
                    }
                };
                if connections.len() >= MAX_CALLBACK_CONNECTIONS {
                    continue;
                }
                let (expected_state, redactor) = (expected_state.clone(), redactor.clone());
                connections.spawn(async move {
                    answer_connection(stream, &expected_state, &redactor).await
                });
            }
        }
    }
}

/// Signs in through the system browser with the authorization code flow
/// and PKCE on a loopback redirect (`docs/SPEC.md` section 3.5, `auth
/// login --browser`), then redeems the refresh token for the download
/// token as the device-code flow does. The address and any warning go to
/// `prompt` (the command's redacted stderr). Nothing is stored here.
pub async fn login_browser(
    identity: &IdentityClient,
    clock: &dyn Clock,
    read_only: bool,
    opener: Arc<dyn BrowserOpener>,
    timeout: Duration,
    prompt: &mut dyn Write,
) -> Result<LoginOutcome> {
    let scope = login_scope(read_only);
    let pkce = Pkce::generate()?;
    identity.redactor.register(pkce.verifier.expose());
    let state = random_urlsafe(24)?;
    let loopback = Loopback::bind().await?;
    let redirect_uri = loopback.redirect_uri();
    let authorize = identity.authorization_url(&redirect_uri, &scope, &state, &pkce.challenge)?;
    writeln!(
        prompt,
        "Opening the browser to sign in. If it does not open, open this address in a browser \
         on this computer:\n{authorize}\nWaiting for sign-in..."
    )?;
    prompt.flush()?;
    // An opener can wait for the browser it starts (`xdg-open` can), so it
    // runs on a thread of its own while the listener waits. The thread is
    // detached: nothing waits for it to end, the runtime included.
    let (sender, mut opened) = tokio::sync::oneshot::channel();
    let thread = std::thread::Builder::new().spawn({
        let authorize = authorize.clone();
        move || {
            let _ = sender.send(opener.open(&authorize));
        }
    });
    let mut waiting_for_opener = true;
    if let Err(error) = thread {
        waiting_for_opener = false;
        warn_if_not_opened(Ok(Err(error)), prompt)?;
    }
    let received = {
        let receiving = tokio::time::timeout(
            timeout,
            receive_callback(&loopback, &state, &identity.redactor),
        );
        tokio::pin!(receiving);
        loop {
            // Biased, so that an opener failure known by the time the answer
            // arrives is reported first.
            tokio::select! {
                biased;
                result = &mut opened, if waiting_for_opener => {
                    waiting_for_opener = false;
                    warn_if_not_opened(result, prompt)?;
                }
                received = &mut receiving => break received,
            }
        }
    };
    if waiting_for_opener {
        if let Ok(result) = opened.try_recv() {
            warn_if_not_opened(Ok(result), prompt)?;
        }
    }
    let code = received.map_err(|_| {
        PurviewError::message(format!(
            "the browser sign-in did not finish within {}; run 'purview auth login --browser' \
             again, or leave out --browser to sign in with a device code",
            describe_duration(timeout)
        ))
    })??;
    // The listener closes before the code is redeemed.
    drop(loopback);
    let token = identity
        .exchange_code(&code, &redirect_uri, &pkce.verifier, &scope)
        .await?;
    complete_login(identity, clock, token, &scope).await
}

/// Warns that the browser did not open. A closed channel means the opener
/// panicked.
fn warn_if_not_opened(
    opened: std::result::Result<std::io::Result<()>, tokio::sync::oneshot::error::RecvError>,
    prompt: &mut dyn Write,
) -> Result<()> {
    let failure = match opened {
        Ok(Ok(())) => return Ok(()),
        Ok(Err(error)) => error.to_string(),
        Err(_) => "the opener stopped without an answer".to_owned(),
    };
    writeln!(
        prompt,
        "warning: could not open the browser ({}); open the address above",
        sanitize(&failure)
    )?;
    prompt.flush()?;
    Ok(())
}

fn describe_duration(duration: Duration) -> String {
    let seconds = duration.as_secs();
    if seconds == 60 {
        "1 minute".to_owned()
    } else if seconds > 60 && seconds.is_multiple_of(60) {
        format!("{} minutes", seconds / 60)
    } else {
        format!("{seconds} seconds")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id_token(claims: Value) -> SecretString {
        let encode = |value: &Value| {
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(value.to_string())
        };
        SecretString::new(format!(
            "{}.{}.",
            encode(&serde_json::json!({"alg": "none"})),
            encode(&claims)
        ))
    }

    #[test]
    fn login_scopes_follow_read_only() {
        assert_eq!(
            login_scope(false),
            "https://graph.microsoft.com/eDiscovery.ReadWrite.All offline_access openid profile"
        );
        assert_eq!(
            login_scope(true),
            "https://graph.microsoft.com/eDiscovery.Read.All offline_access openid profile"
        );
        assert_eq!(
            download_scope(),
            "b26e684c-5068-4120-a679-64a5d2c909d9/.default offline_access"
        );
    }

    #[test]
    fn a_refresh_asks_for_the_stored_scopes_and_nothing_more() {
        assert_eq!(
            graph_refresh_scope("eDiscovery.Read.All openid profile email"),
            "https://graph.microsoft.com/eDiscovery.Read.All openid profile email offline_access"
        );
        assert_eq!(graph_refresh_scope(&login_scope(false)), login_scope(false));
        assert_eq!(
            graph_refresh_scope(
                "https://graph.microsoft.com/eDiscovery.ReadWrite.All eDiscovery.ReadWrite.All"
            ),
            "https://graph.microsoft.com/eDiscovery.ReadWrite.All offline_access"
        );
    }

    #[test]
    fn the_account_is_preferred_username_then_upn_then_email() {
        let all = account_claims(Some(&id_token(serde_json::json!({
            "preferred_username": "Alex@Contoso.Example",
            "upn": "alex.w@contoso.example",
            "email": "other@contoso.example",
            "tid": "00000000-0000-4000-8000-000000000002",
            "oid": "00000000-0000-4000-8000-000000000011",
            "name": "Alex Wilber"
        }))))
        .unwrap();
        assert_eq!(all.account, "alex@contoso.example");
        assert_eq!(all.upn.as_deref(), Some("alex.w@contoso.example"));
        assert_eq!(all.name.as_deref(), Some("Alex Wilber"));
        assert_eq!(all.tid, "00000000-0000-4000-8000-000000000002");

        let upn_only = account_claims(Some(&id_token(serde_json::json!({
            "preferred_username": " ",
            "upn": "Sam@Contoso.Example"
        }))))
        .unwrap();
        assert_eq!(upn_only.account, "sam@contoso.example");
        assert_eq!(upn_only.name, None);

        let email_only = account_claims(Some(&id_token(serde_json::json!({
            "email": "guest@fabrikam.example"
        }))))
        .unwrap();
        assert_eq!(email_only.account, "guest@fabrikam.example");
        assert_eq!(email_only.upn, None);
    }

    #[test]
    fn no_account_claim_or_no_readable_id_token_is_no_account_claim() {
        let none = account_claims(Some(&id_token(serde_json::json!({"name": "Nobody"}))));
        assert_eq!(none.unwrap_err().metadata(), ("NoAccountClaim", 0));
        for token in [None, Some(SecretString::new("not-a-jwt"))] {
            let error = account_claims(token.as_ref()).unwrap_err();
            assert_eq!(error.metadata(), ("NoAccountClaim", 0));
        }
    }

    #[test]
    fn the_poll_timer_is_bounded_only_by_the_code_lifetime() {
        // A cap such as the old 30-second one would shorten these.
        for remaining in [
            Duration::from_secs(31),
            Duration::from_secs(900),
            Duration::ZERO,
        ] {
            assert_eq!(poll_bound(remaining), remaining);
        }
    }

    #[test]
    fn ids_must_be_guids() {
        assert!(validate_client_id("00000000-0000-4000-8000-000000000001").is_ok());
        assert!(validate_client_id("purview").is_err());
        assert!(validate_tenant_id("organizations").is_err());
        assert!(validate_tenant_id("common").is_err());
    }

    #[test]
    fn token_lifetimes_are_bounded_and_accept_strings() {
        let parse = |body: Value| serde_json::from_value::<TokenResponse>(body).unwrap();
        assert_eq!(
            parse(serde_json::json!({"access_token": "a", "expires_in": "1800"}))
                .lifetime_seconds(),
            1800
        );
        assert_eq!(
            parse(serde_json::json!({"access_token": "a", "expires_in": 0})).lifetime_seconds(),
            3600
        );
        assert_eq!(
            parse(serde_json::json!({"access_token": "a", "expires_in": 999_999}))
                .lifetime_seconds(),
            3600
        );
    }

    #[test]
    fn debug_of_a_token_response_shows_no_secret() {
        let response: TokenResponse = serde_json::from_value(serde_json::json!({
            "access_token": "canary-access-0001",
            "refresh_token": "canary-refresh-0001",
            "id_token": "canary-id-0001",
            "expires_in": 3600
        }))
        .unwrap();
        let shown = format!("{response:?}");
        assert!(!shown.contains("canary"), "{shown}");
        let code: DeviceCodeResponse = serde_json::from_value(serde_json::json!({
            "device_code": "canary-device-0001",
            "user_code": "ABCD-EFGH",
            "verification_uri": "https://login.microsoftonline.com/device"
        }))
        .unwrap();
        let shown = format!("{code:?}");
        assert!(!shown.contains("canary"), "{shown}");
    }

    #[test]
    fn the_pkce_challenge_matches_the_rfc_7636_example() {
        // RFC 7636 appendix B.
        assert_eq!(
            pkce_challenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
    }

    #[test]
    fn a_pkce_verifier_is_43_unreserved_characters_and_never_repeats() {
        let first = Pkce::generate().unwrap();
        let second = Pkce::generate().unwrap();
        for pkce in [&first, &second] {
            let verifier = pkce.verifier.expose();
            assert_eq!(verifier.len(), 43, "{verifier}");
            assert!(verifier
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'));
            assert_eq!(pkce.challenge, pkce_challenge(verifier));
        }
        assert_ne!(first.verifier.expose(), second.verifier.expose());
        assert_ne!(random_urlsafe(24).unwrap(), random_urlsafe(24).unwrap());
    }

    fn callback(target: &str, redactor: &Redactor) -> Callback {
        classify_callback(
            &format!("GET {target} HTTP/1.1\r\nHost: localhost\r\n\r\n"),
            "expected",
            redactor,
        )
    }

    #[test]
    fn a_callback_with_this_state_gives_its_code_and_registers_it() {
        let redactor = Redactor::new();
        match callback("/callback?code=canary-code-0001&state=expected", &redactor) {
            Callback::Answer(Ok(code)) => assert_eq!(code.expose(), "canary-code-0001"),
            other => panic!("{other:?}"),
        }
        assert!(!redactor.redact("canary-code-0001").contains("canary"));
    }

    #[test]
    fn requests_that_are_not_the_redirect_are_unrelated() {
        let redactor = Redactor::new();
        for target in [
            "/favicon.ico",
            "/callback/extra?code=abc&state=expected",
            "/",
            "http://localhost/callback?code=abc&state=expected",
            "//callback?code=abc&state=expected",
            "/./callback?code=abc&state=expected",
            "/callback%3F?code=abc&state=expected",
            "/CALLBACK?code=abc&state=expected",
        ] {
            assert!(
                matches!(callback(target, &redactor), Callback::Unrelated),
                "{target}"
            );
        }
        for head in [
            "POST /callback?code=abc&state=expected HTTP/1.1\r\n\r\n",
            "GET /callback?code=abc&state=expected\r\n\r\n",
            // Incomplete: no blank line ends the head.
            "GET /callback?code=abc&state=expected HTTP/1.1\r\nHost: localhost\r\n",
            "GET /callback?code=abc&state=expected HTTP/2\r\n\r\n",
            "GET /callback?code=abc&state=expected HTTP/1.1 extra\r\n\r\n",
            "GET  /callback?code=abc&state=expected HTTP/1.1\r\n\r\n",
            "",
            "\u{16}\u{3}\u{1}",
        ] {
            assert!(
                matches!(
                    classify_callback(head, "expected", &redactor),
                    Callback::Unrelated
                ),
                "{head:?}"
            );
        }
    }

    #[test]
    fn a_callback_without_exactly_this_state_is_foreign_whatever_it_holds() {
        let redactor = Redactor::new();
        for target in [
            "/callback?code=canary-code-0002&state=other",
            "/callback?code=abc",
            "/callback?error=access_denied&state=other",
            "/callback?code=abc&state=expected&state=other",
            "/callback?code=abc&state=expected&state=expected",
            "/callback?code=abc&state=Expected",
        ] {
            assert!(
                matches!(callback(target, &redactor), Callback::Foreign),
                "{target}"
            );
        }
        // A foreign request's values are not registered: nothing reads them,
        // and a registered value would make later writes that hold it fail.
        assert_eq!(redactor.redact("canary-code-0002"), "canary-code-0002");
    }

    #[test]
    fn a_refusal_with_this_state_reports_the_platforms_reason_cleaned() {
        let redactor = Redactor::new();
        redactor.register("canary-secret-0001");
        let target = "/callback?state=expected&error=access_denied\
            &error_description=AADSTS65004%3A+declined%1b%5B31m+canary-secret-0001";
        let message = match callback(target, &redactor) {
            Callback::Answer(Err(error)) => error.to_string(),
            other => panic!("{other:?}"),
        };
        assert!(
            message.starts_with("the browser sign-in was refused: access_denied: AADSTS65004"),
            "{message}"
        );
        assert!(!message.contains('\u{1b}'), "{message}");
        assert!(!message.contains("canary"), "{message}");

        let long = format!(
            "/callback?state=expected&error=x&error_description={}",
            "a".repeat(5_000)
        );
        let message = match callback(&long, &redactor) {
            Callback::Answer(Err(error)) => error.to_string(),
            other => panic!("{other:?}"),
        };
        assert!(
            message.len() < MAX_CALLBACK_DESCRIPTION + 100,
            "{}",
            message.len()
        );
    }

    #[test]
    fn a_head_ends_at_its_first_blank_line() {
        let request = b"GET /callback?state=x HTTP/1.1\r\nHost: localhost\r\n\r\nGET /other";
        let end = head_end(request).unwrap();
        assert!(request[..end].ends_with(b"\r\n\r\n"));
        assert_eq!(&request[end..], b"GET /other");
        assert_eq!(head_end(b"GET / HTTP/1.1\n\nrest"), Some(16));
        assert_eq!(head_end(b"GET / HTTP/1.1\r\nHost: x\r\n"), None);
    }

    #[test]
    fn a_callback_with_this_state_but_no_single_code_is_an_error() {
        let redactor = Redactor::new();
        for target in [
            "/callback?state=expected",
            "/callback?state=expected&code=",
            "/callback?state=expected&code=a&code=b",
            "/callback?state=expected&code=a&error=x",
            "/callback?state=expected&error=x&error=y",
        ] {
            assert!(
                matches!(callback(target, &redactor), Callback::Answer(Err(_))),
                "{target}"
            );
        }
    }

    #[test]
    fn an_ipv6_port_held_elsewhere_is_given_up_and_other_failures_fall_back() {
        use std::io::ErrorKind;
        assert!(ipv6_port_taken(ErrorKind::AddrInUse));
        // Windows: an address held with SO_EXCLUSIVEADDRUSE (WSAEACCES).
        assert!(ipv6_port_taken(ErrorKind::PermissionDenied));
        for unavailable in [
            ErrorKind::AddrNotAvailable,
            ErrorKind::Unsupported,
            ErrorKind::Other,
        ] {
            assert!(!ipv6_port_taken(unavailable), "{unavailable:?}");
        }
    }

    #[tokio::test]
    async fn the_loopback_listener_takes_one_port_on_both_loopback_addresses() {
        let loopback = Loopback::bind().await.unwrap();
        // macOS always has IPv6 loopback, so there the second listener must
        // exist; elsewhere it may not.
        if cfg!(target_os = "macos") {
            assert!(loopback.v6.is_some());
        }
        assert_eq!(loopback.v4.local_addr().unwrap().port(), loopback.port);
        if let Some(v6) = &loopback.v6 {
            let address = v6.local_addr().unwrap();
            assert!(address.ip().is_loopback());
            assert_eq!(address.port(), loopback.port);
        }
        assert_eq!(
            loopback.redirect_uri(),
            format!("http://localhost:{}/callback", loopback.port)
        );
    }

    #[test]
    fn durations_are_described_in_minutes_when_whole() {
        assert_eq!(describe_duration(BROWSER_TIMEOUT), "15 minutes");
        assert_eq!(describe_duration(Duration::from_secs(60)), "1 minute");
        assert_eq!(describe_duration(Duration::from_millis(200)), "0 seconds");
        assert_eq!(describe_duration(Duration::from_secs(90)), "90 seconds");
    }
}
