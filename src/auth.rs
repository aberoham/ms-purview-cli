//! Sign-in against the Microsoft identity platform: the device-code flow,
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
use std::sync::Arc;
use std::time::Duration;

use base64::Engine;
use reqwest::StatusCode;
use serde::{Deserialize, Deserializer};
use serde_json::Value;
use url::Url;
use uuid::Uuid;

use crate::config::AccountRecord;
use crate::env::Clock;
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
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
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

/// The scope for a Graph refresh: exactly the scopes stored with the token,
/// with any short Graph permission name given its resource prefix, and
/// `offline_access` added if the stored list lacks it. It never adds a
/// permission, so a refresh cannot widen a session; and it never drops
/// one, so it cannot narrow it.
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
        redactor: Arc<Redactor>,
    ) -> Result<Self> {
        Ok(Self {
            http: reqwest::Client::builder()
                .timeout(REQUEST_TIMEOUT)
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
    async fn poll_device_code(
        &self,
        code: &DeviceCodeResponse,
        clock: &dyn Clock,
    ) -> Result<TokenResponse> {
        let operation = "signing in with the device code";
        let mut interval = code.interval.unwrap_or(5).clamp(1, 120);
        let lifetime = code.expires_in.unwrap_or(900).clamp(1, 3_600);
        let deadline = clock.now() + chrono::Duration::seconds(lifetime as i64);
        loop {
            clock.sleep(Duration::from_secs(interval)).await;
            if clock.now() >= deadline {
                return Err(expired_device_code());
            }
            let form = [
                ("client_id", self.client_id.as_str()),
                ("grant_type", DEVICE_CODE_GRANT),
                ("device_code", code.device_code.expose()),
            ];
            let (status, body) = self.post("token", &form).await?;
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
        Ok((status, body))
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
    writeln!(
        prompt,
        "To sign in, open {} in a browser and enter the code {}\nWaiting for sign-in...",
        sanitize(&code.verification_uri),
        sanitize(&code.user_code)
    )?;
    prompt.flush()?;
    let token = identity.poll_device_code(&code, clock).await?;
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
    let mut credential = Credential {
        email: claims.account.clone(),
        refresh_token,
        graph: AccessToken::from_response(&token, clock.now(), &scope),
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
        tenant_id: if claims.tid.is_empty() {
            identity.tenant_id().to_owned()
        } else {
            claims.tid
        },
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
}
