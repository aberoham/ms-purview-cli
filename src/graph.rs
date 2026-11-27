//! `GraphClient`, the only Microsoft Graph transport (`docs/SPEC.md`
//! section 4.3).
//!
//! - A request goes out only when its URL has exactly the Graph origin
//!   and lies below the Graph base path; paging links are checked the same
//!   way. Redirects are disabled.
//! - Reads are built from `routes::ReadRoute`, and every read is a `GET`.
//!   The only other request is `send_write`, which takes a
//!   `safety::ApprovedWrite` and sends its one `POST` exactly as approved.
//!   A POST is never sent again: an outcome that is not clear is
//!   `WriteOutcomeUnknown` (`docs/SPEC.md` section 4.3).
//! - A GET makes at most `MAX_GET_ATTEMPTS` attempts, every send counted.
//!   It is retried after a connection error, a timeout, a truncated body,
//!   or HTTP 429, 500, 502, 503 or 504, waiting for `Retry-After` (seconds
//!   or an HTTP date) or else 250 ms × 2^(attempt − 1), at most 30 s. The
//!   first 401 makes the token provider refresh, and the GET is sent again
//!   if an attempt is left.
//! - The client holds no token: each attempt asks the `TokenProvider`.
//! - Responses are read up to `MAX_RESPONSE_BYTES`.

use std::io::Write;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use reqwest::header::{HeaderMap, ACCEPT, CONTENT_TYPE, LOCATION, RETRY_AFTER};
use reqwest::StatusCode;
use serde::Deserialize;
use serde_json::Value;
use url::Url;

use crate::env::Clock;
use crate::error::{GraphErrorDetails, PurviewError, Result};
use crate::origin::Origin;
use crate::output::sanitize;
use crate::redact::{self, Redactor};
use crate::routes::{build_url, Query, ReadRoute};
use crate::safety::{ApprovedWrite, WritePlan};
use crate::token::TokenProvider;
use crate::trace::{Exchange, TraceSink, TracedBody, TracedResponse};

/// The largest Graph response body read.
pub const MAX_RESPONSE_BYTES: usize = 8 * 1024 * 1024;
/// Attempts for one GET, the first included.
pub const MAX_GET_ATTEMPTS: u32 = 3;
/// Pages followed for one list.
pub const MAX_PAGES: usize = 200;
/// The longest back-off between attempts when Graph names no time.
pub const MAX_BACKOFF: Duration = Duration::from_secs(30);
/// The longest `Retry-After` the client waits for. Graph asking for longer
/// ends the GET with Graph's error instead of a wait the person cannot see
/// the end of.
pub const MAX_RETRY_AFTER: Duration = Duration::from_secs(60);
/// A GET's token must stay valid at least this long (`docs/SPEC.md`
/// section 4.5).
pub const GET_TOKEN_VALIDITY: Duration = Duration::from_secs(60);
/// A POST's token must stay valid at least this long (`docs/SPEC.md`
/// section 4.5), so that a 401 should not happen.
pub const POST_TOKEN_VALIDITY: Duration = Duration::from_secs(300);
/// `--timeout 0`, and no `--timeout`, mean this.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(60);
/// The largest `--timeout`.
pub const MAX_TIMEOUT_SECONDS: u64 = 600;

/// How a client is set up, from `Env` and the global flags.
#[derive(Debug, Clone)]
pub struct GraphSettings {
    /// `origin::GRAPH_BASE` in production, a mock origin in tests.
    pub base: Url,
    /// Per-request timeout, the body included.
    pub timeout: Duration,
    /// Log each request and its outcome on the command's stderr.
    pub verbose: bool,
    pub trace: Option<Arc<TraceSink>>,
}

/// One page of a Graph collection. Each element stays raw JSON, so one bad
/// element cannot fail the list (`docs/SPEC.md` section 7.1).
#[derive(Debug, Clone, PartialEq)]
pub struct Page {
    pub value: Vec<Value>,
    /// `@odata.nextLink`, already checked against the Graph origin and
    /// base path.
    pub next_link: Option<Url>,
}

/// Why a list stopped before its last page.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ListStop {
    /// A paging link repeated one already followed.
    RepeatedLink,
    /// `MAX_PAGES` pages were read and Graph still offered another.
    PageLimit,
}

/// Every element of a collection, across pages, and whether the last page
/// was reached.
#[derive(Debug, Clone, PartialEq)]
pub struct Listing {
    pub items: Vec<Value>,
    /// `None` when the last page was read.
    pub stopped: Option<ListStop>,
}

impl Listing {
    /// The items, or an error when the list did not reach its last page.
    /// A read whose decision depends on the whole list, such as a hold
    /// check, uses this.
    pub fn complete(self) -> Result<Vec<Value>> {
        match self.stopped {
            None => Ok(self.items),
            Some(ListStop::RepeatedLink) => Err(PurviewError::message(
                "Graph's paging repeated a link before the list ended, so the list is incomplete",
            )),
            Some(ListStop::PageLimit) => Err(PurviewError::message(format!(
                "the list did not end within {MAX_PAGES} pages, so it is incomplete"
            ))),
        }
    }
}

/// The Graph transport. It holds the token provider, never a token.
pub struct GraphClient {
    http: reqwest::Client,
    base: Url,
    origin: Origin,
    tokens: Arc<dyn TokenProvider>,
    redactor: Arc<Redactor>,
    clock: Arc<dyn Clock>,
    verbose: bool,
    trace: Option<Arc<TraceSink>>,
    trace_failed: AtomicBool,
}

impl std::fmt::Debug for GraphClient {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("GraphClient")
            .field("base", &self.base.as_str())
            .field("verbose", &self.verbose)
            .finish_non_exhaustive()
    }
}

/// Graph's answer to an approved write that it accepted.
#[derive(Debug, Clone, PartialEq)]
pub struct WriteResponse {
    pub status: u16,
    /// The `Location` header, as given; an action names its operation
    /// there (`docs/SPEC.md` section 4.4).
    pub location: Option<String>,
    /// The body, when it is a JSON object; a 202 has none.
    pub body: Option<Value>,
}

/// What one attempt produced.
enum Attempt {
    Response {
        status: StatusCode,
        headers: HeaderMap,
        body: Vec<u8>,
    },
    /// No complete response: the connection failed, the request timed out
    /// or the body was cut off. Retried.
    Transient(String),
    /// A response that is refused without a retry.
    Refused(PurviewError),
}

impl GraphClient {
    pub fn new(
        settings: GraphSettings,
        tokens: Arc<dyn TokenProvider>,
        redactor: Arc<Redactor>,
        clock: Arc<dyn Clock>,
    ) -> Result<Self> {
        let origin = Origin::of(&settings.base).ok_or_else(|| {
            PurviewError::message("the Graph base URL has no origin a request may go to")
        })?;
        if !settings.base.path().ends_with('/') {
            return Err(PurviewError::message(
                "the Graph base URL must end with a slash",
            ));
        }
        Ok(Self {
            http: reqwest::Client::builder()
                .timeout(settings.timeout)
                .redirect(reqwest::redirect::Policy::none())
                .user_agent(concat!("purview/", env!("CARGO_PKG_VERSION")))
                .build()?,
            base: settings.base,
            origin,
            tokens,
            redactor,
            clock,
            verbose: settings.verbose,
            trace: settings.trace,
            trace_failed: AtomicBool::new(false),
        })
    }

    /// The URL a read route addresses.
    pub fn url(&self, route: &ReadRoute, query: &Query) -> Result<Url> {
        build_url(&self.base, &route.segments(), query)
    }

    /// One GET of `route`; the body must be a JSON object.
    pub async fn get(
        &self,
        route: &ReadRoute,
        query: &Query,
        log: &mut (dyn Write + Send),
    ) -> Result<Value> {
        let url = self.url(route, query)?;
        self.get_url(&url, log).await
    }

    /// The first page of a collection.
    pub async fn get_page(
        &self,
        route: &ReadRoute,
        query: &Query,
        log: &mut (dyn Write + Send),
    ) -> Result<Page> {
        let body = self.get(route, query, log).await?;
        self.page(body)
    }

    /// Every page of a collection, following `@odata.nextLink` on the Graph
    /// origin only. It stops at a repeated link and after `MAX_PAGES`
    /// pages, and says so in `Listing::stopped`.
    pub async fn list(
        &self,
        route: &ReadRoute,
        query: &Query,
        log: &mut (dyn Write + Send),
    ) -> Result<Listing> {
        match self.list_partial(route, query, log).await {
            (listing, None) => Ok(listing),
            (_, Some(error)) => Err(error),
        }
    }

    /// `list`, keeping the items of the pages read before a page failed,
    /// with that failure. For reconciliation after an unclear write, where
    /// a candidate on an earlier page is worth showing; a decision that
    /// needs the whole list uses `list`.
    pub async fn list_partial(
        &self,
        route: &ReadRoute,
        query: &Query,
        log: &mut (dyn Write + Send),
    ) -> (Listing, Option<PurviewError>) {
        let mut items = Vec::new();
        let mut url = match self.url(route, query) {
            Ok(url) => url,
            Err(error) => {
                return (
                    Listing {
                        items,
                        stopped: None,
                    },
                    Some(error),
                )
            }
        };
        let mut seen = std::collections::HashSet::new();
        for _ in 0..MAX_PAGES {
            seen.insert(url.as_str().to_owned());
            let page = match self
                .get_url(&url, log)
                .await
                .and_then(|body| self.page(body))
            {
                Ok(page) => page,
                Err(error) => {
                    return (
                        Listing {
                            items,
                            stopped: None,
                        },
                        Some(error),
                    )
                }
            };
            items.extend(page.value);
            match page.next_link {
                None => {
                    return (
                        Listing {
                            items,
                            stopped: None,
                        },
                        None,
                    )
                }
                Some(next) if seen.contains(next.as_str()) => {
                    return (
                        Listing {
                            items,
                            stopped: Some(ListStop::RepeatedLink),
                        },
                        None,
                    )
                }
                Some(next) => url = next,
            }
        }
        (
            Listing {
                items,
                stopped: Some(ListStop::PageLimit),
            },
            None,
        )
    }

    /// A collection page from a response body.
    fn page(&self, mut body: Value) -> Result<Page> {
        let value = match body.get_mut("value").map(Value::take) {
            Some(Value::Array(items)) => items,
            _ => {
                return Err(PurviewError::message(
                    "Graph's list response has no value array",
                ))
            }
        };
        let next_link = match body.get("@odata.nextLink") {
            None | Some(Value::Null) => None,
            Some(Value::String(text)) => Some(self.checked(text, "paging link")?),
            Some(_) => return Err(PurviewError::message("Graph's paging link is not a string")),
        };
        Ok(Page { value, next_link })
    }

    /// `text` as a URL a request may go to: on the Graph origin and below
    /// the Graph base path.
    fn checked(&self, text: &str, what: &'static str) -> Result<Url> {
        let url = Url::parse(text)
            .map_err(|_| PurviewError::message(format!("Graph's {what} is not a URL")))?;
        if !self.admits(&url) {
            return Err(PurviewError::ForeignOrigin {
                what,
                url: sanitize(&self.redactor.redact(&redact::url(&url, &self.redactor))),
            });
        }
        Ok(url)
    }

    fn admits(&self, url: &Url) -> bool {
        self.origin.admits(url) && url.path().starts_with(self.base.path())
    }

    /// The retry loop for one GET.
    async fn get_url(&self, url: &Url, log: &mut (dyn Write + Send)) -> Result<Value> {
        if !self.admits(url) {
            return Err(PurviewError::ForeignOrigin {
                what: "request URL",
                url: sanitize(&self.redactor.redact(&redact::url(url, &self.redactor))),
            });
        }
        let shown = sanitize(&self.redactor.redact(&redact::url(url, &self.redactor)));
        let mut attempt = 1;
        let mut refreshed_after_401 = false;
        loop {
            let token = self
                .tokens
                .graph(GET_TOKEN_VALIDITY)
                .await
                .map_err(|error| {
                    // What the provider tried before it failed is still
                    // worth showing.
                    self.log_notes(log);
                    PurviewError::TokenUnavailable(Box::new(error))
                })?;
            self.log_notes(log);
            self.log(log, &format!("GET {shown}"));
            let started = self.clock.elapsed();
            let outcome = self.attempt(url, token.expose()).await;
            drop(token);
            let took = self.clock.elapsed().saturating_sub(started);
            self.record(url, &outcome, log);
            let (status, headers, body) = match outcome {
                Attempt::Response {
                    status,
                    headers,
                    body,
                } => (status, headers, body),
                Attempt::Refused(error) => return Err(error),
                Attempt::Transient(reason) => {
                    self.log(log, &format!("{reason} after {} ms", took.as_millis()));
                    if attempt < MAX_GET_ATTEMPTS {
                        let wait = backoff(attempt);
                        self.log_retry(log, &wait, attempt);
                        self.clock.sleep(wait).await;
                        attempt += 1;
                        continue;
                    }
                    return Err(PurviewError::GraphUnreachable {
                        reason,
                        attempts: attempt,
                    });
                }
            };
            self.log(
                log,
                &format!(
                    "HTTP {} in {} ms{}",
                    status.as_u16(),
                    took.as_millis(),
                    header_text(&headers, "request-id")
                        .map(|id| format!(", request-id {}", sanitize(&self.redactor.redact(&id))))
                        .unwrap_or_default()
                ),
            );
            if status.is_success() {
                return match serde_json::from_slice::<Value>(&body) {
                    Ok(value @ Value::Object(_)) => Ok(value),
                    _ => Err(PurviewError::message(
                        "Microsoft Graph returned a response that is not a JSON object",
                    )),
                };
            }
            if status == StatusCode::UNAUTHORIZED
                && !refreshed_after_401
                && attempt < MAX_GET_ATTEMPTS
            {
                refreshed_after_401 = true;
                self.log(log, "refreshing the Graph token after HTTP 401");
                self.tokens.invalidate_graph().await;
                attempt += 1;
                continue;
            }
            if is_retryable(status) && attempt < MAX_GET_ATTEMPTS {
                match self.retry_wait(&headers, attempt) {
                    Ok(wait) => {
                        self.log_retry(log, &wait, attempt);
                        self.clock.sleep(wait).await;
                        attempt += 1;
                        continue;
                    }
                    Err(asked) => {
                        return Err(self.graph_error(status, &headers, &body).context(format!(
                            "Graph asked to retry after {} seconds, longer than the {}-second \
                             limit",
                            asked.as_secs() + u64::from(asked.subsec_nanos() > 0),
                            MAX_RETRY_AFTER.as_secs()
                        )));
                    }
                }
            }
            return Err(self.graph_error(status, &headers, &body));
        }
    }

    /// Sends the approved POST once: the method, path and bytes in the
    /// plan, nothing else. A 2xx with a readable body is the response. Any
    /// other 4xx is Graph's error, and the write was not applied. No
    /// response, a timeout, 429 or a 5xx leave the outcome unknown, as does
    /// a 2xx whose body cannot be read: each is `WriteOutcomeUnknown`, and
    /// the request is never sent again, whatever `Retry-After` says. A
    /// connection that could not be opened sent nothing and is
    /// `GraphUnreachable`.
    pub(crate) async fn send_write(
        &self,
        write: ApprovedWrite,
        log: &mut (dyn Write + Send),
    ) -> Result<(WritePlan, WriteResponse)> {
        let url = build_url(&self.base, &write.route().segments(), &Query::new())?;
        if !self.admits(&url) {
            return Err(PurviewError::ForeignOrigin {
                what: "request URL",
                url: sanitize(&self.redactor.redact(&redact::url(&url, &self.redactor))),
            });
        }
        let token = self
            .tokens
            .graph(POST_TOKEN_VALIDITY)
            .await
            .map_err(|error| {
                self.log_notes(log);
                PurviewError::TokenUnavailable(Box::new(error))
            })?;
        self.log_notes(log);
        let shown = sanitize(&self.redactor.redact(&redact::url(&url, &self.redactor)));
        self.log(log, &format!("{} {shown}", write.method()));
        let started = self.clock.elapsed();
        let sent = self
            .http
            .post(url.clone())
            .bearer_auth(token.expose())
            .header(ACCEPT, "application/json")
            .header(CONTENT_TYPE, "application/json")
            .body(write.body().to_vec())
            .send()
            .await;
        drop(token);
        let response =
            match sent {
                Ok(response) => response,
                Err(error) if error.is_builder() => return Err(PurviewError::message(
                    "the Graph request could not be built: the stored Graph token is not a valid \
                     header value; nothing was sent. Run 'purview auth login' again",
                )),
                Err(error) if error.is_connect() => {
                    let reason = transport_failure(&error);
                    self.record_write(&url, &write, None, Some(&reason), log);
                    return Err(PurviewError::GraphUnreachable {
                        reason,
                        attempts: 1,
                    });
                }
                Err(error) => {
                    let reason = transport_failure(&error);
                    self.record_write(&url, &write, None, Some(&reason), log);
                    self.log(log, &reason);
                    return Err(unknown(format!("{reason} before Graph answered")));
                }
            };
        let status = response.status();
        let headers = response.headers().clone();
        let body = match read_body(response).await {
            Ok(body) => Some(body),
            Err(reason) => {
                self.log(log, &reason);
                None
            }
        };
        let took = self.clock.elapsed().saturating_sub(started);
        self.record_write(
            &url,
            &write,
            Some((status, &headers, body.as_deref().unwrap_or_default())),
            None,
            log,
        );
        self.log(
            log,
            &format!(
                "HTTP {} in {} ms{}",
                status.as_u16(),
                took.as_millis(),
                header_text(&headers, "request-id")
                    .map(|id| format!(", request-id {}", sanitize(&self.redactor.redact(&id))))
                    .unwrap_or_default()
            ),
        );
        if status.is_success() {
            let Some(body) = body else {
                return Err(unknown(format!(
                    "Graph accepted the request (HTTP {}), but its response could not be read",
                    status.as_u16()
                )));
            };
            let body = match serde_json::from_slice::<Value>(&body) {
                Ok(value @ Value::Object(_)) => Some(value),
                // An empty answer is expected only where Graph sends no
                // object; a create that answers with nothing is unclear.
                _ if body.iter().all(u8::is_ascii_whitespace)
                    && !write.route().answers_with_object() =>
                {
                    None
                }
                _ => {
                    return Err(unknown(format!(
                        "Graph accepted the request (HTTP {}), but its response is not a JSON \
                         object",
                        status.as_u16()
                    )))
                }
            };
            return Ok((
                write.into_plan(),
                WriteResponse {
                    status: status.as_u16(),
                    location: header_text(&headers, LOCATION.as_str()),
                    body,
                },
            ));
        }
        let error = self.graph_error(status, &headers, body.as_deref().unwrap_or_default());
        // A redirect is not followed, and the POST before it may have been
        // processed (a 303 says so), so it is unclear too.
        // Only a client error says the request was refused; 408 and 429
        // say nothing about whether it ran.
        let refused = status.is_client_error()
            && status != StatusCode::REQUEST_TIMEOUT
            && status != StatusCode::TOO_MANY_REQUESTS;
        if !refused {
            return Err(unknown(format!(
                "Graph answered HTTP {} ({})",
                status.as_u16(),
                error
            )));
        }
        Err(error)
    }

    /// Writes a POST exchange to the trace, its body included.
    fn record_write(
        &self,
        url: &Url,
        write: &ApprovedWrite,
        response: Option<(StatusCode, &HeaderMap, &[u8])>,
        error: Option<&str>,
        log: &mut (dyn Write + Send),
    ) {
        let Some(trace) = &self.trace else {
            return;
        };
        let request_body = serde_json::from_slice::<Value>(write.body()).ok();
        let exchange = Exchange {
            method: write.method(),
            url,
            request_body: request_body.as_ref(),
            response: response.map(|(status, headers, body)| TracedResponse {
                status: status.as_u16(),
                headers,
                body: TracedBody::Json(body),
            }),
            error,
        };
        if let Err(error) = trace.record(&exchange) {
            if !self.trace_failed.swap(true, Ordering::Relaxed) {
                let _ = writeln!(
                    log,
                    "warning: could not write a trace file: {}",
                    sanitize(&error.to_string())
                );
            }
        }
    }

    /// Sends one GET and reads its body. For a success, a body that is cut
    /// off or times out is transient and one over the limit is refused. For
    /// any other status the status and headers are what matter (a 403
    /// stays a 403, and a 503 keeps its `Retry-After`), so a body that
    /// cannot be read in full is dropped and the response kept.
    async fn attempt(&self, url: &Url, token: &str) -> Attempt {
        let response = match self
            .http
            .get(url.clone())
            .bearer_auth(token)
            .header(ACCEPT, "application/json")
            .send()
            .await
        {
            Ok(response) => response,
            // A request that cannot be built (in practice, a stored token
            // that is not a valid header value) fails the same way again.
            Err(error) if error.is_builder() => {
                return Attempt::Refused(PurviewError::message(
                    "the Graph request could not be built: the stored Graph token is not a valid \
                     header value; run 'purview auth login' again",
                ))
            }
            Err(error) => return Attempt::Transient(transport_failure(&error)),
        };
        let status = response.status();
        let headers = response.headers().clone();
        let success = status.is_success();
        let kept = |status, headers| Attempt::Response {
            status,
            headers,
            body: Vec::new(),
        };
        if response
            .content_length()
            .is_some_and(|length| length > MAX_RESPONSE_BYTES as u64)
        {
            return if success {
                Attempt::Refused(too_large())
            } else {
                kept(status, headers)
            };
        }
        let mut response = response;
        let mut body = Vec::new();
        loop {
            match response.chunk().await {
                Ok(Some(chunk)) => {
                    if body.len().saturating_add(chunk.len()) > MAX_RESPONSE_BYTES {
                        return if success {
                            Attempt::Refused(too_large())
                        } else {
                            kept(status, headers)
                        };
                    }
                    body.extend_from_slice(&chunk);
                }
                Ok(None) => break,
                Err(_) if !success => return kept(status, headers),
                Err(error) if error.is_timeout() => {
                    return Attempt::Transient("the response timed out".to_owned())
                }
                Err(_) => return Attempt::Transient("the response was cut off".to_owned()),
            }
        }
        Attempt::Response {
            status,
            headers,
            body,
        }
    }

    /// How long to wait before the next attempt, or the wait Graph asked
    /// for when it is longer than `MAX_RETRY_AFTER`.
    fn retry_wait(
        &self,
        headers: &HeaderMap,
        attempt: u32,
    ) -> std::result::Result<Duration, Duration> {
        match header_text(headers, RETRY_AFTER.as_str())
            .and_then(|value| retry_after(&value, self.clock.now()))
        {
            Some(asked) if asked > MAX_RETRY_AFTER => Err(asked),
            Some(asked) => Ok(asked),
            None => Ok(backoff(attempt)),
        }
    }

    /// A `Graph` error from the allow-listed fields of the body, with the
    /// message redacted. The body is never quoted otherwise.
    fn graph_error(&self, status: StatusCode, headers: &HeaderMap, body: &[u8]) -> PurviewError {
        #[derive(Deserialize, Default)]
        struct Envelope {
            #[serde(default)]
            error: Body,
        }
        #[derive(Deserialize, Default)]
        struct Body {
            #[serde(default)]
            code: Option<Value>,
            #[serde(default)]
            message: Option<Value>,
            #[serde(default, rename = "innerError")]
            inner_error: Option<Inner>,
        }
        #[derive(Deserialize, Default)]
        struct Inner {
            #[serde(default, rename = "request-id")]
            request_id: Option<Value>,
            #[serde(default)]
            date: Option<Value>,
        }
        let parsed: Envelope = serde_json::from_slice(body).unwrap_or_default();
        // A message can quote a URL with a signature in it; the URL's
        // query is redacted as it would be anywhere else.
        let clean = |value: Option<&Value>| -> String {
            value
                .and_then(Value::as_str)
                .map(|text| {
                    sanitize(
                        &self
                            .redactor
                            .redact(&redact::urls_in_text(text, &self.redactor)),
                    )
                })
                .unwrap_or_default()
        };
        let inner = parsed.error.inner_error.unwrap_or_default();
        let mut message = clean(parsed.error.message.as_ref());
        if status.is_redirection() && message.is_empty() {
            message = "Graph answered with a redirect, which the tool does not follow".to_owned();
        }
        let request_id = match clean(inner.request_id.as_ref()) {
            id if id.is_empty() => header_text(headers, "request-id")
                .map(|id| sanitize(&self.redactor.redact(&id)))
                .unwrap_or_default(),
            id => id,
        };
        PurviewError::Graph(Box::new(GraphErrorDetails {
            status: status.as_u16(),
            code: clean(parsed.error.code.as_ref()),
            message,
            request_id,
            date: clean(inner.date.as_ref()),
            retry_after: header_text(headers, RETRY_AFTER.as_str())
                .and_then(|value| retry_after(&value, self.clock.now())),
        }))
    }

    /// Writes the exchange to the trace, if one is open. A trace that
    /// cannot be written is reported once, and the command goes on.
    fn record(&self, url: &Url, outcome: &Attempt, log: &mut (dyn Write + Send)) {
        let Some(trace) = &self.trace else {
            return;
        };
        let (response, error) = match outcome {
            Attempt::Response {
                status,
                headers,
                body,
            } => (
                Some(TracedResponse {
                    status: status.as_u16(),
                    headers,
                    body: TracedBody::Json(body),
                }),
                None,
            ),
            Attempt::Transient(reason) => (None, Some(reason.clone())),
            Attempt::Refused(error) => (None, Some(error.to_string())),
        };
        let exchange = Exchange {
            method: "GET",
            url,
            request_body: None,
            response,
            error: error.as_deref(),
        };
        if let Err(error) = trace.record(&exchange) {
            if !self.trace_failed.swap(true, Ordering::Relaxed) {
                let _ = writeln!(
                    log,
                    "warning: could not write a trace file: {}",
                    sanitize(&error.to_string())
                );
            }
        }
    }

    fn log(&self, log: &mut (dyn Write + Send), line: &str) {
        if self.verbose {
            let _ = writeln!(log, "[verbose] {line}");
        }
    }

    /// Writes what the token provider did since the last request, such as
    /// a refresh, before the request it was for.
    fn log_notes(&self, log: &mut (dyn Write + Send)) {
        for note in self.tokens.take_notes() {
            self.log(log, &sanitize(&self.redactor.redact(&note)));
        }
    }

    fn log_retry(&self, log: &mut (dyn Write + Send), wait: &Duration, attempt: u32) {
        self.log(
            log,
            &format!(
                "retrying in {} ms (attempt {} of {MAX_GET_ATTEMPTS})",
                wait.as_millis(),
                attempt + 1
            ),
        );
    }
}

fn is_retryable(status: StatusCode) -> bool {
    matches!(status.as_u16(), 429 | 500 | 502 | 503 | 504)
}

/// 250 ms × 2^(attempt − 1), at most `MAX_BACKOFF`.
fn backoff(attempt: u32) -> Duration {
    Duration::from_millis(250u64.saturating_mul(1u64 << attempt.saturating_sub(1).min(16)))
        .min(MAX_BACKOFF)
}

/// A `Retry-After` value: whole seconds, or an HTTP date, counted from
/// `now`. A date in the past means no wait. Anything else is ignored.
fn retry_after(value: &str, now: chrono::DateTime<chrono::Utc>) -> Option<Duration> {
    let value = value.trim();
    if let Ok(seconds) = value.parse::<u64>() {
        return Some(Duration::from_secs(seconds));
    }
    let date = chrono::DateTime::parse_from_rfc2822(value).ok()?;
    Some(
        (date.with_timezone(&chrono::Utc) - now)
            .to_std()
            .unwrap_or(Duration::ZERO),
    )
}

fn header_text(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned)
}

/// A write whose outcome is not known; the command adds what it finds.
fn unknown(reason: String) -> PurviewError {
    PurviewError::WriteOutcomeUnknown {
        notes: Vec::new(),
        reason,
        candidates: Vec::new(),
    }
}

/// A POST response's body, up to `MAX_RESPONSE_BYTES`, or why it could not
/// be read in full.
async fn read_body(mut response: reqwest::Response) -> std::result::Result<Vec<u8>, String> {
    if response
        .content_length()
        .is_some_and(|length| length > MAX_RESPONSE_BYTES as u64)
    {
        return Err(too_large().to_string());
    }
    let mut body = Vec::new();
    loop {
        match response.chunk().await {
            Ok(Some(chunk)) => {
                if body.len().saturating_add(chunk.len()) > MAX_RESPONSE_BYTES {
                    return Err(too_large().to_string());
                }
                body.extend_from_slice(&chunk);
            }
            Ok(None) => return Ok(body),
            Err(error) if error.is_timeout() => return Err("the response timed out".to_owned()),
            Err(_) => return Err("the response was cut off".to_owned()),
        }
    }
}

fn too_large() -> PurviewError {
    PurviewError::message(format!(
        "Microsoft Graph's response exceeds {MAX_RESPONSE_BYTES} bytes"
    ))
}

/// A request that got no response. reqwest's own message names the URL,
/// which could carry a paging token, so only the kind is kept.
fn transport_failure(error: &reqwest::Error) -> String {
    if error.is_timeout() {
        "the request timed out"
    } else if error.is_connect() {
        "the connection failed"
    } else {
        "the request failed"
    }
    .to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_doubles_from_250_ms_and_stops_at_30_seconds() {
        let waits: Vec<u128> = (1..=9)
            .map(|attempt| backoff(attempt).as_millis())
            .collect();
        assert_eq!(
            waits,
            [250, 500, 1000, 2000, 4000, 8000, 16000, 30000, 30000]
        );
        assert_eq!(backoff(u32::MAX), MAX_BACKOFF);
    }

    #[test]
    fn retry_after_takes_seconds_or_an_http_date() {
        let now = crate::env::test_epoch();
        assert_eq!(retry_after("7", now), Some(Duration::from_secs(7)));
        assert_eq!(
            retry_after("Mon, 05 Jan 2026 09:00:12 GMT", now),
            Some(Duration::from_secs(12))
        );
        assert_eq!(
            retry_after("Mon, 05 Jan 2026 08:00:00 GMT", now),
            Some(Duration::ZERO)
        );
        assert_eq!(retry_after("soon", now), None);
        assert_eq!(retry_after("-1", now), None);
    }

    #[test]
    fn only_the_listed_statuses_are_retried() {
        let retried: Vec<u16> = (100..600)
            .filter(|code| is_retryable(StatusCode::from_u16(*code).unwrap()))
            .collect();
        assert_eq!(retried, [429, 500, 502, 503, 504]);
    }
}
