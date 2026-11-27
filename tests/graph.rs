//! `GraphClient` against wiremock origins: origins, paging, retries, the
//! 401 refresh, body limits, the trace and the verbose log. A fake token
//! provider stands in for the stored credential.

mod support;

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use ms_purview_cli::env::{test_epoch, Clock, ManualClock};
use ms_purview_cli::error::{PurviewError, Result};
use ms_purview_cli::graph::{GraphClient, GraphSettings, ListStop, MAX_PAGES};
use ms_purview_cli::redact::Redactor;
use ms_purview_cli::routes::{CaseId, Query, ReadRoute};
use ms_purview_cli::token::{DownloadToken, GraphToken, SecretString, TokenProvider};
use ms_purview_cli::trace::TraceSink;
use serde_json::{json, Value};
use support::graph_fixture;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use url::Url;
use wiremock::matchers::{header, method, path, query_param};
use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

const CASES: &str = "/v1.0/security/cases/ediscoveryCases";
const FIRST: &str = "canary-graph-access-0001";
const SECOND: &str = "canary-graph-access-0002";

/// Hands out `FIRST` until invalidated, then `SECOND`. With `fail`, every
/// request for a token fails, as a refused refresh would.
#[derive(Default)]
struct FakeTokens {
    invalidated: AtomicUsize,
    calls: AtomicUsize,
    fail: bool,
    /// Hand out a token that is not a valid header value.
    malformed: bool,
    notes: Mutex<Vec<String>>,
}

#[async_trait]
impl TokenProvider for FakeTokens {
    async fn graph(&self, _min_validity: Duration) -> Result<GraphToken> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if self.fail {
            return Err(PurviewError::message("the refresh was refused"));
        }
        if self.malformed {
            return Ok(GraphToken::new(SecretString::new("canary-bad\ntoken-0001")));
        }
        let token = if self.invalidated.load(Ordering::SeqCst) == 0 {
            FIRST
        } else {
            SECOND
        };
        Ok(GraphToken::new(SecretString::new(token)))
    }

    async fn download(&self, _min_validity: Duration) -> Result<DownloadToken> {
        panic!("a Graph read never asks for the download token");
    }

    async fn invalidate_graph(&self) {
        self.invalidated.fetch_add(1, Ordering::SeqCst);
    }

    fn take_notes(&self) -> Vec<String> {
        std::mem::take(&mut *self.notes.lock().unwrap())
    }
}

struct Setup {
    client: GraphClient,
    tokens: Arc<FakeTokens>,
    clock: Arc<ManualClock>,
    redactor: Arc<Redactor>,
}

fn base_of(uri: &str) -> Url {
    Url::parse(&format!("{uri}/v1.0/")).unwrap()
}

fn setup_with(
    base: Url,
    tokens: FakeTokens,
    timeout: Duration,
    verbose: bool,
    trace: Option<&std::path::Path>,
) -> Setup {
    let tokens = Arc::new(tokens);
    let clock = Arc::new(ManualClock::new(test_epoch()));
    let redactor = Arc::new(Redactor::new());
    for token in [FIRST, SECOND] {
        redactor.register(token);
    }
    let trace = trace.map(|dir| {
        Arc::new(TraceSink::open(dir, redactor.clone(), clock.clone(), &mut Vec::new()).unwrap())
    });
    let client = GraphClient::new(
        GraphSettings {
            base,
            timeout,
            verbose,
            trace,
        },
        tokens.clone(),
        redactor.clone(),
        clock.clone(),
    )
    .unwrap();
    Setup {
        client,
        tokens,
        clock,
        redactor,
    }
}

fn setup(server: &MockServer) -> Setup {
    setup_with(
        base_of(&server.uri()),
        FakeTokens::default(),
        Duration::from_secs(10),
        false,
        None,
    )
}

fn top1() -> Query {
    Query::new().top(1)
}

async fn requests(server: &MockServer) -> usize {
    server.received_requests().await.unwrap().len()
}

fn status(code: u16, body: Value) -> ResponseTemplate {
    ResponseTemplate::new(code).set_body_json(body)
}

#[tokio::test]
async fn a_page_is_read_with_the_provider_s_token_and_no_other_header_of_note() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(CASES))
        .and(query_param("$top", "1"))
        .and(header("authorization", format!("Bearer {FIRST}").as_str()))
        .and(header("accept", "application/json"))
        .respond_with(status(
            200,
            graph_fixture("cases-list-top1.json", &server.uri()),
        ))
        .expect(1)
        .mount(&server)
        .await;
    let setup = setup(&server);
    let page = setup
        .client
        .get_page(&ReadRoute::Cases, &top1(), &mut Vec::new())
        .await
        .unwrap();
    assert_eq!(page.value.len(), 1);
    assert_eq!(page.next_link, None);
    assert_eq!(setup.tokens.calls.load(Ordering::SeqCst), 1);
    assert!(setup.clock.sleeps().is_empty());
}

#[tokio::test]
async fn a_list_follows_next_links_on_the_graph_origin_to_the_last_page() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(CASES))
        .and(query_param("$skiptoken", "page-0002"))
        .respond_with(status(
            200,
            graph_fixture("cases-list-page2.json", &server.uri()),
        ))
        .expect(1)
        .with_priority(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(CASES))
        .respond_with(status(
            200,
            graph_fixture("cases-list-page1.json", &server.uri()),
        ))
        .expect(1)
        .with_priority(2)
        .mount(&server)
        .await;
    let listing = setup(&server)
        .client
        .list(&ReadRoute::Cases, &Query::new(), &mut Vec::new())
        .await
        .unwrap();
    assert_eq!(listing.stopped, None);
    // The entry without an id is kept raw; parsing comes later.
    assert_eq!(listing.items.len(), 3);
    assert_eq!(listing.items[2]["status"], "closing");
}

#[tokio::test]
async fn a_next_link_off_the_graph_origin_or_base_path_is_refused_unsent() {
    let server = MockServer::start().await;
    let foreign = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(status(200, json!({"value": []})))
        .mount(&foreign)
        .await;
    let same_host_other_port = foreign.uri();
    let next_links = [
        // Another host.
        graph_fixture("cases-list-foreign-nextlink.json", &server.uri())["@odata.nextLink"]
            .as_str()
            .unwrap()
            .to_owned(),
        // The same host on another port.
        format!("{same_host_other_port}/v1.0/security/cases/ediscoveryCases?$skiptoken=x"),
        // The Graph origin, but outside the base path.
        format!("{}/beta/security/cases/ediscoveryCases", server.uri()),
        format!("{}/v1.0/../beta/security", server.uri()),
    ];
    for next in next_links {
        server.reset().await;
        Mock::given(method("GET"))
            .and(path(CASES))
            .respond_with(status(200, json!({"value": [1], "@odata.nextLink": next})))
            .expect(1)
            .mount(&server)
            .await;
        let error = setup(&server)
            .client
            .list(&ReadRoute::Cases, &Query::new(), &mut Vec::new())
            .await
            .unwrap_err();
        assert_eq!(error.metadata(), ("ForeignOrigin", 0), "{next}");
        assert!(error.to_string().contains("another origin"), "{error}");
    }
    assert_eq!(requests(&foreign).await, 0);
}

#[tokio::test]
async fn a_repeated_link_stops_the_list_and_the_list_is_marked_incomplete() {
    let server = MockServer::start().await;
    let again = format!("{}{CASES}", server.uri());
    Mock::given(method("GET"))
        .and(path(CASES))
        .respond_with(status(200, json!({"value": [1], "@odata.nextLink": again})))
        .expect(1)
        .mount(&server)
        .await;
    let listing = setup(&server)
        .client
        .list(&ReadRoute::Cases, &Query::new(), &mut Vec::new())
        .await
        .unwrap();
    assert_eq!(listing.stopped, Some(ListStop::RepeatedLink));
    assert_eq!(listing.items, [json!(1)]);
    assert!(listing.complete().is_err());
}

/// Every page offers a next one.
struct Endless(String);

impl Respond for Endless {
    fn respond(&self, request: &Request) -> ResponseTemplate {
        let page: u64 = request
            .url
            .query_pairs()
            .find(|(key, _)| key == "$skiptoken")
            .and_then(|(_, value)| value.parse().ok())
            .unwrap_or(0);
        status(
            200,
            json!({
                "value": [page],
                "@odata.nextLink": format!("{}{CASES}?$skiptoken={}", self.0, page + 1),
            }),
        )
    }
}

#[tokio::test]
async fn a_list_stops_after_200_pages() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(CASES))
        .respond_with(Endless(server.uri()))
        .mount(&server)
        .await;
    let listing = setup(&server)
        .client
        .list(&ReadRoute::Cases, &Query::new(), &mut Vec::new())
        .await
        .unwrap();
    assert_eq!(listing.stopped, Some(ListStop::PageLimit));
    assert_eq!(listing.items.len(), MAX_PAGES);
    assert_eq!(requests(&server).await, MAX_PAGES);
}

#[tokio::test]
async fn each_retryable_status_is_retried_twice_with_backoff() {
    for code in [429, 500, 502, 503, 504] {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(status(code, json!({"error": {"code": "Busy"}})))
            .up_to_n_times(2)
            .with_priority(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .respond_with(status(200, json!({"value": []})))
            .with_priority(2)
            .mount(&server)
            .await;
        let setup = setup(&server);
        setup
            .client
            .get_page(&ReadRoute::Cases, &top1(), &mut Vec::new())
            .await
            .unwrap_or_else(|error| panic!("{code}: {error}"));
        assert_eq!(requests(&server).await, 3, "{code}");
        assert_eq!(
            setup.clock.sleeps(),
            [Duration::from_millis(250), Duration::from_millis(500)],
            "{code}"
        );
    }
}

#[tokio::test]
async fn a_get_makes_at_most_three_attempts() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(status(
            503,
            graph_fixture("error-503-retry-after-date.json", &server.uri()),
        ))
        .mount(&server)
        .await;
    let error = setup(&server)
        .client
        .get_page(&ReadRoute::Cases, &top1(), &mut Vec::new())
        .await
        .unwrap_err();
    assert_eq!(requests(&server).await, 3);
    assert_eq!(error.metadata(), ("ServiceUnavailable", 503));
    assert!(
        error
            .to_string()
            .contains("request id 00000000-0000-4000-8000-000000000044"),
        "{error}"
    );
}

#[tokio::test]
async fn retry_after_is_honoured_in_seconds_or_as_a_date() {
    for (value, wait) in [
        ("7", Duration::from_secs(7)),
        ("Mon, 05 Jan 2026 09:00:12 GMT", Duration::from_secs(12)),
        ("Mon, 05 Jan 2026 08:00:00 GMT", Duration::ZERO),
        ("not a time", Duration::from_millis(250)),
    ] {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(
                status(429, graph_fixture("error-429.json", &server.uri()))
                    .insert_header("retry-after", value),
            )
            .up_to_n_times(1)
            .with_priority(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .respond_with(status(200, json!({"value": []})))
            .with_priority(2)
            .mount(&server)
            .await;
        let setup = setup(&server);
        setup
            .client
            .get_page(&ReadRoute::Cases, &top1(), &mut Vec::new())
            .await
            .unwrap();
        assert_eq!(setup.clock.sleeps(), [wait], "{value}");
    }
}

#[tokio::test]
async fn a_retry_after_over_the_limit_ends_the_get_without_waiting() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(
            status(429, graph_fixture("error-429.json", &server.uri()))
                .insert_header("retry-after", "61"),
        )
        .mount(&server)
        .await;
    let setup = setup(&server);
    let error = setup
        .client
        .get_page(&ReadRoute::Cases, &top1(), &mut Vec::new())
        .await
        .unwrap_err();
    assert_eq!(requests(&server).await, 1);
    assert!(setup.clock.sleeps().is_empty());
    assert_eq!(error.metadata(), ("TooManyRequests", 429));
    assert!(
        error.to_string().contains("retry after 61 seconds"),
        "{error}"
    );
}

#[tokio::test]
async fn other_failures_are_not_retried() {
    for code in [400, 403, 404, 409, 501] {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(status(
                code,
                json!({"error": {"code": "No", "message": "no"}}),
            ))
            .mount(&server)
            .await;
        let error = setup(&server)
            .client
            .get_page(&ReadRoute::Cases, &top1(), &mut Vec::new())
            .await
            .unwrap_err();
        assert_eq!(requests(&server).await, 1, "{code}");
        assert_eq!(error.graph_status(), Some(code));
    }
}

#[tokio::test]
async fn a_401_refreshes_once_and_retries_once_with_the_new_token() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(header("authorization", format!("Bearer {FIRST}").as_str()))
        .respond_with(status(401, graph_fixture("error-401.json", &server.uri())))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(header("authorization", format!("Bearer {SECOND}").as_str()))
        .respond_with(status(200, json!({"value": []})))
        .expect(1)
        .mount(&server)
        .await;
    let fixture = setup(&server);
    fixture
        .client
        .get_page(&ReadRoute::Cases, &top1(), &mut Vec::new())
        .await
        .unwrap();
    assert_eq!(fixture.tokens.invalidated.load(Ordering::SeqCst), 1);
    assert_eq!(requests(&server).await, 2);
    assert!(fixture.clock.sleeps().is_empty());

    // A second 401 is the error: one refresh, two requests.
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(status(401, graph_fixture("error-401.json", &server.uri())))
        .mount(&server)
        .await;
    let fixture = setup(&server);
    let error = fixture
        .client
        .get_page(&ReadRoute::Cases, &top1(), &mut Vec::new())
        .await
        .unwrap_err();
    assert_eq!(error.metadata(), ("InvalidAuthenticationToken", 401));
    assert_eq!(fixture.tokens.invalidated.load(Ordering::SeqCst), 1);
    assert_eq!(requests(&server).await, 2);
}

#[tokio::test]
async fn a_token_that_cannot_be_had_sends_nothing_and_is_marked() {
    let server = MockServer::start().await;
    let setup = setup_with(
        base_of(&server.uri()),
        FakeTokens {
            fail: true,
            ..FakeTokens::default()
        },
        Duration::from_secs(10),
        false,
        None,
    );
    let error = setup
        .client
        .get_page(&ReadRoute::Cases, &top1(), &mut Vec::new())
        .await
        .unwrap_err();
    assert!(error.is_token_unavailable(), "{error}");
    assert_eq!(requests(&server).await, 0);
}

#[tokio::test]
async fn a_refused_connection_is_retried_then_reported() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    drop(listener);
    let setup = setup_with(
        base_of(&format!("http://{address}")),
        FakeTokens::default(),
        Duration::from_secs(10),
        false,
        None,
    );
    let error = setup
        .client
        .get_page(&ReadRoute::Cases, &top1(), &mut Vec::new())
        .await
        .unwrap_err();
    assert_eq!(
        error.to_string(),
        "could not reach Microsoft Graph: the connection failed (3 attempts)"
    );
    assert_eq!(setup.clock.sleeps().len(), 2);
}

#[tokio::test]
async fn a_request_that_times_out_is_retried_then_reported() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(status(200, json!({"value": []})).set_delay(Duration::from_secs(5)))
        .mount(&server)
        .await;
    let setup = setup_with(
        base_of(&server.uri()),
        FakeTokens::default(),
        Duration::from_millis(200),
        false,
        None,
    );
    let error = setup
        .client
        .get_page(&ReadRoute::Cases, &top1(), &mut Vec::new())
        .await
        .unwrap_err();
    assert_eq!(
        error.to_string(),
        "could not reach Microsoft Graph: the request timed out (3 attempts)"
    );
    assert_eq!(requests(&server).await, 3);
}

/// A server that answers each connection with the next of `answers`, raw,
/// then closes it, and counts the connections.
async fn raw_server(answers: Vec<Vec<u8>>) -> (String, Arc<AtomicUsize>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let count = Arc::new(AtomicUsize::new(0));
    let counter = count.clone();
    tokio::spawn(async move {
        for answer in answers {
            let (mut stream, _) = listener.accept().await.unwrap();
            counter.fetch_add(1, Ordering::SeqCst);
            let mut buffer = [0u8; 4096];
            let _ = stream.read(&mut buffer).await;
            let _ = stream.write_all(&answer).await;
            let _ = stream.shutdown().await;
        }
    });
    (format!("http://{address}"), count)
}

#[tokio::test]
async fn a_truncated_body_is_retried() {
    let whole = br#"{"value": []}"#;
    let cut = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 100\r\n\r\n{\"value\": ["
        .to_vec();
    let mut full = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        whole.len()
    )
    .into_bytes();
    full.extend_from_slice(whole);
    let (uri, connections) = raw_server(vec![cut, full]).await;
    let setup = setup_with(
        base_of(&uri),
        FakeTokens::default(),
        Duration::from_secs(10),
        false,
        None,
    );
    let page = setup
        .client
        .get_page(&ReadRoute::Cases, &top1(), &mut Vec::new())
        .await
        .unwrap();
    assert!(page.value.is_empty());
    assert_eq!(connections.load(Ordering::SeqCst), 2);
    assert_eq!(setup.clock.sleeps(), [Duration::from_millis(250)]);
}

#[tokio::test]
async fn a_redirect_is_not_followed() {
    let server = MockServer::start().await;
    let foreign = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(status(200, json!({"value": []})))
        .mount(&foreign)
        .await;
    Mock::given(method("GET"))
        .respond_with(
            ResponseTemplate::new(302)
                .insert_header("location", format!("{}{CASES}", foreign.uri())),
        )
        .mount(&server)
        .await;
    let error = setup(&server)
        .client
        .get_page(&ReadRoute::Cases, &top1(), &mut Vec::new())
        .await
        .unwrap_err();
    assert_eq!(error.graph_status(), Some(302));
    assert!(error.to_string().contains("does not follow"), "{error}");
    assert_eq!(requests(&foreign).await, 0);
    assert_eq!(requests(&server).await, 1);
}

#[tokio::test]
async fn an_oversized_or_unreadable_body_is_refused_without_a_retry() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(query_param("$top", "1"))
        .respond_with(ResponseTemplate::new(200).set_body_string("x".repeat(8 * 1024 * 1024 + 1)))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(query_param("$top", "2"))
        .respond_with(ResponseTemplate::new(200).set_body_string("not json"))
        .mount(&server)
        .await;
    let setup = setup(&server);
    let error = setup
        .client
        .get_page(&ReadRoute::Cases, &top1(), &mut Vec::new())
        .await
        .unwrap_err();
    assert!(error.to_string().contains("exceeds"), "{error}");
    let error = setup
        .client
        .get_page(&ReadRoute::Cases, &Query::new().top(2), &mut Vec::new())
        .await
        .unwrap_err();
    assert!(error.to_string().contains("not a JSON object"), "{error}");
    assert_eq!(requests(&server).await, 2);
}

#[tokio::test]
async fn a_graph_error_keeps_only_allow_listed_fields_redacted() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(status(
            403,
            json!({"error": {
                "code": "Forbidden",
                "message": format!("token {FIRST} has no role"),
                "innerError": {"request-id": "request-0001", "date": "2026-01-05T09:00:00"},
                "details": [{"secret": "canary-detail-0001"}],
            }}),
        ))
        .mount(&server)
        .await;
    let error = setup(&server)
        .client
        .get(
            &ReadRoute::Case(CaseId::parse("00000000-0000-4000-8000-000000000031").unwrap()),
            &Query::new(),
            &mut Vec::new(),
        )
        .await
        .unwrap_err();
    assert_eq!(
        error.to_string(),
        "Microsoft Graph returned HTTP 403: Forbidden: token [redacted] has no role (request id \
         request-0001; date 2026-01-05T09:00:00)"
    );
}

#[tokio::test]
async fn the_trace_and_verbose_log_hold_each_attempt_without_tokens() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(
            status(
                503,
                json!({"error": {"code": "ServiceUnavailable", "message": FIRST}}),
            )
            .insert_header("request-id", "request-0001"),
        )
        .up_to_n_times(1)
        .with_priority(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .respond_with(status(
            200,
            graph_fixture("cases-list-top1.json", &server.uri()),
        ))
        .with_priority(2)
        .mount(&server)
        .await;
    let root = tempfile::tempdir().unwrap();
    let trace = root.path().join("trace");
    let setup = setup_with(
        base_of(&server.uri()),
        FakeTokens::default(),
        Duration::from_secs(10),
        true,
        Some(&trace),
    );
    setup
        .tokens
        .notes
        .lock()
        .unwrap()
        .push(format!("refreshed {FIRST}"));
    let mut log = Vec::new();
    setup
        .client
        .get_page(&ReadRoute::Cases, &top1(), &mut log)
        .await
        .unwrap();
    let log = String::from_utf8(log).unwrap();
    let lines: Vec<&str> = log.lines().collect();
    let url = format!("{}{CASES}?%24top=1", server.uri());
    assert_eq!(
        lines,
        [
            "[verbose] refreshed [redacted]".to_owned(),
            format!("[verbose] GET {url}"),
            "[verbose] HTTP 503 in 0 ms, request-id request-0001".to_owned(),
            "[verbose] retrying in 250 ms (attempt 2 of 3)".to_owned(),
            format!("[verbose] GET {url}"),
            "[verbose] HTTP 200 in 0 ms".to_owned(),
        ]
    );
    let mut files: Vec<_> = std::fs::read_dir(&trace)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .collect();
    files.sort();
    assert_eq!(files.len(), 2);
    for file in &files {
        let name = file.file_name().unwrap().to_string_lossy().into_owned();
        assert!(name.ends_with("-GET-ediscoveryCases.json"), "{name}");
        let text = std::fs::read_to_string(file).unwrap();
        assert!(!text.contains("canary"), "{text}");
        assert!(
            !text.to_ascii_lowercase().contains("authorization"),
            "{text}"
        );
    }
    let first: Value = serde_json::from_slice(&std::fs::read(&files[0]).unwrap()).unwrap();
    assert_eq!(first["response"]["status"], 503);
    assert_eq!(first["response"]["headers"]["request-id"], "request-0001");
    assert_eq!(first["response"]["body"]["error"]["message"], "[redacted]");
    let _ = setup.redactor;
}

#[tokio::test]
async fn the_verbose_log_shows_a_paging_link_without_its_other_query_values() {
    let server = MockServer::start().await;
    let next = format!(
        "{}{CASES}?$skiptoken=page-0002&sig=canary-sig-0009",
        server.uri()
    );
    Mock::given(method("GET"))
        .and(query_param("$skiptoken", "page-0002"))
        .respond_with(status(200, json!({"value": []})))
        .with_priority(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .respond_with(status(200, json!({"value": [], "@odata.nextLink": next})))
        .with_priority(2)
        .mount(&server)
        .await;
    let setup = setup_with(
        base_of(&server.uri()),
        FakeTokens::default(),
        Duration::from_secs(10),
        true,
        None,
    );
    let mut log = Vec::new();
    setup
        .client
        .list(&ReadRoute::Cases, &Query::new(), &mut log)
        .await
        .unwrap();
    let log = String::from_utf8(log).unwrap();
    assert!(!log.contains("canary"), "{log}");
    assert!(
        log.contains("?%24skiptoken=page-0002&sig=REDACTED"),
        "{log}"
    );
}

#[tokio::test]
async fn the_client_refuses_a_base_without_an_origin() {
    let error = GraphClient::new(
        GraphSettings {
            base: Url::parse("file:///v1.0/").unwrap(),
            timeout: Duration::from_secs(1),
            verbose: false,
            trace: None,
        },
        Arc::new(FakeTokens::default()),
        Arc::new(Redactor::new()),
        Arc::new(ManualClock::new(test_epoch())) as Arc<dyn Clock>,
    )
    .unwrap_err();
    assert!(error.to_string().contains("no origin"), "{error}");
}

/// Mounts `codes` in order, one response each, then 200.
async fn mount_sequence(server: &MockServer, codes: &[u16]) {
    for (index, code) in codes.iter().enumerate() {
        Mock::given(method("GET"))
            .respond_with(status(
                *code,
                json!({"error": {"code": format!("E{code}")}}),
            ))
            .up_to_n_times(1)
            .with_priority(index as u8 + 1)
            .mount(server)
            .await;
    }
    Mock::given(method("GET"))
        .respond_with(status(200, json!({"value": []})))
        .with_priority(codes.len() as u8 + 1)
        .mount(server)
        .await;
}

#[tokio::test]
async fn a_401_shares_the_three_attempt_budget() {
    // 401 last: no attempt is left, so no refresh and no fourth GET.
    let server = MockServer::start().await;
    mount_sequence(&server, &[503, 503, 401]).await;
    let fixture = setup(&server);
    let error = fixture
        .client
        .get_page(&ReadRoute::Cases, &top1(), &mut Vec::new())
        .await
        .unwrap_err();
    assert_eq!(error.graph_status(), Some(401));
    assert_eq!(requests(&server).await, 3);
    assert_eq!(fixture.tokens.invalidated.load(Ordering::SeqCst), 0);

    // 401 first: one refresh, then the two attempts left.
    let server = MockServer::start().await;
    mount_sequence(&server, &[401, 503, 503]).await;
    let fixture = setup(&server);
    let error = fixture
        .client
        .get_page(&ReadRoute::Cases, &top1(), &mut Vec::new())
        .await
        .unwrap_err();
    assert_eq!(error.graph_status(), Some(503));
    assert_eq!(requests(&server).await, 3);
    assert_eq!(fixture.tokens.invalidated.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn an_error_whose_body_cannot_be_read_keeps_its_status() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(403).set_body_string("x".repeat(8 * 1024 * 1024 + 1)))
        .mount(&server)
        .await;
    let error = setup(&server)
        .client
        .get_page(&ReadRoute::Cases, &top1(), &mut Vec::new())
        .await
        .unwrap_err();
    assert_eq!(error.graph_status(), Some(403));
    assert_eq!(requests(&server).await, 1);

    // A 503 cut off part way keeps its Retry-After, which is over the
    // limit, so there is no retry.
    let cut = b"HTTP/1.1 503 Service Unavailable\r\nRetry-After: 61\r\nContent-Length: 100\r\n\r\n{\"error\""
        .to_vec();
    let (uri, connections) = raw_server(vec![cut]).await;
    let fixture = setup_with(
        base_of(&uri),
        FakeTokens::default(),
        Duration::from_secs(10),
        false,
        None,
    );
    let error = fixture
        .client
        .get_page(&ReadRoute::Cases, &top1(), &mut Vec::new())
        .await
        .unwrap_err();
    assert_eq!(error.graph_status(), Some(503));
    assert!(
        error.to_string().contains("retry after 61 seconds"),
        "{error}"
    );
    assert_eq!(connections.load(Ordering::SeqCst), 1);
    assert!(fixture.clock.sleeps().is_empty());
}

#[tokio::test]
async fn a_request_that_cannot_be_built_is_not_retried_or_sent() {
    let server = MockServer::start().await;
    let fixture = setup_with(
        base_of(&server.uri()),
        FakeTokens {
            malformed: true,
            ..FakeTokens::default()
        },
        Duration::from_secs(10),
        false,
        None,
    );
    let error = fixture
        .client
        .get_page(&ReadRoute::Cases, &top1(), &mut Vec::new())
        .await
        .unwrap_err();
    assert!(error.to_string().contains("could not be built"), "{error}");
    assert!(!error.to_string().contains("canary"), "{error}");
    assert_eq!(requests(&server).await, 0);
    assert!(fixture.clock.sleeps().is_empty());
}

#[tokio::test]
async fn a_url_quoted_in_a_graph_error_loses_its_secret_query_values() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(status(
            403,
            json!({"error": {
                "code": "Forbidden",
                "message": format!(
                    "see {}/v1.0/x?sig=canary-sig-0005&$top=1.",
                    server.uri()
                ),
            }}),
        ))
        .mount(&server)
        .await;
    let error = setup(&server)
        .client
        .get_page(&ReadRoute::Cases, &top1(), &mut Vec::new())
        .await
        .unwrap_err();
    let text = error.to_string();
    assert!(!text.contains("canary"), "{text}");
    assert!(text.contains("/v1.0/x?REDACTED"), "{text}");
}

#[tokio::test]
async fn a_redirect_s_location_is_resolved_and_redacted_in_the_trace() {
    for location in [
        "/next?code=canary-code-0002",
        "//foreign.example/x?sig=canary-sig-0003",
        "?token=canary-token-0004",
    ] {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(302).insert_header("location", location))
            .mount(&server)
            .await;
        let root = tempfile::tempdir().unwrap();
        let trace = root.path().join("trace");
        let fixture = setup_with(
            base_of(&server.uri()),
            FakeTokens::default(),
            Duration::from_secs(10),
            true,
            Some(&trace),
        );
        let mut log = Vec::new();
        let error = fixture
            .client
            .get_page(&ReadRoute::Cases, &top1(), &mut log)
            .await
            .unwrap_err();
        assert_eq!(error.graph_status(), Some(302), "{location}");
        let log = String::from_utf8(log).unwrap();
        assert!(!log.contains("canary"), "{location}: {log}");
        let file = std::fs::read_dir(&trace)
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .path();
        let text = std::fs::read_to_string(&file).unwrap();
        assert!(!text.contains("canary"), "{location}: {text}");
        let record: Value = serde_json::from_str(&text).unwrap();
        let shown = record["response"]["headers"]["location"].as_str().unwrap();
        assert!(shown.starts_with("http"), "{location}: {shown}");
        assert!(shown.ends_with("=REDACTED"), "{location}: {shown}");
    }
}

#[tokio::test]
async fn a_timed_out_page_shows_its_link_redacted_in_the_log_and_trace() {
    let server = MockServer::start().await;
    let next = format!(
        "{}{CASES}?$skiptoken=page-0002&sig=canary-sig-0006",
        server.uri()
    );
    Mock::given(method("GET"))
        .and(query_param("$skiptoken", "page-0002"))
        .respond_with(status(200, json!({"value": []})).set_delay(Duration::from_secs(5)))
        .with_priority(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .respond_with(status(200, json!({"value": [], "@odata.nextLink": next})))
        .with_priority(2)
        .mount(&server)
        .await;
    let root = tempfile::tempdir().unwrap();
    let trace = root.path().join("trace");
    let fixture = setup_with(
        base_of(&server.uri()),
        FakeTokens::default(),
        Duration::from_millis(200),
        true,
        Some(&trace),
    );
    let mut log = Vec::new();
    let error = fixture
        .client
        .list(&ReadRoute::Cases, &Query::new(), &mut log)
        .await
        .unwrap_err();
    assert!(
        error.to_string().contains("timed out (3 attempts)"),
        "{error}"
    );
    let log = String::from_utf8(log).unwrap();
    assert!(!log.contains("canary"), "{log}");
    assert!(log.contains("sig=REDACTED"), "{log}");
    let files: Vec<_> = std::fs::read_dir(&trace).unwrap().collect();
    assert_eq!(files.len(), 4);
    for file in files {
        let text = std::fs::read_to_string(file.unwrap().path()).unwrap();
        assert!(!text.contains("canary"), "{text}");
    }
}

#[tokio::test]
async fn the_verbose_log_redacts_the_request_id_and_keeps_notes_before_a_token_failure() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(status(200, json!({"value": []})).insert_header("request-id", FIRST))
        .mount(&server)
        .await;
    let fixture = setup_with(
        base_of(&server.uri()),
        FakeTokens::default(),
        Duration::from_secs(10),
        true,
        None,
    );
    let mut log = Vec::new();
    fixture
        .client
        .get_page(&ReadRoute::Cases, &top1(), &mut log)
        .await
        .unwrap();
    let log = String::from_utf8(log).unwrap();
    assert!(log.contains("request-id [redacted]"), "{log}");
    assert!(!log.contains("canary"), "{log}");

    let fixture = setup_with(
        base_of(&server.uri()),
        FakeTokens {
            fail: true,
            ..FakeTokens::default()
        },
        Duration::from_secs(10),
        true,
        None,
    );
    fixture
        .tokens
        .notes
        .lock()
        .unwrap()
        .push("refreshed the Graph token: returned scope none".to_owned());
    let mut log = Vec::new();
    let error = fixture
        .client
        .get_page(&ReadRoute::Cases, &top1(), &mut log)
        .await
        .unwrap_err();
    assert!(error.is_token_unavailable());
    assert_eq!(
        String::from_utf8(log).unwrap(),
        "[verbose] refreshed the Graph token: returned scope none\n"
    );
}

#[tokio::test]
async fn a_fractional_wait_over_the_limit_is_reported_rounded_up() {
    let server = MockServer::start().await;
    // 60.5 seconds from the clock once it has moved half a second.
    Mock::given(method("GET"))
        .respond_with(
            status(429, graph_fixture("error-429.json", &server.uri()))
                .insert_header("retry-after", "Mon, 05 Jan 2026 09:01:01 GMT"),
        )
        .mount(&server)
        .await;
    let fixture = setup(&server);
    fixture.clock.advance(Duration::from_millis(500));
    let error = fixture
        .client
        .get_page(&ReadRoute::Cases, &top1(), &mut Vec::new())
        .await
        .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("retry after 61 seconds, longer than the 60-second"),
        "{error}"
    );
    assert_eq!(requests(&server).await, 1);
}

mod polling {
    use super::*;
    use ms_purview_cli::env::ManualInterrupt;
    use ms_purview_cli::poll::{PollEnd, Poller, Timing};
    use ms_purview_cli::routes::OperationId;

    const OPERATION: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaa0001";

    fn route() -> ReadRoute {
        ReadRoute::Operation(
            CaseId::parse("00000000-0000-4000-8000-000000000031").unwrap(),
            OperationId::parse(OPERATION).unwrap(),
        )
    }

    fn operation_path() -> String {
        format!("{CASES}/00000000-0000-4000-8000-000000000031/operations/{OPERATION}")
    }

    fn status(status: &str) -> ResponseTemplate {
        ResponseTemplate::new(200).set_body_json(json!({"id": OPERATION, "status": status}))
    }

    async fn answer(server: &MockServer, priority: u8, times: Option<u64>, with: ResponseTemplate) {
        let mock = Mock::given(method("GET"))
            .and(path(operation_path()))
            .respond_with(with)
            .with_priority(priority);
        match times {
            Some(times) => mock.up_to_n_times(times),
            None => mock,
        }
        .mount(server)
        .await;
    }

    async fn wait(setup: &Setup, grace: Option<Duration>) -> Result<PollEnd> {
        let interrupt = ManualInterrupt::default();
        let poller = Poller {
            graph: &setup.client,
            clock: setup.clock.as_ref(),
            interrupt: &interrupt,
            timing: Timing {
                timeout: Duration::from_secs(3600),
                interval: None,
            },
            not_found_grace: grace,
        };
        poller
            .wait(&route(), &mut Vec::new(), &mut |_, _, _| {})
            .await
    }

    #[tokio::test]
    async fn a_404_is_retried_only_within_the_grace_for_a_fresh_submission() {
        let server = MockServer::start().await;
        answer(&server, 1, Some(1), ResponseTemplate::new(404)).await;
        answer(&server, 2, None, status("succeeded")).await;
        let setup = setup(&server);
        let end = wait(&setup, Some(Duration::from_secs(30))).await.unwrap();
        assert!(matches!(end, PollEnd::Finished(_)), "{end:?}");
        assert_eq!(setup.clock.sleeps(), [Duration::from_secs(10)]);

        let server = MockServer::start().await;
        answer(&server, 1, None, ResponseTemplate::new(404)).await;
        let setup = setup_with(
            base_of(&server.uri()),
            FakeTokens::default(),
            Duration::from_secs(10),
            false,
            None,
        );
        let error = wait(&setup, None).await.unwrap_err();
        assert_eq!(error.graph_status(), Some(404));
        assert_eq!(requests(&server).await, 1);

        // Past the grace, the 404 stands: reads at 0, 10 and 20 s are
        // retried, the one at 30 s is not.
        let setup = setup_with(
            base_of(&server.uri()),
            FakeTokens::default(),
            Duration::from_secs(10),
            false,
            None,
        );
        let error = wait(&setup, Some(Duration::from_secs(30)))
            .await
            .unwrap_err();
        assert_eq!(error.graph_status(), Some(404));
        assert_eq!(setup.clock.sleeps(), [Duration::from_secs(10); 3]);
    }

    #[tokio::test]
    async fn ctrl_c_between_a_read_and_the_sleep_ends_the_wait_before_sleeping() {
        let server = MockServer::start().await;
        answer(&server, 1, None, status("running")).await;
        let setup = setup(&server);
        let interrupt = ManualInterrupt::default();
        let poller = Poller {
            graph: &setup.client,
            clock: setup.clock.as_ref(),
            interrupt: &interrupt,
            timing: Timing {
                timeout: Duration::from_secs(3600),
                interval: None,
            },
            not_found_grace: None,
        };
        let end = poller
            .wait(&route(), &mut Vec::new(), &mut |_, _, _| interrupt.fire())
            .await
            .unwrap();
        let PollEnd::Interrupted { last: Some(last) } = end else {
            panic!("{end:?}");
        };
        assert_eq!(last.status.as_str(), "running");
        assert!(setup.clock.sleeps().is_empty());
        assert_eq!(requests(&server).await, 1);
    }

    #[tokio::test]
    async fn a_graph_that_cannot_be_reached_is_waited_for_until_the_deadline() {
        // A port nothing listens on: every attempt fails to connect.
        let closed = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let base = base_of(&format!("http://{}", closed.local_addr().unwrap()));
        drop(closed);
        let setup = setup_with(
            base,
            FakeTokens::default(),
            Duration::from_secs(10),
            false,
            None,
        );
        let interrupt = ManualInterrupt::default();
        let poller = Poller {
            graph: &setup.client,
            clock: setup.clock.as_ref(),
            interrupt: &interrupt,
            timing: Timing {
                timeout: Duration::from_secs(15),
                interval: None,
            },
            not_found_grace: None,
        };
        let mut log = Vec::new();
        let end = poller
            .wait(&route(), &mut log, &mut |_, _, _| {})
            .await
            .unwrap();
        assert_eq!(end, PollEnd::TimedOut { last: None });
        let log = String::from_utf8(log).unwrap();
        assert!(
            log.contains("warning: reading the operation failed (could not reach Microsoft Graph"),
            "{log}"
        );
    }

    #[tokio::test]
    async fn the_interval_steps_up_after_two_minutes() {
        let server = MockServer::start().await;
        answer(&server, 1, Some(14), status("running")).await;
        answer(&server, 2, None, status("failed")).await;
        let setup = setup(&server);
        let end = wait(&setup, None).await.unwrap();
        let PollEnd::Finished(record) = end else {
            panic!("{end:?}");
        };
        assert_eq!(record.status.as_str(), "failed");
        let mut expected = vec![Duration::from_secs(10); 12];
        expected.extend([Duration::from_secs(30); 2]);
        assert_eq!(setup.clock.sleeps(), expected);
    }

    #[tokio::test]
    async fn a_transport_failure_keeps_waiting_and_a_refusal_ends_it() {
        let server = MockServer::start().await;
        answer(&server, 1, Some(3), ResponseTemplate::new(502)).await;
        answer(&server, 2, Some(1), status("running")).await;
        answer(&server, 3, None, ResponseTemplate::new(403)).await;
        let setup = setup(&server);
        let error = wait(&setup, None).await.unwrap_err();
        assert_eq!(error.graph_status(), Some(403));
        // Three 502s use the client's three attempts (0.25 s and 0.5 s
        // apart), then the poll waits its interval twice.
        assert_eq!(
            setup.clock.sleeps(),
            [
                Duration::from_millis(250),
                Duration::from_millis(500),
                Duration::from_secs(10),
                Duration::from_secs(10)
            ]
        );
    }
}
