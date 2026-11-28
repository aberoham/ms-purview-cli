//! In-process flows of `estimate` (`docs/SPEC.md` section 8.5, flows 3, 4
//! and 5) through `cli::execute_with`: the action preflight on existing
//! searches, the POST, polling, the report download and the collection
//! check, and a token that expires while the estimate is polled. Every
//! request to the mock Graph, identity platform and download origin is
//! recorded.

mod support;

use std::io::Write;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ms_purview_cli::download::DownloadRule;
use ms_purview_cli::env::Env;
use serde_json::{json, Value};
use support::*;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

const CASES: &str = "/v1.0/security/cases/ediscoveryCases";
const CASE: &str = "00000000-0000-4000-8000-000000000031";
const SEARCH: &str = "00000000-0000-4000-8000-000000000051";
const OP: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaa0001";
const OTHER_OP: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaa0002";
const ALPHA: &str = "alpha.proxyservice.ediscovery.svc.cloud.microsoft";
const FILE_PATH: &str = "/ediscovery/api/proxy/exportaedblobFileResult";
const GRAPH_TOKEN: &str = "canary-graph-access-0001";
const DOWNLOAD_TOKEN: &str = "canary-download-access-0001";

fn search_path(tail: &str) -> String {
    format!("{CASES}/{CASE}/searches/{SEARCH}{tail}")
}

fn operation_path() -> String {
    format!("{CASES}/{CASE}/operations/{OP}")
}

const LOCATIONS_HEADER: &str = "\u{feff}DataSourceName,DataSourceType,Location,LocationId,LocationType,LocationSubType,Count,Size,Status,ErrorWarning,Query\r\n";
const STATISTICS_HEADER: &str = "\u{feff}DataSourceName,DataSourceType,Location,LocationType,LocationSubType,StatType,StatName,OriginalStatName,Value\r\n";

/// An estimate zip; `failed` adds one failed location to each file.
fn estimate_zip(failed: bool) -> Vec<u8> {
    let mut locations = String::from(LOCATIONS_HEADER);
    locations.push_str("Exchange,Mailbox,alex@contoso.example,id-1,Mailbox,PrimaryMailBox,12,2048,Succeeded,,q\r\n");
    locations.push_str(
        "Exchange,Mailbox,sam@contoso.example,id-2,Mailbox,PrimaryMailBox,3,100,Succeeded,,q\r\n",
    );
    locations.push_str(
        "Exchange,Mailbox,lee@contoso.example,id-3,Mailbox,ArchiveMailBox,0,0,Succeeded,,q\r\n",
    );
    let mut statistics = String::from(STATISTICS_HEADER);
    if failed {
        locations.push_str("Exchange,Mailbox,kim@contoso.example,id-4,Mailbox,PrimaryMailBox,,,Failed,Timed out,q\r\n");
        statistics.push_str("Exchange,Mailbox,pat@fabrikam.example,Mailbox,SystemMailbox,Error,OperationCanceledException,x,0\r\n");
    }
    let rows = if failed { 4 } else { 3 };
    let summary = format!(
        "\u{feff}Job ID,j,x\r\nLocationCount,{rows},Locations\r\n\r\nStartTime (UTC),01/05/2026 9:00:00 AM,x\r\n"
    );
    let summary = summary.as_str();
    let mut buffer = std::io::Cursor::new(Vec::new());
    {
        let mut writer = zip::ZipWriter::new(&mut buffer);
        let options = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Deflated);
        for (name, body) in [
            ("Locations-2026-01-05_09-00-00.csv", locations.as_str()),
            ("Statistics-2026-01-05_09-00-00.csv", statistics.as_str()),
            ("Summary-2026-01-05_09-00-00.csv", summary),
        ] {
            writer.start_file(name, options).unwrap();
            writer.write_all(body.as_bytes()).unwrap();
        }
        writer.finish().unwrap();
    }
    buffer.into_inner()
}

struct Setup {
    harness: Harness,
    alpha: MockServer,
}

impl Setup {
    async fn new() -> Self {
        let harness = Harness::new().await;
        sign_in_alex(&harness).await;
        Self {
            harness,
            alpha: MockServer::start().await,
        }
    }

    fn data_root(&self) -> PathBuf {
        self.harness.root.path().join("data")
    }

    fn file_url(&self) -> String {
        format!(
            "http://{ALPHA}:{}{FILE_PATH}?downloadType=Report",
            self.alpha.address().port()
        )
    }

    fn configure(&self, env: &mut Env) {
        env.download_rule = DownloadRule {
            allow_http: true,
            any_port: true,
            ..DownloadRule::production()
        };
        let address: SocketAddr = *self.alpha.address();
        env.download_resolve = vec![(ALPHA.to_owned(), address)];
        env.data_dir = Some(self.data_root());
    }

    async fn run(&self, args: &[&str]) -> Run {
        let mut argv = vec!["estimate", CASE, SEARCH];
        argv.extend_from_slice(args);
        self.harness
            .run_with(&argv, |env, _| self.configure(env))
            .await
    }

    async fn get(&self, at: &str, body: Value) {
        Mock::given(method("GET"))
            .and(path(at))
            .respond_with(json_response(200, body))
            .mount(&self.harness.graph)
            .await;
    }

    /// The search, its three empty source lists, and an operation list.
    async fn preflight(&self, search: Value, operations: Value) {
        self.preflight_search(search).await;
        self.get(&format!("{CASES}/{CASE}/operations"), operations)
            .await;
    }

    /// The search and its three empty source lists.
    async fn preflight_search(&self, search: Value) {
        self.get(&search_path(""), search).await;
        for sources in [
            "custodianSources",
            "noncustodialSources",
            "additionalSources",
        ] {
            self.get(
                &search_path(&format!("/{sources}")),
                fixture_value(&self.harness, "search-sources-empty.json"),
            )
            .await;
        }
    }

    /// The POST answering 202 with `location`.
    async fn accept(&self, location: &str) {
        Mock::given(method("POST"))
            .and(path(search_path("/estimateStatistics")))
            .respond_with(ResponseTemplate::new(202).insert_header("Location", location))
            .mount(&self.harness.graph)
            .await;
    }

    fn key_form_location(&self) -> String {
        format!(
            "{}/v1.0/security/cases/ediscoverycases('{CASE}')/operations('{OP}')",
            self.harness.graph.uri()
        )
    }

    /// The operation: `running` for `polls` reads, then `last`.
    async fn operation(&self, polls: u64, last: Value) {
        if polls > 0 {
            Mock::given(method("GET"))
                .and(path(operation_path()))
                .respond_with(json_response(200, operation("running", json!([]))))
                .up_to_n_times(polls)
                .with_priority(1)
                .mount(&self.harness.graph)
                .await;
        }
        Mock::given(method("GET"))
            .and(path(operation_path()))
            .respond_with(json_response(200, last))
            .with_priority(2)
            .mount(&self.harness.graph)
            .await;
    }

    async fn serve(&self, body: Vec<u8>) {
        Mock::given(method("GET"))
            .and(path(FILE_PATH))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(body))
            .mount(&self.alpha)
            .await;
    }

    /// A whole estimate that succeeds after `polls` running reads.
    async fn ready(&self, polls: u64, failed: bool) {
        self.preflight(
            fixture_value(&self.harness, "search-get-mailboxes.json"),
            json!({"value": []}),
        )
        .await;
        self.accept(&self.key_form_location()).await;
        self.operation(polls, self.succeeded()).await;
        self.serve(estimate_zip(failed)).await;
    }

    fn succeeded(&self) -> Value {
        operation(
            "succeeded",
            json!([{"fileName": "Orders API mentions_Estimate.zip", "size": 0, "downloadUrl": self.file_url()}]),
        )
    }

    async fn graph_requests(&self) -> Vec<Request> {
        self.harness
            .graph
            .received_requests()
            .await
            .expect("the mock Graph records requests")
    }

    async fn posts(&self) -> Vec<Request> {
        self.graph_requests()
            .await
            .into_iter()
            .filter(|request| request.method.as_str() != "GET")
            .collect()
    }

    async fn downloads(&self) -> Vec<Request> {
        self.alpha
            .received_requests()
            .await
            .expect("the mock download origin records requests")
    }
}

fn fixture_value(harness: &Harness, name: &str) -> Value {
    graph_fixture(name, &harness.graph.uri())
}

fn operation(status: &str, files: Value) -> Value {
    json!({
        "@odata.type": "#microsoft.graph.security.ediscoveryEstimateOperation",
        "id": OP,
        "action": "estimateStatistics",
        "status": status,
        "createdDateTime": "2026-01-05T09:00:00Z",
        "indexedItemCount": 15,
        "indexedItemsSize": 2148,
        "unindexedItemCount": 0,
        "mailboxCount": 2,
        "reportFileMetadata": files,
    })
}

fn header(request: &Request, name: &str) -> Option<String> {
    request
        .headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned)
}

fn search_with(change: impl FnOnce(&mut Value), harness: &Harness) -> Value {
    let mut search = fixture_value(harness, "search-get-mailboxes.json");
    change(&mut search);
    search
}

// Flow 3: actions on existing searches.

#[tokio::test]
async fn a_search_without_a_scope_or_with_sites_is_refused() {
    for (change, code) in [
        (
            Box::new(|search: &mut Value| {
                search.as_object_mut().unwrap().remove("dataSourceScopes");
            }) as Box<dyn FnOnce(&mut Value)>,
            "ScopeUnverified",
        ),
        (
            Box::new(|search: &mut Value| {
                search["dataSourceScopes"] = json!("allTenantMailboxes,allTenantSites");
            }),
            "ScopeNotAllowed",
        ),
    ] {
        let setup = Setup::new().await;
        let search = search_with(change, &setup.harness);
        setup.preflight(search, json!({"value": []})).await;
        setup.accept(&setup.key_form_location()).await;
        let run = setup.run(&["--json", "--yes"]).await;
        assert_eq!(run.outcome.exit_code, 1, "{code}");
        assert_eq!(run.json()["error"]["code"], code);
        assert!(setup.posts().await.is_empty(), "{code}");
    }
}

#[tokio::test]
async fn a_search_with_sources_or_unreadable_sources_is_refused() {
    let setup = Setup::new().await;
    Mock::given(method("GET"))
        .and(path(search_path("/noncustodialSources")))
        .respond_with(json_response(
            200,
            fixture_value(&setup.harness, "search-sources-one.json"),
        ))
        .with_priority(1)
        .mount(&setup.harness.graph)
        .await;
    setup
        .preflight(
            fixture_value(&setup.harness, "search-get-mailboxes.json"),
            json!({"value": []}),
        )
        .await;
    let run = setup.run(&["--json", "--yes"]).await;
    assert_eq!(run.json()["error"]["code"], "SearchHasSources");
    assert!(setup.posts().await.is_empty());

    let setup = Setup::new().await;
    Mock::given(method("GET"))
        .and(path(search_path("/additionalSources")))
        .respond_with(json_response(
            500,
            json!({"error": {"code": "InternalServerError"}}),
        ))
        .with_priority(1)
        .mount(&setup.harness.graph)
        .await;
    setup
        .preflight(
            fixture_value(&setup.harness, "search-get-mailboxes.json"),
            json!({"value": []}),
        )
        .await;
    let run = setup.run(&["--json", "--yes"]).await;
    assert_eq!(run.json()["error"]["code"], "ScopeUnverified");
    assert!(setup.posts().await.is_empty());
}

#[tokio::test]
async fn a_portal_search_with_a_generic_query_is_refused_then_accepted_with_a_reason() {
    let setup = Setup::new().await;
    let search = search_with(
        |search| search["contentQuery"] = json!("retention"),
        &setup.harness,
    );
    setup.preflight(search, json!({"value": []})).await;
    let run = setup.run(&["--json", "--yes"]).await;
    assert_eq!(run.json()["error"]["code"], "GenericQuery");
    // The search's GET came first: its query is checked only then.
    assert!(setup
        .graph_requests()
        .await
        .iter()
        .any(|request| request.url.path() == search_path("")));
    assert!(setup.posts().await.is_empty());

    let run = setup
        .run(&[
            "--json",
            "--dry-run",
            "--allow-generic",
            "--reason",
            "Legal asked for every mention",
        ])
        .await;
    assert_eq!(run.outcome.exit_code, 0, "{}", run.stdout());
    let plan = &run.json()["results"]["plan"];
    assert!(plan["warnings"][0]
        .as_str()
        .unwrap()
        .contains("Legal asked for every mention"));
    assert_eq!(plan["preflight"][2]["contentQuery"], "retention");
    assert!(setup.posts().await.is_empty());

    // A query outside the grammar is refused even with the override.
    let setup = Setup::new().await;
    let search = search_with(
        |search| search["contentQuery"] = json!("retention policy"),
        &setup.harness,
    );
    setup.preflight(search, json!({"value": []})).await;
    let run = setup
        .run(&["--json", "--yes", "--allow-generic", "--reason", "needed"])
        .await;
    assert_eq!(run.json()["error"]["code"], "KqlNotUnderstood");
    assert!(setup.posts().await.is_empty());
}

#[tokio::test]
async fn an_estimate_not_yet_finished_needs_allow_concurrent() {
    let setup = Setup::new().await;
    let running = json!({"value": [
        {"id": OTHER_OP, "action": "estimateStatistics", "status": "running", "createdDateTime": "2026-01-05T08:00:00Z"},
        {"id": "aaaaaaaaaaaaaaaaaaaaaaaaaaaa0003", "action": "exportResult", "status": "running"},
        {"id": "aaaaaaaaaaaaaaaaaaaaaaaaaaaa0004", "action": "estimateStatistics", "status": "succeeded"},
    ]});
    setup
        .preflight(
            fixture_value(&setup.harness, "search-get-mailboxes.json"),
            running,
        )
        .await;
    setup.accept(&setup.key_form_location()).await;
    setup.operation(0, setup.succeeded()).await;
    setup.serve(estimate_zip(false)).await;

    let run = setup.run(&["--json", "--yes"]).await;
    assert_eq!(run.outcome.exit_code, 1);
    let error = &run.json()["error"];
    assert_eq!(error["code"], "ConcurrentOperation");
    let message = error["message"].as_str().unwrap();
    assert!(message.contains(OTHER_OP), "{message}");
    assert!(
        !message.contains("aaaaaaaaaaaaaaaaaaaaaaaaaaaa0003"),
        "{message}"
    );
    assert!(setup.posts().await.is_empty());

    let run = setup.run(&["--json", "--dry-run"]).await;
    assert_eq!(run.outcome.exit_code, 0, "{}", run.stdout());
    assert!(run.json()["results"]["plan"]["warnings"][0]
        .as_str()
        .unwrap()
        .contains("may be a duplicate"));

    let run = setup.run(&["--json", "--yes", "--allow-concurrent"]).await;
    assert_eq!(run.outcome.exit_code, 0, "{}", run.stdout());
    assert_eq!(setup.posts().await.len(), 1);
}

// Flow 4: estimate.

#[tokio::test]
async fn an_estimate_posts_once_polls_downloads_and_checks_the_collection() {
    let setup = Setup::new().await;
    setup.ready(3, false).await;
    let run = setup.run(&["--json", "--yes"]).await;
    assert_eq!(
        run.outcome.exit_code,
        0,
        "{} {}",
        run.stdout(),
        run.stderr()
    );
    let posts = setup.posts().await;
    assert_eq!(posts.len(), 1);
    assert_eq!(
        String::from_utf8_lossy(&posts[0].body),
        "{\"statisticsOptions\":\"includeQueryStats\"}"
    );
    let result = &run.json()["results"]["result"];
    assert_eq!(result["operationId"], OP);
    assert_eq!(result["operationStatus"], "succeeded");
    assert_eq!(result["collection"], "complete");
    assert_eq!(result["indexedItemCount"], 15);
    assert_eq!(result["mailboxCount"], 2);
    assert_eq!(result["locationsSearched"], 3);
    assert_eq!(result["topLocations"].as_array().unwrap().len(), 2);
    assert_eq!(
        result["topLocations"][0]["location"],
        "alex@contoso.example"
    );
    assert_eq!(result["failedLocations"], json!([]));
    // Under the default limits, every check ran and none was passed.
    assert_eq!(result["volume"]["exceeded"], false);
    assert_eq!(result["volume"]["over"], json!([]));
    assert_eq!(result["volume"]["unchecked"], json!([]));
    assert_eq!(result["volume"]["limits"]["warn_hits"], 5000);
    assert!(!run.stderr().contains("VOLUME"), "{}", run.stderr());
    let file = PathBuf::from(result["files"][0]["path"].as_str().unwrap());
    assert!(file.starts_with(setup.data_root().join("cases").join(CASE).join(OP)));
    assert!(file.exists());
    // Four reads of the operation: three running, then succeeded.
    let polls = setup
        .graph_requests()
        .await
        .iter()
        .filter(|request| request.url.path() == operation_path())
        .count();
    assert_eq!(polls, 4);

    // The download carries the download token and the header, and the
    // tokens stay with their origins.
    let downloads = setup.downloads().await;
    assert_eq!(downloads.len(), 1);
    assert_eq!(
        header(&downloads[0], "authorization").as_deref(),
        Some(format!("Bearer {DOWNLOAD_TOKEN}").as_str())
    );
    assert_eq!(
        header(&downloads[0], "x-allowwithaadtoken").as_deref(),
        Some("true")
    );
    for request in setup.graph_requests().await {
        assert_eq!(
            header(&request, "authorization").as_deref(),
            Some(format!("Bearer {GRAPH_TOKEN}").as_str())
        );
    }
}

#[tokio::test]
async fn failed_locations_are_incomplete_and_strict_exits_4() {
    let setup = Setup::new().await;
    setup.ready(0, true).await;
    let run = setup.run(&["--json", "--yes"]).await;
    assert_eq!(run.outcome.exit_code, 0, "{}", run.stdout());
    let result = &run.json()["results"]["result"];
    assert_eq!(result["collection"], "incomplete");
    assert_eq!(result["failedLocations"].as_array().unwrap().len(), 2);
    assert!(
        run.stderr()
            .contains("2 locations were not searched in full"),
        "{}",
        run.stderr()
    );

    let run = setup
        .run(&["--json", "--yes", "--strict", "--results-only"])
        .await;
    assert_eq!(run.outcome.exit_code, 4, "{}", run.stdout());
    let document = run.json();
    assert_eq!(document["outcome"]["code"], "Incomplete");
    assert_eq!(document["outcome"]["reasons"][0]["code"], "FailedLocations");
    // Exit 4 prints the whole envelope, --results-only or not.
    assert_eq!(document["results"]["result"]["collection"], "incomplete");
}

#[tokio::test]
async fn no_download_is_unchecked_and_strict_cannot_be_combined_with_it() {
    let setup = Setup::new().await;
    setup.ready(0, true).await;
    let run = setup.run(&["--json", "--yes", "--no-download"]).await;
    assert_eq!(run.outcome.exit_code, 0, "{}", run.stdout());
    assert_eq!(run.json()["results"]["result"]["collection"], "unchecked");
    assert!(setup.downloads().await.is_empty());
    for extra in [&["--no-download"][..], &["--no-wait"]] {
        let mut args = vec!["--json", "--yes", "--strict"];
        args.extend_from_slice(extra);
        let run = setup.run(&args).await;
        assert_eq!(run.outcome.exit_code, 1, "{extra:?}");
        assert_eq!(run.json()["error"]["code"], "CommandFailed");
    }
    assert_eq!(setup.posts().await.len(), 1);
}

#[tokio::test]
async fn a_report_zip_without_statistics_is_unchecked_and_strict_exits_4() {
    let setup = Setup::new().await;
    setup
        .preflight(
            fixture_value(&setup.harness, "search-get-mailboxes.json"),
            json!({"value": []}),
        )
        .await;
    setup.accept(&setup.key_form_location()).await;
    setup.operation(0, setup.succeeded()).await;
    let mut buffer = std::io::Cursor::new(Vec::new());
    {
        let mut writer = zip::ZipWriter::new(&mut buffer);
        writer
            .start_file("Summary-1.csv", zip::write::SimpleFileOptions::default())
            .unwrap();
        writer.write_all(b"Job ID,j,x\r\n").unwrap();
        // Locations without Statistics: an estimate needs both.
        writer
            .start_file("Locations-1.csv", zip::write::SimpleFileOptions::default())
            .unwrap();
        writer
            .write_all(
                format!(
                    "{LOCATIONS_HEADER}Exchange,Mailbox,alex@contoso.example,id-1,Mailbox,PrimaryMailBox,12,2048,Succeeded,,q\r\n"
                )
                .as_bytes(),
            )
            .unwrap();
        writer.finish().unwrap();
    }
    setup.serve(buffer.into_inner()).await;
    let run = setup.run(&["--json", "--yes", "--strict"]).await;
    assert_eq!(run.outcome.exit_code, 4, "{}", run.stdout());
    let document = run.json();
    assert_eq!(document["results"]["result"]["collection"], "unchecked");
    assert_eq!(document["outcome"]["reasons"][0]["code"], "EvidenceMissing");
}

#[tokio::test]
async fn no_wait_submits_and_prints_the_commands_that_carry_on() {
    let setup = Setup::new().await;
    setup.ready(0, false).await;
    let run = setup.run(&["--json", "--yes", "--no-wait"]).await;
    assert_eq!(run.outcome.exit_code, 0, "{}", run.stdout());
    let result = &run.json()["results"]["result"];
    assert_eq!(result["operationId"], OP);
    assert_eq!(result["collection"], "unchecked");
    assert!(result["resume"][0]
        .as_str()
        .unwrap()
        .ends_with(&format!("operation get {CASE} {OP} --wait")));
    assert!(setup
        .graph_requests()
        .await
        .iter()
        .all(|request| request.url.path() != operation_path()));
    assert!(setup.downloads().await.is_empty());
}

#[tokio::test]
async fn a_location_for_another_case_or_host_stops_after_the_one_post() {
    for location in [
        format!(
            "{{graph}}/v1.0/security/cases/ediscoverycases('00000000-0000-4000-8000-000000000032')/operations('{OP}')"
        ),
        format!("https://graph.contoso.example/v1.0/security/cases/ediscoverycases('{CASE}')/operations('{OP}')"),
        String::new(),
    ] {
        let setup = Setup::new().await;
        setup
            .preflight(
                fixture_value(&setup.harness, "search-get-mailboxes.json"),
                json!({"value": []}),
            )
            .await;
        let location = location.replace("{graph}", &setup.harness.graph.uri());
        setup.accept(&location).await;
        setup.operation(0, setup.succeeded()).await;
        let run = setup.run(&["--json", "--yes"]).await;
        assert_eq!(run.outcome.exit_code, 1, "{location}");
        let error = &run.json()["error"];
        assert_eq!(error["code"], "UnexpectedLocation", "{location}");
        assert!(
            error["message"].as_str().unwrap().contains("operation list"),
            "{location}"
        );
        assert_eq!(setup.posts().await.len(), 1);
        assert!(setup
            .graph_requests()
            .await
            .iter()
            .all(|request| request.url.path() != operation_path()));
    }
}

#[tokio::test]
async fn the_path_form_location_is_accepted() {
    let setup = Setup::new().await;
    setup
        .preflight(
            fixture_value(&setup.harness, "search-get-mailboxes.json"),
            json!({"value": []}),
        )
        .await;
    setup
        .accept(&format!(
            "{}/v1.0/security/cases/ediscoveryCases/{CASE}/operations/{OP}",
            setup.harness.graph.uri()
        ))
        .await;
    setup.operation(1, setup.succeeded()).await;
    setup.serve(estimate_zip(false)).await;
    let run = setup.run(&["--json", "--yes"]).await;
    assert_eq!(run.outcome.exit_code, 0, "{}", run.stdout());
}

#[tokio::test]
async fn the_wait_deadline_exits_5_with_the_commands_that_resume() {
    let setup = Setup::new().await;
    setup
        .preflight(
            fixture_value(&setup.harness, "search-get-mailboxes.json"),
            json!({"value": []}),
        )
        .await;
    setup.accept(&setup.key_form_location()).await;
    setup.operation(1000, setup.succeeded()).await;
    let run = setup
        .run(&[
            "--json",
            "--yes",
            "--wait-timeout",
            "1m",
            "--poll-interval",
            "10s",
        ])
        .await;
    assert_eq!(run.outcome.exit_code, 5, "{}", run.stdout());
    let document = run.json();
    assert_eq!(document["error"]["code"], "WaitTimeout");
    assert_eq!(document["operationId"], OP);
    assert!(document["resume"][1]
        .as_str()
        .unwrap()
        .ends_with(&format!("download {CASE} {OP}")));
    assert!(setup.downloads().await.is_empty());
}

#[tokio::test]
async fn an_unclear_estimate_lists_operations_started_since_as_candidates() {
    let setup = Setup::new().await;
    setup
        .preflight_search(fixture_value(&setup.harness, "search-get-mailboxes.json"))
        .await;
    // The preflight list and its read after approval are empty; the
    // reconciliation list has the new estimate, an older one and another
    // account's.
    Mock::given(method("GET"))
        .and(path(format!("{CASES}/{CASE}/operations")))
        .respond_with(json_response(200, json!({"value": []})))
        .up_to_n_times(2)
        .with_priority(1)
        .mount(&setup.harness.graph)
        .await;
    setup
        .get(
            &format!("{CASES}/{CASE}/operations"),
            json!({"value": [
                {"id": OP, "action": "estimateStatistics", "status": "running", "createdDateTime": "2026-01-05T09:00:30Z"},
                {"id": OTHER_OP, "action": "estimateStatistics", "status": "succeeded", "createdDateTime": "2026-01-01T09:00:00Z"},
                {"id": "aaaaaaaaaaaaaaaaaaaaaaaaaaaa0005", "action": "estimateStatistics", "status": "running", "createdDateTime": "2026-01-05T09:00:40Z",
                 "createdBy": {"user": {"id": "00000000-0000-4000-8000-000000000099"}}},
            ]}),
        )
        .await;
    Mock::given(method("POST"))
        .and(path(search_path("/estimateStatistics")))
        .respond_with(json_response(
            503,
            json!({"error": {"code": "ServiceUnavailable"}}),
        ))
        .mount(&setup.harness.graph)
        .await;
    let run = setup.run(&["--json", "--yes"]).await;
    assert_eq!(run.outcome.exit_code, 1);
    let error = &run.json()["error"];
    assert_eq!(error["code"], "WriteOutcomeUnknown");
    let message = error["message"].as_str().unwrap();
    assert!(
        message.contains(&format!("estimate {OP} (running")),
        "{message}"
    );
    assert!(!message.contains(OTHER_OP), "{message}");
    assert!(
        !message.contains("aaaaaaaaaaaaaaaaaaaaaaaaaaaa0005"),
        "{message}"
    );
    assert_eq!(setup.posts().await.len(), 1);
}

#[tokio::test]
async fn a_human_run_shows_the_plan_and_the_result() {
    let setup = Setup::new().await;
    setup.ready(0, true).await;
    let run = setup.run(&["--yes"]).await;
    assert_eq!(run.outcome.exit_code, 0, "{}", run.stderr());
    let stderr = run.stderr();
    assert!(stderr.contains("Plan: purview estimate"), "{stderr}");
    assert!(
        stderr.contains("{\"contentQuery\":\"participants:alex@contoso.example"),
        "{stderr}"
    );
    let stdout = run.stdout();
    assert!(
        stdout.starts_with("Applied: purview estimate\n"),
        "{stdout}"
    );
    assert!(
        stdout.contains("\"collection\": \"incomplete\""),
        "{stdout}"
    );
}

/// Writes `volume` into config.json, keeping the rest.
fn set_volume(harness: &Harness, volume: Value) {
    let file = harness.config_dir().join("config.json");
    let mut config = harness.config();
    config["volume"] = volume;
    std::fs::write(&file, serde_json::to_vec_pretty(&config).unwrap()).unwrap();
}

#[tokio::test]
async fn an_estimate_above_the_volume_limits_warns_loudly_and_still_succeeds() {
    let setup = Setup::new().await;
    setup.ready(0, false).await;
    // The fixture: 15 items, 2,148 bytes, and locations of 12, 3 and 0 hits.
    set_volume(
        &setup.harness,
        json!({"warn_hits": 14, "warn_hits_per_location": 2, "max_export_size": "2KiB"}),
    );
    let run = setup.run(&["--json", "--yes"]).await;
    assert_eq!(run.outcome.exit_code, 0, "{}", run.stdout());
    let volume = &run.json()["results"]["result"]["volume"];
    assert_eq!(volume["exceeded"], true);
    assert_eq!(
        volume["over"],
        json!([
            {"setting": "volume.warn_hits", "value": 15, "limit": 14},
            {"setting": "volume.warn_hits_per_location", "value": 12, "limit": 2, "locations": 2},
            {"setting": "volume.max_export_size", "value": 2148, "limit": 2048},
        ])
    );
    let stderr = run.stderr();
    assert!(
        stderr.contains(
            "warning: VOLUME: the estimate found 15 items, more than volume.warn_hits (14)"
        ),
        "{stderr}"
    );
    assert!(
        stderr.contains(
            "2 locations have more than volume.warn_hits_per_location (2) hits; the largest has 12"
        ),
        "{stderr}"
    );
    assert!(
        stderr.contains("more than volume.max_export_size (2.0 KiB)"),
        "{stderr}"
    );
    assert!(stderr.contains("narrow the query"), "{stderr}");
    // The warning names no location.
    assert!(!stderr.contains("alex@contoso.example"), "{stderr}");
    // --strict is about the collection, not the volume.
    let run = setup.run(&["--json", "--yes", "--strict"]).await;
    assert_eq!(run.outcome.exit_code, 0, "{}", run.stdout());
    // A human run warns on stderr and shows volume in the result.
    let run = setup.run(&["--yes"]).await;
    assert_eq!(run.outcome.exit_code, 0, "{}", run.stderr());
    assert!(
        run.stderr().contains("warning: VOLUME:"),
        "{}",
        run.stderr()
    );
    assert!(
        run.stdout().contains("\"exceeded\": true"),
        "{}",
        run.stdout()
    );
}

#[tokio::test]
async fn without_the_zip_hits_per_location_are_unchecked() {
    let setup = Setup::new().await;
    setup.ready(0, false).await;
    set_volume(&setup.harness, json!({"warn_hits": 14}));
    let run = setup.run(&["--json", "--yes", "--no-download"]).await;
    assert_eq!(run.outcome.exit_code, 0, "{}", run.stdout());
    let volume = &run.json()["results"]["result"]["volume"];
    assert_eq!(volume["exceeded"], true);
    assert_eq!(volume["over"][0]["setting"], "volume.warn_hits");
    assert_eq!(
        volume["unchecked"],
        json!(["volume.warn_hits_per_location"])
    );
    assert!(
        run.stderr().contains("warning: VOLUME:"),
        "{}",
        run.stderr()
    );
    // --no-wait has no counts, so no volume.
    let run = setup.run(&["--json", "--yes", "--no-wait"]).await;
    assert_eq!(run.outcome.exit_code, 0, "{}", run.stdout());
    assert!(run.json()["results"]["result"].get("volume").is_none());
}

#[tokio::test]
async fn a_bad_volume_setting_stops_the_estimate_before_any_request() {
    let setup = Setup::new().await;
    setup.ready(0, false).await;
    set_volume(&setup.harness, json!({"max_export_size": "huge"}));
    let identity_before = setup
        .harness
        .identity
        .received_requests()
        .await
        .unwrap()
        .len();
    let run = setup.run(&["--json", "--yes"]).await;
    assert_eq!(run.outcome.exit_code, 1, "{}", run.stdout());
    let message = run.json()["error"]["message"].as_str().unwrap().to_owned();
    assert!(message.contains("volume.max_export_size"), "{message}");
    assert!(!message.contains("huge"), "{message}");
    assert_eq!(run.stderr(), "");
    assert!(setup.graph_requests().await.is_empty());
    assert_eq!(
        setup
            .harness
            .identity
            .received_requests()
            .await
            .unwrap()
            .len(),
        identity_before
    );

    // With no account signed in, the setting is still the error.
    let harness = Harness::new().await;
    let dir = harness.config_dir();
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("config.json"),
        serde_json::to_vec(&json!({"volume": {"warn_hits": -1}})).unwrap(),
    )
    .unwrap();
    let run = harness
        .run(&["--json", "estimate", CASE, SEARCH, "--yes"])
        .await;
    assert_eq!(run.outcome.exit_code, 1, "{}", run.stdout());
    let message = run.json()["error"]["message"].as_str().unwrap().to_owned();
    assert!(message.contains("volume.warn_hits"), "{message}");
}

#[tokio::test]
async fn a_failed_estimate_uses_none_of_its_counts() {
    let setup = Setup::new().await;
    setup
        .preflight(
            fixture_value(&setup.harness, "search-get-mailboxes.json"),
            json!({"value": []}),
        )
        .await;
    setup.accept(&setup.key_form_location()).await;
    setup.operation(0, operation("failed", json!([]))).await;
    set_volume(
        &setup.harness,
        json!({"warn_hits": 1, "max_export_size": "1KiB"}),
    );
    let run = setup.run(&["--json", "--yes"]).await;
    assert_eq!(run.outcome.exit_code, 4, "{}", run.stdout());
    let volume = &run.json()["results"]["result"]["volume"];
    assert_eq!(volume["exceeded"], false);
    assert_eq!(
        volume["unchecked"],
        json!([
            "volume.warn_hits",
            "volume.warn_hits_per_location",
            "volume.max_export_size"
        ])
    );
    assert!(!run.stderr().contains("VOLUME"), "{}", run.stderr());
}

#[tokio::test]
async fn a_count_graph_gives_as_another_type_is_unchecked_and_named() {
    let setup = Setup::new().await;
    setup
        .preflight(
            fixture_value(&setup.harness, "search-get-mailboxes.json"),
            json!({"value": []}),
        )
        .await;
    setup.accept(&setup.key_form_location()).await;
    let mut last = setup.succeeded();
    last["indexedItemCount"] = json!(-5);
    setup.operation(0, last).await;
    setup.serve(estimate_zip(false)).await;
    let run = setup.run(&["--json", "--yes"]).await;
    assert_eq!(run.outcome.exit_code, 0, "{}", run.stdout());
    assert_eq!(
        run.json()["results"]["result"]["volume"]["unchecked"],
        json!(["volume.warn_hits"])
    );
    assert!(
        run.stderr()
            .contains("has fields that are not counts (indexedItemCount)"),
        "{}",
        run.stderr()
    );
}

/// The estimate zip with the file whose name starts with `prefix`
/// replaced by `body`.
fn estimate_zip_replacing(prefix: &str, body: &str) -> Vec<u8> {
    let mut zip = zip::ZipArchive::new(std::io::Cursor::new(estimate_zip(false))).unwrap();
    let mut buffer = std::io::Cursor::new(Vec::new());
    {
        let mut writer = zip::ZipWriter::new(&mut buffer);
        for index in 0..zip.len() {
            let entry = zip.by_index(index).unwrap();
            if entry.name().unwrap().starts_with(prefix) {
                let name = entry.name().unwrap().into_owned();
                drop(entry);
                writer
                    .start_file(name, zip::write::SimpleFileOptions::default())
                    .unwrap();
                writer.write_all(body.as_bytes()).unwrap();
            } else {
                writer.raw_copy_file(entry).unwrap();
            }
        }
        writer.finish().unwrap();
    }
    buffer.into_inner()
}

#[tokio::test]
async fn a_failed_location_with_a_count_leaves_hits_per_location_unchecked() {
    let failed_row = format!(
        "{LOCATIONS_HEADER}Exchange,Mailbox,alex@contoso.example,id-1,Mailbox,PrimaryMailBox,0,0,Failed,Timed out,q\r\n"
    );
    let statistics_error = format!(
        "{STATISTICS_HEADER}Exchange,Mailbox,pat@fabrikam.example,Mailbox,SystemMailbox,Error,OperationCanceledException,x,0\r\n"
    );
    for zip in [
        estimate_zip_replacing("Locations-", &failed_row),
        estimate_zip_replacing("Statistics-", &statistics_error),
    ] {
        let setup = Setup::new().await;
        setup
            .preflight(
                fixture_value(&setup.harness, "search-get-mailboxes.json"),
                json!({"value": []}),
            )
            .await;
        setup.accept(&setup.key_form_location()).await;
        setup.operation(0, setup.succeeded()).await;
        setup.serve(zip).await;
        let run = setup.run(&["--json", "--yes"]).await;
        assert_eq!(run.outcome.exit_code, 0, "{}", run.stdout());
        let result = &run.json()["results"]["result"];
        assert_eq!(result["collection"], "incomplete");
        assert_eq!(
            result["volume"]["unchecked"],
            json!(["volume.warn_hits_per_location"])
        );
    }
}

#[tokio::test]
async fn a_partial_success_leaves_hits_per_location_unchecked() {
    let setup = Setup::new().await;
    setup
        .preflight(
            fixture_value(&setup.harness, "search-get-mailboxes.json"),
            json!({"value": []}),
        )
        .await;
    setup.accept(&setup.key_form_location()).await;
    let mut last = setup.succeeded();
    last["status"] = json!("partiallySucceeded");
    setup.operation(0, last).await;
    setup.serve(estimate_zip(false)).await;
    set_volume(&setup.harness, json!({"warn_hits": 14}));
    let run = setup.run(&["--json", "--yes"]).await;
    let result = &run.json()["results"]["result"];
    assert_eq!(result["collection"], "complete", "{}", run.stdout());
    // Its counts are still used, and its hits per location unchecked.
    assert_eq!(result["volume"]["over"][0]["setting"], "volume.warn_hits");
    assert_eq!(
        result["volume"]["unchecked"],
        json!(["volume.warn_hits_per_location"])
    );
}

#[tokio::test]
async fn a_second_locations_file_leaves_hits_per_location_unchecked() {
    let setup = Setup::new().await;
    setup
        .preflight(
            fixture_value(&setup.harness, "search-get-mailboxes.json"),
            json!({"value": []}),
        )
        .await;
    setup.accept(&setup.key_form_location()).await;
    setup.operation(0, setup.succeeded()).await;
    // The estimate zip, with a second Locations file whose one row has
    // more hits than the limit.
    let mut zip = zip::ZipArchive::new(std::io::Cursor::new(estimate_zip(false))).unwrap();
    let mut buffer = std::io::Cursor::new(Vec::new());
    {
        let mut writer = zip::ZipWriter::new(&mut buffer);
        for index in 0..zip.len() {
            writer.raw_copy_file(zip.by_index(index).unwrap()).unwrap();
        }
        let options = zip::write::SimpleFileOptions::default();
        writer
            .start_file("Locations-2026-01-05_09-30-00.csv", options)
            .unwrap();
        writer
            .write_all(
                format!(
                    "{LOCATIONS_HEADER}Exchange,Mailbox,sam@contoso.example,id-2,Mailbox,PrimaryMailBox,5000,9,Succeeded,,q\r\n"
                )
                .as_bytes(),
            )
            .unwrap();
        writer.finish().unwrap();
    }
    setup.serve(buffer.into_inner()).await;
    let run = setup.run(&["--json", "--yes"]).await;
    assert_eq!(run.outcome.exit_code, 0, "{}", run.stdout());
    let volume = &run.json()["results"]["result"]["volume"];
    assert_eq!(volume["exceeded"], false);
    assert_eq!(
        volume["unchecked"],
        json!(["volume.warn_hits_per_location"])
    );
}

// Flow 5: the Graph token expires while the estimate is polled.

/// Answers with `response` and appends `label` to a log shared by every
/// mock, so that a test can see the order across origins.
#[derive(Clone)]
struct Logged {
    log: Arc<Mutex<Vec<&'static str>>>,
    label: &'static str,
    response: ResponseTemplate,
}

impl Respond for Logged {
    fn respond(&self, _request: &Request) -> ResponseTemplate {
        self.log.lock().unwrap().push(self.label);
        self.response.clone()
    }
}

#[tokio::test]
async fn a_token_that_expires_while_polling_is_refreshed_before_the_next_read() {
    let setup = Setup::new().await;
    let log: Arc<Mutex<Vec<&'static str>>> = Arc::default();
    let logged = |label: &'static str, response: ResponseTemplate| Logged {
        log: log.clone(),
        label,
        response,
    };
    setup
        .preflight(
            fixture_value(&setup.harness, "search-get-mailboxes.json"),
            json!({"value": []}),
        )
        .await;
    setup.accept(&setup.key_form_location()).await;
    Mock::given(method("GET"))
        .and(path(operation_path()))
        .respond_with(logged(
            "poll running",
            json_response(200, operation("running", json!([]))),
        ))
        .up_to_n_times(40)
        .with_priority(1)
        .mount(&setup.harness.graph)
        .await;
    Mock::given(method("GET"))
        .and(path(operation_path()))
        .respond_with(logged(
            "poll succeeded",
            json_response(200, setup.succeeded()),
        ))
        .with_priority(2)
        .mount(&setup.harness.graph)
        .await;
    Mock::given(method("GET"))
        .and(path(FILE_PATH))
        .respond_with(logged(
            "file",
            ResponseTemplate::new(200).set_body_bytes(estimate_zip(false)),
        ))
        .mount(&setup.alpha)
        .await;
    // The download redemption names its own resource; any other token
    // request is the Graph refresh.
    Mock::given(method("POST"))
        .and(path(token_path("token")))
        .and(Form::new(&[(
            "scope",
            "b26e684c-5068-4120-a679-64a5d2c909d9/.default offline_access",
        )]))
        .respond_with(logged(
            "download token",
            json_response(200, fixture("token-download.json")),
        ))
        .with_priority(1)
        .mount(&setup.harness.identity)
        .await;
    Mock::given(method("POST"))
        .and(path(token_path("token")))
        .respond_with(logged(
            "graph refresh",
            json_response(200, fixture("token-poll-window.json")),
        ))
        .with_priority(2)
        .mount(&setup.harness.identity)
        .await;
    // Six minutes of the Graph token left: enough for the POST, which
    // needs five, and not for the 400 seconds of polling, since a read
    // needs one.
    setup.harness.clock.advance(Duration::from_secs(4271 - 360));
    let run = setup
        .run(&["--json", "--yes", "--poll-interval", "10s"])
        .await;
    assert_eq!(
        run.outcome.exit_code,
        0,
        "{} {}",
        run.stdout(),
        run.stderr()
    );
    let posts = setup.posts().await;
    assert_eq!(posts.len(), 1);
    assert_eq!(
        header(&posts[0], "authorization").as_deref(),
        Some(format!("Bearer {GRAPH_TOKEN}").as_str()),
        "the POST went out with no refresh"
    );
    let events = log.lock().unwrap().clone();
    let at = |label: &str| events.iter().position(|event| *event == label);
    let count = |label: &str| events.iter().filter(|event| **event == label).count();
    assert_eq!(count("graph refresh"), 1, "{events:?}");
    assert_eq!(count("poll running"), 40, "{events:?}");
    assert_eq!(count("poll succeeded"), 1, "{events:?}");
    let refresh = at("graph refresh").unwrap();
    let last_poll = at("poll succeeded").unwrap();
    let redemption = at("download token").expect("the download token was redeemed");
    let file = at("file").expect("the file was downloaded");
    // A refresh during polling, with reads on both sides of it; then,
    // only after the last read, the download token and the file.
    assert!(refresh > 0 && refresh < last_poll, "{events:?}");
    assert!(last_poll < redemption, "{events:?}");
    assert!(redemption < file, "{events:?}");
    // Reads before the refresh used the old token, those after it the new.
    let polls: Vec<String> = setup
        .graph_requests()
        .await
        .iter()
        .filter(|request| request.url.path() == operation_path())
        .map(|request| header(request, "authorization").unwrap_or_default())
        .collect();
    let first_new = polls
        .iter()
        .position(|token| token.ends_with("canary-graph-access-0002"))
        .expect("a read after the refresh");
    assert!(first_new > 0);
    assert!(polls[first_new..]
        .iter()
        .all(|token| token.ends_with("canary-graph-access-0002")));
}

// operation get --check.

impl Setup {
    async fn run_raw(&self, args: &[&str]) -> Run {
        self.harness
            .run_with(args, |env, _| self.configure(env))
            .await
    }
}

#[tokio::test]
async fn check_reads_the_evidence_and_a_later_download_reuses_it() {
    let setup = Setup::new().await;
    setup.operation(0, setup.succeeded()).await;
    setup.serve(estimate_zip(true)).await;
    let run = setup
        .run_raw(&["--json", "operation", "get", CASE, OP, "--check"])
        .await;
    assert_eq!(
        run.outcome.exit_code,
        0,
        "{} {}",
        run.stdout(),
        run.stderr()
    );
    assert_eq!(run.json()["results"]["collection"], "incomplete");
    assert_eq!(setup.downloads().await.len(), 1);

    let run = setup.run_raw(&["--json", "download", CASE, OP]).await;
    assert_eq!(run.outcome.exit_code, 0, "{}", run.stdout());
    assert_eq!(run.json()["results"][0]["status"], "alreadyDownloaded");
    assert_eq!(setup.downloads().await.len(), 1, "fetched once");

    // Without --check, nothing is downloaded and it stays unchecked.
    let run = setup
        .run_raw(&["--json", "operation", "get", CASE, OP])
        .await;
    assert_eq!(run.json()["results"]["collection"], "unchecked");
    assert_eq!(setup.downloads().await.len(), 1);
}

#[tokio::test]
async fn check_on_a_running_operation_downloads_nothing() {
    let setup = Setup::new().await;
    setup.operation(0, operation("running", json!([]))).await;
    let run = setup
        .run_raw(&["--json", "operation", "get", CASE, OP, "--check"])
        .await;
    assert_eq!(run.outcome.exit_code, 0, "{}", run.stdout());
    assert_eq!(run.json()["results"]["collection"], "unchecked");
    assert!(run.stderr().contains("not finished"), "{}", run.stderr());
    assert!(setup.downloads().await.is_empty());
}

/// A fresh operation that is not visible yet answers 404 at first; the
/// wait reads it again instead of failing.
#[tokio::test]
async fn a_new_operation_not_yet_visible_is_read_again() {
    let setup = Setup::new().await;
    setup
        .preflight(
            fixture_value(&setup.harness, "search-get-mailboxes.json"),
            json!({"value": []}),
        )
        .await;
    setup.accept(&setup.key_form_location()).await;
    Mock::given(method("GET"))
        .and(path(operation_path()))
        .respond_with(json_response(
            404,
            json!({"error": {"code": "NotFound", "message": "not found"}}),
        ))
        .up_to_n_times(1)
        .with_priority(1)
        .mount(&setup.harness.graph)
        .await;
    setup.operation(0, setup.succeeded()).await;
    setup.serve(estimate_zip(false)).await;
    let run = setup.run(&["--json", "--yes"]).await;
    assert_eq!(
        run.outcome.exit_code,
        0,
        "{} {}",
        run.stdout(),
        run.stderr()
    );
    assert!(run.stderr().contains("not visible yet"), "{}", run.stderr());
}

// Round-1 review fixes.

#[tokio::test]
async fn a_search_that_changes_after_the_plan_is_not_estimated() {
    let setup = Setup::new().await;
    // The plan reads the query; the read after approval sees another.
    Mock::given(method("GET"))
        .and(path(search_path("")))
        .respond_with(json_response(
            200,
            fixture_value(&setup.harness, "search-get-mailboxes.json"),
        ))
        .up_to_n_times(1)
        .with_priority(1)
        .mount(&setup.harness.graph)
        .await;
    let changed = search_with(
        |search| {
            search["contentQuery"] = json!("participants:sam@contoso.example AND \"orders-api\"")
        },
        &setup.harness,
    );
    setup.preflight(changed, json!({"value": []})).await;
    setup.accept(&setup.key_form_location()).await;
    let run = setup.run(&["--json", "--yes"]).await;
    assert_eq!(run.outcome.exit_code, 1, "{}", run.stdout());
    assert_eq!(run.json()["error"]["code"], "SearchChanged");
    assert!(setup.posts().await.is_empty());
}

#[tokio::test]
async fn an_operation_that_is_not_an_estimate_is_not_downloaded() {
    let setup = Setup::new().await;
    setup
        .preflight(
            fixture_value(&setup.harness, "search-get-mailboxes.json"),
            json!({"value": []}),
        )
        .await;
    setup.accept(&setup.key_form_location()).await;
    let export = json!({
        "@odata.type": "#microsoft.graph.security.ediscoverySearchExportOperation",
        "id": OP,
        "action": "exportResult",
        "status": "succeeded",
        "exportFileMetadata": [{"fileName": "Items.1.001.zip", "size": 10, "downloadUrl": setup.file_url()}],
    });
    setup.operation(0, export).await;
    setup.serve(estimate_zip(false)).await;
    let run = setup.run(&["--json", "--yes"]).await;
    assert_eq!(run.outcome.exit_code, 1, "{}", run.stdout());
    assert_eq!(run.json()["error"]["code"], "UnexpectedLocation");
    assert!(setup.downloads().await.is_empty());
    assert!(setup
        .harness
        .identity
        .received_requests()
        .await
        .expect("recorded")
        .is_empty());
}

#[tokio::test]
async fn an_answer_other_than_202_stops_before_polling() {
    let setup = Setup::new().await;
    setup
        .preflight(
            fixture_value(&setup.harness, "search-get-mailboxes.json"),
            json!({"value": []}),
        )
        .await;
    Mock::given(method("POST"))
        .and(path(search_path("/estimateStatistics")))
        .respond_with(
            json_response(200, json!({"id": OP}))
                .insert_header("Location", setup.key_form_location().as_str()),
        )
        .mount(&setup.harness.graph)
        .await;
    let run = setup.run(&["--json", "--yes"]).await;
    assert_eq!(run.json()["error"]["code"], "UnexpectedLocation");
    assert!(setup
        .graph_requests()
        .await
        .iter()
        .all(|request| request.url.path() != operation_path()));
}

#[tokio::test]
async fn a_signed_url_in_a_failure_reason_is_redacted() {
    let setup = Setup::new().await;
    setup
        .preflight(
            fixture_value(&setup.harness, "search-get-mailboxes.json"),
            json!({"value": []}),
        )
        .await;
    setup.accept(&setup.key_form_location()).await;
    let signed = ["https://", "files.contoso.example/r?sig=canary-sig-0077"].concat();
    let mut failed = operation("failed", json!([]));
    failed["resultInfo"] = json!({"code": 1, "message": format!("see {signed}")});
    setup.operation(0, failed).await;
    for args in [
        &["--json", "--yes", "--no-download"][..],
        &["--yes", "--no-download"],
    ] {
        let run = setup.run(args).await;
        assert_eq!(run.outcome.exit_code, 4, "{args:?}: {}", run.stdout());
        assert!(
            !run.stdout().contains("canary-sig-0077"),
            "{}",
            run.stdout()
        );
        assert!(
            !run.stderr().contains("canary-sig-0077"),
            "{}",
            run.stderr()
        );
    }
}

#[tokio::test]
async fn an_operation_entry_that_cannot_be_read_may_be_a_duplicate() {
    for entry in [
        json!({"id": OTHER_OP, "status": "running"}),
        json!({"id": OTHER_OP, "action": "estimateStatistics"}),
        json!("not an object"),
    ] {
        let setup = Setup::new().await;
        setup
            .preflight(
                fixture_value(&setup.harness, "search-get-mailboxes.json"),
                json!({"value": [entry.clone()]}),
            )
            .await;
        setup.accept(&setup.key_form_location()).await;
        let run = setup.run(&["--json", "--yes"]).await;
        assert_eq!(
            run.json()["error"]["code"],
            "ConcurrentOperation",
            "{entry}"
        );
        assert!(setup.posts().await.is_empty(), "{entry}");
    }
}

#[tokio::test]
async fn a_source_list_whose_paging_leaves_it_is_unverified() {
    let setup = Setup::new().await;
    let elsewhere = format!(
        "{}{CASES}/{CASE}/searches/00000000-0000-4000-8000-000000000052/custodianSources",
        setup.harness.graph.uri()
    );
    Mock::given(method("GET"))
        .and(path(search_path("/custodianSources")))
        .respond_with(json_response(
            200,
            json!({"value": [], "@odata.nextLink": elsewhere}),
        ))
        .with_priority(1)
        .mount(&setup.harness.graph)
        .await;
    // The other collection answers, empty: only the binding refuses it.
    Mock::given(method("GET"))
        .and(path(format!(
            "{CASES}/{CASE}/searches/00000000-0000-4000-8000-000000000052/custodianSources"
        )))
        .respond_with(json_response(200, json!({"value": []})))
        .mount(&setup.harness.graph)
        .await;
    setup.accept(&setup.key_form_location()).await;
    setup
        .preflight(
            fixture_value(&setup.harness, "search-get-mailboxes.json"),
            json!({"value": []}),
        )
        .await;
    let run = setup.run(&["--json", "--yes"]).await;
    assert_eq!(run.json()["error"]["code"], "ScopeUnverified");
    assert!(setup.posts().await.is_empty());
}

/// An estimate zip whose Locations file has a row with no status, or two
/// Locations files, cannot be checked; known failures are still listed.
#[tokio::test]
async fn partial_evidence_is_unchecked_and_strict_exits_4() {
    let build = |extra_row: &str, second_locations: bool| -> Vec<u8> {
        let mut buffer = std::io::Cursor::new(Vec::new());
        {
            let mut writer = zip::ZipWriter::new(&mut buffer);
            let options = zip::write::SimpleFileOptions::default();
            let locations = format!(
                "{LOCATIONS_HEADER}Exchange,Mailbox,alex@contoso.example,id-1,Mailbox,PrimaryMailBox,12,2048,Succeeded,,q\r\n{extra_row}"
            );
            writer.start_file("Locations-1.csv", options).unwrap();
            writer.write_all(locations.as_bytes()).unwrap();
            if second_locations {
                writer.start_file("Locations-2.csv", options).unwrap();
                writer.write_all(LOCATIONS_HEADER.as_bytes()).unwrap();
            }
            writer.start_file("Statistics-1.csv", options).unwrap();
            writer.write_all(STATISTICS_HEADER.as_bytes()).unwrap();
            writer.finish().unwrap();
        }
        buffer.into_inner()
    };
    for (zip, label) in [
        (
            build(
                "Exchange,Mailbox,sam@contoso.example,id-2,Mailbox,PrimaryMailBox,3\r\n",
                false,
            ),
            "a row with no status",
        ),
        (build("", true), "two Locations files"),
    ] {
        let setup = Setup::new().await;
        setup
            .preflight(
                fixture_value(&setup.harness, "search-get-mailboxes.json"),
                json!({"value": []}),
            )
            .await;
        setup.accept(&setup.key_form_location()).await;
        setup.operation(0, setup.succeeded()).await;
        setup.serve(zip).await;
        let run = setup.run(&["--json", "--yes", "--strict"]).await;
        assert_eq!(run.outcome.exit_code, 4, "{label}: {}", run.stdout());
        let document = run.json();
        assert_eq!(
            document["results"]["result"]["collection"], "unchecked",
            "{label}"
        );
        assert_eq!(
            document["outcome"]["reasons"][0]["code"], "EvidenceMissing",
            "{label}"
        );
    }
}

#[tokio::test]
async fn wrap_untrusted_marks_the_plan_query_and_report_text() {
    let setup = Setup::new().await;
    setup.ready(0, true).await;
    let run = setup
        .run(&["--json", "--dry-run", "--wrap-untrusted"])
        .await;
    assert_eq!(run.outcome.exit_code, 0, "{}", run.stdout());
    let query = run.json()["results"]["plan"]["preflight"][2]["contentQuery"]
        .as_str()
        .unwrap()
        .to_owned();
    assert!(query.starts_with("[UNTRUSTED:"), "{query}");

    let run = setup.run(&["--json", "--yes", "--wrap-untrusted"]).await;
    assert_eq!(run.outcome.exit_code, 0, "{}", run.stdout());
    let failed = &run.json()["results"]["result"]["failedLocations"][0];
    assert!(failed["location"]
        .as_str()
        .unwrap()
        .starts_with("[UNTRUSTED:"));
    assert!(failed["failureMessage"]
        .as_str()
        .unwrap()
        .starts_with("[UNTRUSTED:"));
}

#[tokio::test]
async fn an_interrupted_check_resumes_with_check_and_never_downloads_items() {
    let setup = Setup::new().await;
    let reports = format!(
        "http://{ALPHA}:{}/reports?downloadType=Report",
        setup.alpha.address().port()
    );
    let items = format!(
        "http://{ALPHA}:{}/items?downloadType=Items",
        setup.alpha.address().port()
    );
    let export = json!({
        "@odata.type": "#microsoft.graph.security.ediscoverySearchExportOperation",
        "id": OP,
        "action": "exportResult",
        "status": "succeeded",
        "exportFileMetadata": [
            {"fileName": "Reports-Orders.zip", "size": 10, "downloadUrl": reports},
            {"fileName": "Items.1.001.Orders.zip", "size": 10, "downloadUrl": items},
        ],
    });
    setup.operation(0, export).await;
    let interrupt = Arc::new(ms_purview_cli::env::ManualInterrupt::default());
    interrupt.fire();
    let run = setup
        .harness
        .run_with(
            &["--json", "operation", "get", CASE, OP, "--check"],
            |env, _| {
                setup.configure(env);
                env.interrupt = interrupt.clone();
            },
        )
        .await;
    assert_eq!(run.outcome.exit_code, 130, "{}", run.stdout());
    let document = run.json();
    assert_eq!(document["error"]["code"], "Interrupted");
    let resume: Vec<String> = document["resume"]
        .as_array()
        .unwrap()
        .iter()
        .map(|command| command.as_str().unwrap().to_owned())
        .collect();
    assert_eq!(resume.len(), 1, "{resume:?}");
    assert!(resume[0].ends_with(&format!("operation get {CASE} {OP} --check")));
    assert!(setup
        .downloads()
        .await
        .iter()
        .all(|request| request.url.path() != "/items"));
}

#[tokio::test]
async fn an_estimate_started_while_the_prompt_was_open_may_be_a_duplicate() {
    let setup = Setup::new().await;
    setup
        .preflight_search(fixture_value(&setup.harness, "search-get-mailboxes.json"))
        .await;
    Mock::given(method("GET"))
        .and(path(format!("{CASES}/{CASE}/operations")))
        .respond_with(json_response(200, json!({"value": []})))
        .up_to_n_times(1)
        .with_priority(1)
        .mount(&setup.harness.graph)
        .await;
    setup
        .get(
            &format!("{CASES}/{CASE}/operations"),
            json!({"value": [{"id": OTHER_OP, "action": "estimateStatistics", "status": "running"}]}),
        )
        .await;
    setup.accept(&setup.key_form_location()).await;
    let run = setup.run(&["--json", "--yes"]).await;
    assert_eq!(run.json()["error"]["code"], "ConcurrentOperation");
    assert!(run.json()["error"]["message"]
        .as_str()
        .unwrap()
        .contains("after the plan was shown"));
    assert!(setup.posts().await.is_empty());
}

#[tokio::test]
async fn a_wait_with_check_that_times_out_resumes_with_check() {
    let setup = Setup::new().await;
    setup.operation(1000, setup.succeeded()).await;
    let run = setup
        .run_raw(&[
            "--json",
            "operation",
            "get",
            CASE,
            OP,
            "--wait",
            "--check",
            "--wait-timeout",
            "1m",
        ])
        .await;
    assert_eq!(run.outcome.exit_code, 5, "{}", run.stdout());
    let resume = run.json()["resume"].clone();
    assert_eq!(resume.as_array().unwrap().len(), 1, "{resume}");
    assert!(resume[0]
        .as_str()
        .unwrap()
        .ends_with(&format!("operation get {CASE} {OP} --wait --check")));
}

/// A status that Graph does not document is not repeated in the
/// candidates: it is Graph's text.
#[tokio::test]
async fn an_unknown_status_in_a_candidate_is_not_repeated() {
    let setup = Setup::new().await;
    setup
        .preflight_search(fixture_value(&setup.harness, "search-get-mailboxes.json"))
        .await;
    Mock::given(method("GET"))
        .and(path(format!("{CASES}/{CASE}/operations")))
        .respond_with(json_response(200, json!({"value": []})))
        .up_to_n_times(2)
        .with_priority(1)
        .mount(&setup.harness.graph)
        .await;
    setup
        .get(
            &format!("{CASES}/{CASE}/operations"),
            json!({"value": [
                {"id": OP, "action": "estimateStatistics", "status": "see canary-status-0091", "createdDateTime": "2026-01-05T09:00:30Z"},
            ]}),
        )
        .await;
    Mock::given(method("POST"))
        .and(path(search_path("/estimateStatistics")))
        .respond_with(json_response(
            503,
            json!({"error": {"code": "ServiceUnavailable"}}),
        ))
        .mount(&setup.harness.graph)
        .await;
    let run = setup.run(&["--json", "--yes"]).await;
    let message = run.json()["error"]["message"].as_str().unwrap().to_owned();
    assert!(
        message.contains(&format!("estimate {OP} (unknown status")),
        "{message}"
    );
    assert!(!message.contains("canary-status-0091"), "{message}");
}

/// Answers with `response`, and moves the clock forward by `by` at the
/// `nth` request.
struct AdvanceOn {
    clock: Arc<ms_purview_cli::env::ManualClock>,
    seen: std::sync::atomic::AtomicUsize,
    nth: usize,
    by: Duration,
    response: ResponseTemplate,
}

impl Respond for AdvanceOn {
    fn respond(&self, _request: &Request) -> ResponseTemplate {
        if self.seen.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1 == self.nth {
            self.clock.advance(self.by);
        }
        self.response.clone()
    }
}

#[tokio::test]
async fn an_unclear_estimate_looks_from_after_the_last_read_before_the_send() {
    let setup = Setup::new().await;
    setup
        .preflight_search(fixture_value(&setup.harness, "search-get-mailboxes.json"))
        .await;
    // The operations list read after approval takes ten minutes.
    Mock::given(method("GET"))
        .and(path(format!("{CASES}/{CASE}/operations")))
        .respond_with(AdvanceOn {
            clock: setup.harness.clock.clone(),
            seen: Default::default(),
            nth: 2,
            by: Duration::from_secs(600),
            response: json_response(200, json!({"value": []})),
        })
        .up_to_n_times(2)
        .with_priority(1)
        .mount(&setup.harness.graph)
        .await;
    setup
        .get(
            &format!("{CASES}/{CASE}/operations"),
            json!({"value": [
                {"id": OTHER_OP, "action": "estimateStatistics", "status": "succeeded", "createdDateTime": "2026-01-05T08:58:00Z"},
                {"id": OP, "action": "estimateStatistics", "status": "running", "createdDateTime": "2026-01-05T09:10:10Z"},
            ]}),
        )
        .await;
    Mock::given(method("POST"))
        .and(path(search_path("/estimateStatistics")))
        .respond_with(json_response(
            503,
            json!({"error": {"code": "ServiceUnavailable"}}),
        ))
        .mount(&setup.harness.graph)
        .await;
    let run = setup.run(&["--json", "--yes"]).await;
    let message = run.json()["error"]["message"].as_str().unwrap().to_owned();
    assert!(
        message.contains(&format!("estimate {OP} (running")),
        "{message}"
    );
    assert!(!message.contains(OTHER_OP), "{message}");
}
