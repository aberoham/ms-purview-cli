//! In-process flows of `report` (`docs/SPEC.md` section 3.5) through
//! `cli::execute_with`: the action preflight, the size limit against the
//! search's latest estimate, the POST, polling, the report download and
//! the collection check from `Locations`. Every request to the mock Graph
//! and download origin is recorded.

mod support;

use std::io::Write;
use std::net::SocketAddr;
use std::path::PathBuf;

use ms_purview_cli::download::DownloadRule;
use ms_purview_cli::env::Env;
use serde_json::{json, Value};
use support::*;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, Request, ResponseTemplate};

const CASES: &str = "/v1.0/security/cases/ediscoveryCases";
const CASE: &str = "00000000-0000-4000-8000-000000000031";
const SEARCH: &str = "00000000-0000-4000-8000-000000000051";
const OP: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaa0001";
const ESTIMATE: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaa0009";
const OTHER_ESTIMATE: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaa0008";
const ALPHA: &str = "alpha.proxyservice.ediscovery.svc.cloud.microsoft";
const FILE_PATH: &str = "/ediscovery/api/proxy/exportaedblobFileResult";
const GIB: u64 = 1 << 30;

fn search_path(tail: &str) -> String {
    format!("{CASES}/{CASE}/searches/{SEARCH}{tail}")
}

fn operation_path() -> String {
    format!("{CASES}/{CASE}/operations/{OP}")
}

fn last_estimate_path() -> String {
    search_path("/lastEstimateStatisticsOperation")
}

const LOCATIONS_HEADER: &str = "\u{feff}DataSourceName,DataSourceType,Location,LocationId,LocationType,LocationSubType,Count,Size,Status,ErrorWarning,Query\r\n";

/// An item report zip; `failed` adds one failed location.
fn report_zip(failed: bool) -> Vec<u8> {
    let mut locations = String::from(LOCATIONS_HEADER);
    locations.push_str("Exchange,Mailbox,alex@contoso.example,id-1,Mailbox,PrimaryMailBox,12,2048,Succeeded,,q\r\n");
    locations.push_str(
        "Exchange,Mailbox,sam@contoso.example,id-2,Mailbox,PrimaryMailBox,3,100,Succeeded,,q\r\n",
    );
    if failed {
        locations.push_str("Exchange,Mailbox,kim@contoso.example,id-4,Mailbox,PrimaryMailBox,,,Failed,Timed out,q\r\n");
    }
    let items =
        "\u{feff}Subject,Sender,Location\r\nhello,alex@contoso.example,alex@contoso.example\r\n";
    let summary = "\u{feff}Job ID,j,x\r\nLocationCount,2,Locations\r\n";
    let mut buffer = std::io::Cursor::new(Vec::new());
    {
        let mut writer = zip::ZipWriter::new(&mut buffer);
        let options = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Deflated);
        for (name, body) in [
            ("Items_0_2026-01-05_09-00-00.csv", items),
            ("Locations-2026-01-05_09-00-00.csv", locations.as_str()),
            ("Summary-2026-01-05_09-00-00.csv", summary),
        ] {
            writer.start_file(name, options).unwrap();
            writer.write_all(body.as_bytes()).unwrap();
        }
        writer.finish().unwrap();
    }
    buffer.into_inner()
}

/// A zip of the given entries.
fn zip_of(entries: &[(&str, &str)]) -> Vec<u8> {
    let mut buffer = std::io::Cursor::new(Vec::new());
    {
        let mut writer = zip::ZipWriter::new(&mut buffer);
        let options = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Deflated);
        for (name, body) in entries {
            writer.start_file(*name, options).unwrap();
            writer.write_all(body.as_bytes()).unwrap();
        }
        writer.finish().unwrap();
    }
    buffer.into_inner()
}

/// The search's latest estimate: created after the fixture search's last
/// change, with `size` bytes.
/// It has no `@odata.type`, as observed.
fn estimate(status: &str, size: Value) -> Value {
    json!({
        "id": ESTIMATE,
        "action": "estimateStatistics",
        "status": status,
        "createdDateTime": "2026-01-04T09:00:00Z",
        "indexedItemCount": 120,
        "indexedItemsSize": size,
        "reportFileMetadata": [],
    })
}

struct Setup {
    harness: Harness,
    alpha: MockServer,
    /// The size the operation gives for its zip.
    zip_size: usize,
}

impl Setup {
    async fn new() -> Self {
        let harness = Harness::new().await;
        sign_in_alex(&harness).await;
        Self {
            harness,
            alpha: MockServer::start().await,
            zip_size: report_zip(false).len(),
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
        let mut argv = vec!["report", CASE, SEARCH];
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

    /// The search, its three empty source lists, an operation list and the
    /// latest estimate.
    async fn preflight(&self, search: Value, operations: Value, latest: Value) {
        self.get(&search_path(""), search).await;
        for sources in [
            "custodianSources",
            "noncustodialSources",
            "additionalSources",
        ] {
            self.get(
                &search_path(&format!("/{sources}")),
                graph_fixture("search-sources-empty.json", &self.harness.graph.uri()),
            )
            .await;
        }
        self.get(&format!("{CASES}/{CASE}/operations"), operations)
            .await;
        self.get(&last_estimate_path(), latest).await;
    }

    fn search(&self) -> Value {
        graph_fixture("search-get-mailboxes.json", &self.harness.graph.uri())
    }

    async fn accept(&self) {
        let location = format!(
            "{}/v1.0/security/cases/ediscoverycases('{CASE}')/operations('{OP}')",
            self.harness.graph.uri()
        );
        Mock::given(method("POST"))
            .and(path(search_path("/exportReport")))
            .respond_with(ResponseTemplate::new(202).insert_header("Location", location))
            .mount(&self.harness.graph)
            .await;
    }

    fn succeeded(&self) -> Value {
        json!({
            "@odata.type": "#microsoft.graph.security.ediscoverySearchExportOperation",
            "id": OP,
            "action": "exportReport",
            "status": "succeeded",
            "createdDateTime": "2026-01-05T09:00:00Z",
            "displayName": "report 2026-01-05 0900Z",
            "exportCriteria": "searchHits",
            "exportLocation": "responsiveLocations",
            "additionalOptions": "teamsAndYammerConversations",
            "exportFormat": "pst",
            "exportFileMetadata": [
                {"fileName": "Orders API mentions_report.zip", "size": self.zip_size, "downloadUrl": self.file_url()}
            ],
        })
    }

    /// A whole report: a small estimate, the 202, a succeeded operation
    /// and its zip.
    async fn ready(&mut self, failed: bool) {
        self.ready_with(report_zip(failed)).await;
    }

    /// A whole report whose zip is `zip`.
    async fn ready_with(&mut self, zip: Vec<u8>) {
        self.zip_size = zip.len();
        self.preflight(
            self.search(),
            json!({"value": []}),
            estimate("succeeded", json!(GIB)),
        )
        .await;
        self.accept().await;
        self.get(&operation_path(), self.succeeded()).await;
        Mock::given(method("GET"))
            .and(path(FILE_PATH))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(zip))
            .mount(&self.alpha)
            .await;
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

    async fn post_body(&self) -> Value {
        let posts = self.posts().await;
        assert_eq!(posts.len(), 1);
        serde_json::from_slice(&posts[0].body).unwrap()
    }

    async fn downloads(&self) -> Vec<Request> {
        self.alpha
            .received_requests()
            .await
            .expect("the mock download origin records requests")
    }
}

/// Writes `key` into config.json, keeping the rest.
fn set_config(harness: &Harness, key: &str, value: Value) {
    let file = harness.config_dir().join("config.json");
    let mut config = harness.config();
    config[key] = value;
    std::fs::write(&file, serde_json::to_vec_pretty(&config).unwrap()).unwrap();
}

#[tokio::test]
async fn a_report_posts_the_observed_body_waits_downloads_and_checks_locations() {
    let mut setup = Setup::new().await;
    setup.ready(false).await;
    let run = setup.run(&["--json", "--yes"]).await;
    assert_eq!(
        run.outcome.exit_code,
        0,
        "{} {}",
        run.stdout(),
        run.stderr()
    );
    let body = setup.post_body().await;
    assert_eq!(
        body,
        json!({
            "displayName": "report 2026-01-05 0900Z",
            "exportCriteria": "searchHits",
            "exportLocation": "responsiveLocations",
            "additionalOptions": "teamsAndYammerConversations",
        })
    );
    let plan = &run.json()["results"]["plan"];
    let warnings = plan["warnings"].to_string();
    assert!(warnings.contains("counted 120 items"), "{warnings}");
    assert!(warnings.contains("1,200 to 4,440 rows"), "{warnings}");
    let preflight = plan["preflight"].to_string();
    assert!(
        preflight.contains("within volume.max_export_size"),
        "{preflight}"
    );
    assert!(preflight.contains("Teams context: on"), "{preflight}");
    let result = &run.json()["results"]["result"];
    assert_eq!(result["operationId"], OP);
    assert_eq!(result["operationStatus"], "succeeded");
    assert_eq!(result["collection"], "complete");
    assert_eq!(result["estimateId"], ESTIMATE);
    assert_eq!(result["teamsContext"], true);
    assert_eq!(result["locationsWithHits"], 2);
    assert_eq!(result["failedLocations"], json!([]));
    let file = PathBuf::from(result["files"][0]["path"].as_str().unwrap());
    assert!(file.starts_with(setup.data_root().join("cases").join(CASE).join(OP)));
    assert!(file.exists());
    assert_eq!(setup.downloads().await.len(), 1);
}

#[tokio::test]
async fn a_failed_location_is_incomplete_and_strict_exits_4() {
    let mut setup = Setup::new().await;
    setup.ready(true).await;
    let run = setup.run(&["--json", "--yes"]).await;
    assert_eq!(run.outcome.exit_code, 0, "{}", run.stdout());
    assert_eq!(run.json()["results"]["result"]["collection"], "incomplete");
    assert!(
        run.stderr()
            .contains("the report succeeded, but 1 location was not searched in full"),
        "{}",
        run.stderr()
    );
    let run = setup.run(&["--json", "--yes", "--strict"]).await;
    assert_eq!(run.outcome.exit_code, 4, "{}", run.stdout());
    assert_eq!(
        run.json()["outcome"]["reasons"][0]["code"],
        "FailedLocations"
    );
}

#[tokio::test]
async fn an_estimate_above_the_size_limit_blocks_the_report_and_allow_large_sends_it() {
    let setup = Setup::new().await;
    setup
        .preflight(
            setup.search(),
            json!({"value": []}),
            estimate("succeeded", json!(11 * GIB)),
        )
        .await;
    setup.accept().await;
    setup.get(&operation_path(), setup.succeeded()).await;
    let run = setup.run(&["--json", "--yes", "--no-download"]).await;
    assert_eq!(run.outcome.exit_code, 1, "{}", run.stdout());
    let error = &run.json()["error"];
    assert_eq!(error["code"], "TooLarge");
    let message = error["message"].as_str().unwrap();
    assert!(message.contains("11.0 GiB"), "{message}");
    assert!(message.contains("10.0 GiB"), "{message}");
    assert!(message.contains("--allow-large"), "{message}");
    assert!(setup.posts().await.is_empty());

    // The plan itself is blocked: without --yes nobody is asked.
    let run = setup.run(&["--json"]).await;
    assert_eq!(run.outcome.exit_code, 1, "{}", run.stdout());
    assert_eq!(run.json()["error"]["code"], "TooLarge");

    // A dry run shows the plan that would be refused.
    let run = setup.run(&["--json", "--dry-run"]).await;
    assert_eq!(run.outcome.exit_code, 0, "{}", run.stdout());
    assert!(run.json()["results"]["plan"]["preflight"]
        .to_string()
        .contains("over volume.max_export_size"));
    assert!(setup.posts().await.is_empty());

    // A higher limit lets it through.
    set_config(
        &setup.harness,
        "volume",
        json!({"max_export_size": "12GiB"}),
    );
    let run = setup.run(&["--json", "--yes", "--no-download"]).await;
    assert_eq!(run.outcome.exit_code, 0, "{}", run.stdout());
    assert!(setup.post_body().await.get("description").is_none());

    // --allow-large sends it, with the reason as the description.
    let setup = Setup::new().await;
    setup
        .preflight(
            setup.search(),
            json!({"value": []}),
            estimate("succeeded", json!(11 * GIB)),
        )
        .await;
    setup.accept().await;
    setup.get(&operation_path(), setup.succeeded()).await;
    let run = setup
        .run(&[
            "--json",
            "--yes",
            "--no-download",
            "--allow-large",
            "--reason",
            "the requester asked for every item",
        ])
        .await;
    assert_eq!(run.outcome.exit_code, 0, "{}", run.stdout());
    assert_eq!(
        setup.post_body().await["description"],
        "--allow-large: the requester asked for every item"
    );
    let warnings = run.json()["results"]["plan"]["warnings"].to_string();
    assert!(warnings.contains("VOLUME:"), "{warnings}");
}

#[tokio::test]
async fn a_search_without_a_current_estimate_is_refused_before_any_post() {
    let stale = {
        let mut value = estimate("succeeded", json!(GIB));
        value["createdDateTime"] = json!("2026-01-01T09:00:00Z");
        value
    };
    let no_time = {
        let mut value = estimate("succeeded", json!(GIB));
        value.as_object_mut().unwrap().remove("createdDateTime");
        value
    };
    let no_size = {
        let mut value = estimate("succeeded", json!(GIB));
        value.as_object_mut().unwrap().remove("indexedItemsSize");
        value
    };
    let not_estimate = {
        let mut value = estimate("succeeded", json!(GIB));
        value["action"] = json!("exportReport");
        value
    };
    for (latest, why) in [
        (estimate("failed", json!(GIB)), "did not succeed"),
        (estimate("running", json!(GIB)), "is not finished"),
        (
            stale,
            "the search was changed after its latest estimate ran",
        ),
        (no_time, "times that show the estimate is newer"),
        (no_size, "has no indexedItemsSize"),
        (not_estimate, "not an estimate operation"),
        (estimate("partiallySucceeded", json!(GIB)), "lower bound"),
    ] {
        let setup = Setup::new().await;
        setup
            .preflight(setup.search(), json!({"value": []}), latest)
            .await;
        setup.accept().await;
        let run = setup.run(&["--json", "--yes"]).await;
        assert_eq!(run.outcome.exit_code, 1, "{why}: {}", run.stdout());
        let error = &run.json()["error"];
        assert_eq!(error["code"], "VolumeUnchecked", "{why}");
        let message = error["message"].as_str().unwrap();
        assert!(message.contains(why), "{why}: {message}");
        assert!(message.contains("purview estimate"), "{message}");
        assert!(setup.posts().await.is_empty(), "{why}");
    }
}

#[tokio::test]
async fn a_latest_estimate_graph_does_not_have_is_refused_unless_allow_large() {
    for (status, why) in [
        (404, "Graph found no estimate of the search (HTTP 404)"),
        (400, "could not be read (BadRequest, HTTP 400)"),
    ] {
        let setup = Setup::new().await;
        Mock::given(method("GET"))
            .and(path(last_estimate_path()))
            .respond_with(json_response(
                status,
                json!({"error": {"code": if status == 404 { "NotFound" } else { "BadRequest" }, "message": "secret-ish text"}}),
            ))
            .with_priority(1)
            .mount(&setup.harness.graph)
            .await;
        setup
            .preflight(setup.search(), json!({"value": []}), json!({}))
            .await;
        setup.accept().await;
        setup.get(&operation_path(), setup.succeeded()).await;
        let run = setup.run(&["--json", "--yes"]).await;
        assert_eq!(run.json()["error"]["code"], "VolumeUnchecked", "{status}");
        let message = run.json()["error"]["message"].as_str().unwrap().to_owned();
        assert!(message.contains(why), "{message}");
        assert!(!message.contains("secret-ish"), "{message}");
        assert!(setup.posts().await.is_empty());

        let run = setup
            .run(&[
                "--json",
                "--yes",
                "--no-download",
                "--allow-large",
                "--reason",
                "no estimate yet",
            ])
            .await;
        assert_eq!(run.outcome.exit_code, 0, "{status}: {}", run.stdout());
        assert_eq!(setup.posts().await.len(), 1);
    }
}

#[tokio::test]
async fn teams_context_is_left_out_by_the_flag_or_the_setting() {
    let mut setup = Setup::new().await;
    setup.ready(false).await;
    let run = setup
        .run(&["--json", "--yes", "--no-download", "--no-teams-context"])
        .await;
    assert_eq!(run.outcome.exit_code, 0, "{}", run.stdout());
    assert!(setup.post_body().await.get("additionalOptions").is_none());
    let plan = &run.json()["results"]["plan"];
    assert!(plan["warnings"].to_string().contains("experimental"));
    assert!(plan["preflight"].to_string().contains("Teams context: off"));
    assert_eq!(run.json()["results"]["result"]["teamsContext"], false);

    let mut setup = Setup::new().await;
    setup.ready(false).await;
    set_config(&setup.harness, "defaults", json!({"teams_context": false}));
    let run = setup.run(&["--json", "--yes", "--no-download"]).await;
    assert_eq!(run.outcome.exit_code, 0, "{}", run.stdout());
    assert!(setup.post_body().await.get("additionalOptions").is_none());
}

#[tokio::test]
async fn a_bad_teams_context_setting_stops_the_report_before_any_request() {
    let mut setup = Setup::new().await;
    setup.ready(false).await;
    set_config(&setup.harness, "defaults", json!({"teams_context": "off"}));
    let run = setup.run(&["--json", "--yes"]).await;
    assert_eq!(run.outcome.exit_code, 1);
    let message = run.json()["error"]["message"].as_str().unwrap().to_owned();
    assert!(message.contains("defaults.teams_context"), "{message}");
    assert!(!message.contains("\"off\""), "{message}");
    assert!(setup.graph_requests().await.is_empty());
}

#[tokio::test]
async fn a_report_or_export_not_yet_finished_needs_allow_concurrent() {
    for action in ["exportResult", "exportReport"] {
        let setup = Setup::new().await;
        setup
            .preflight(
                setup.search(),
                json!({"value": [
                    {"id": "aaaaaaaaaaaaaaaaaaaaaaaaaaaa0003", "action": action, "status": "running", "createdDateTime": "2026-01-05T08:00:00Z"},
                    {"id": "aaaaaaaaaaaaaaaaaaaaaaaaaaaa0004", "action": "estimateStatistics", "status": "running"},
                ]}),
                estimate("succeeded", json!(GIB)),
            )
            .await;
        setup.accept().await;
        setup.get(&operation_path(), setup.succeeded()).await;
        let run = setup.run(&["--json", "--yes"]).await;
        assert_eq!(
            run.json()["error"]["code"],
            "ConcurrentOperation",
            "{action}"
        );
        let message = run.json()["error"]["message"].as_str().unwrap().to_owned();
        assert!(
            message.contains("aaaaaaaaaaaaaaaaaaaaaaaaaaaa0003"),
            "{message}"
        );
        assert!(
            !message.contains("aaaaaaaaaaaaaaaaaaaaaaaaaaaa0004"),
            "{message}"
        );
        assert!(setup.posts().await.is_empty());
        // The plan itself is blocked, and names the operation.
        let run = setup.run(&["--json"]).await;
        assert_eq!(
            run.json()["error"]["code"],
            "ConcurrentOperation",
            "{action}"
        );
        let run = setup.run(&["--json", "--dry-run"]).await;
        assert!(run.json()["results"]["plan"]["warnings"]
            .to_string()
            .contains("aaaaaaaaaaaaaaaaaaaaaaaaaaaa0003"));
        let run = setup
            .run(&["--json", "--yes", "--no-download", "--allow-concurrent"])
            .await;
        assert_eq!(run.outcome.exit_code, 0, "{action}: {}", run.stdout());
    }
}

#[tokio::test]
async fn an_operation_that_is_not_an_item_report_is_not_downloaded() {
    let mut setup = Setup::new().await;
    setup.ready(false).await;
    let mut export = setup.succeeded();
    export["action"] = json!("exportResult");
    Mock::given(method("GET"))
        .and(path(operation_path()))
        .respond_with(json_response(200, export))
        .with_priority(1)
        .mount(&setup.harness.graph)
        .await;
    let run = setup.run(&["--json", "--yes"]).await;
    assert_eq!(run.json()["error"]["code"], "UnexpectedLocation");
    assert!(run.json()["error"]["message"]
        .as_str()
        .unwrap()
        .contains("is not an item report"));
    assert!(setup.downloads().await.is_empty());
}

#[tokio::test]
async fn a_latest_estimate_that_changes_after_the_plan_stops_the_send() {
    let setup = Setup::new().await;
    // The plan reads one estimate; the read after approval finds another.
    Mock::given(method("GET"))
        .and(path(last_estimate_path()))
        .respond_with(json_response(200, estimate("succeeded", json!(GIB))))
        .up_to_n_times(1)
        .with_priority(1)
        .mount(&setup.harness.graph)
        .await;
    let mut other = estimate("succeeded", json!(GIB));
    other["id"] = json!(OTHER_ESTIMATE);
    setup
        .preflight(setup.search(), json!({"value": []}), other)
        .await;
    setup.accept().await;
    let run = setup.run(&["--json", "--yes"]).await;
    assert_eq!(
        run.json()["error"]["code"],
        "SearchChanged",
        "{}",
        run.stdout()
    );
    assert!(setup.posts().await.is_empty());
}

#[tokio::test]
async fn an_unclear_report_reads_each_candidate_for_its_true_action() {
    let setup = Setup::new().await;
    setup
        .preflight(
            setup.search(),
            json!({"value": []}),
            estimate("succeeded", json!(GIB)),
        )
        .await;
    // The preflight list and its read after approval are empty; the
    // reconciliation list has a report and an export, both shown as
    // exportResult.
    Mock::given(method("GET"))
        .and(path(format!("{CASES}/{CASE}/operations")))
        .respond_with(json_response(200, json!({"value": []})))
        .up_to_n_times(2)
        .with_priority(1)
        .mount(&setup.harness.graph)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("{CASES}/{CASE}/operations")))
        .respond_with(json_response(
            200,
            json!({"value": [
                {"id": OP, "action": "exportResult", "status": "running", "createdDateTime": "2026-01-05T09:00:30Z"},
                {"id": "aaaaaaaaaaaaaaaaaaaaaaaaaaaa0005", "action": "exportResult", "status": "running", "createdDateTime": "2026-01-05T09:00:40Z"},
            ]}),
        ))
        .with_priority(2)
        .mount(&setup.harness.graph)
        .await;
    setup.get(&operation_path(), setup.succeeded()).await;
    Mock::given(method("GET"))
        .and(path(format!(
            "{CASES}/{CASE}/operations/aaaaaaaaaaaaaaaaaaaaaaaaaaaa0005"
        )))
        .respond_with(json_response(
            200,
            json!({
                "@odata.type": "#microsoft.graph.security.ediscoverySearchExportOperation",
                "id": "aaaaaaaaaaaaaaaaaaaaaaaaaaaa0005",
                "action": "exportResult",
                "status": "running",
            }),
        ))
        .mount(&setup.harness.graph)
        .await;
    Mock::given(method("POST"))
        .and(path(search_path("/exportReport")))
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
        message.contains(&format!("item report {OP} (running")),
        "{message}"
    );
    assert!(
        message.contains("export aaaaaaaaaaaaaaaaaaaaaaaaaaaa0005 (running"),
        "{message}"
    );
    assert_eq!(setup.posts().await.len(), 1);
}

#[tokio::test]
async fn no_wait_submits_and_resumes_with_the_check_never_download() {
    let mut setup = Setup::new().await;
    setup.ready(false).await;
    let run = setup.run(&["--json", "--yes", "--no-wait"]).await;
    assert_eq!(run.outcome.exit_code, 0, "{}", run.stdout());
    let result = &run.json()["results"]["result"];
    assert_eq!(result["operationId"], OP);
    assert_eq!(result["collection"], "unchecked");
    // The operation the header named is not checked yet, so the resume
    // fetches only the evidence file.
    let resume = result["resume"].as_array().unwrap();
    assert_eq!(resume.len(), 1, "{resume:?}");
    assert!(resume[0]
        .as_str()
        .unwrap()
        .ends_with(&format!("operation get {CASE} {OP} --wait --check")));
    assert!(setup.downloads().await.is_empty());
    assert!(!setup
        .graph_requests()
        .await
        .iter()
        .any(|request| request.url.path() == operation_path()));
}

#[tokio::test]
async fn the_reason_needs_an_override_and_each_override_needs_a_reason() {
    let setup = Setup::new().await;
    for args in [
        vec!["--json", "--reason", "why"],
        vec!["--json", "--allow-large"],
        vec!["--json", "--allow-generic"],
    ] {
        let run = setup.run(&args).await;
        assert_eq!(run.outcome.exit_code, 1, "{args:?}");
        assert_eq!(run.json()["error"]["code"], "CommandFailed", "{args:?}");
    }
    assert!(setup.graph_requests().await.is_empty());
}

#[tokio::test]
async fn a_generic_query_and_a_large_estimate_need_both_overrides_and_share_the_reason() {
    let setup = Setup::new().await;
    let mut search = setup.search();
    search["contentQuery"] = json!("retention");
    setup
        .preflight(
            search,
            json!({"value": []}),
            estimate("succeeded", json!(11 * GIB)),
        )
        .await;
    setup.accept().await;
    setup.get(&operation_path(), setup.succeeded()).await;
    let run = setup
        .run(&["--json", "--yes", "--allow-large", "--reason", "needed"])
        .await;
    assert_eq!(run.json()["error"]["code"], "GenericQuery");
    let run = setup
        .run(&["--json", "--yes", "--allow-generic", "--reason", "needed"])
        .await;
    assert_eq!(run.json()["error"]["code"], "TooLarge");
    assert!(setup.posts().await.is_empty());
    let run = setup
        .run(&[
            "--json",
            "--yes",
            "--no-download",
            "--allow-generic",
            "--allow-large",
            "--reason",
            "Legal asked for every mention",
        ])
        .await;
    assert_eq!(run.outcome.exit_code, 0, "{}", run.stdout());
    assert_eq!(
        setup.post_body().await["description"],
        "--allow-generic and --allow-large: Legal asked for every mention"
    );
}

#[tokio::test]
async fn a_human_run_shows_the_plan_and_the_result() {
    let mut setup = Setup::new().await;
    setup.ready(false).await;
    let run = setup.run(&["--yes"]).await;
    assert_eq!(run.outcome.exit_code, 0, "{}", run.stderr());
    let stderr = run.stderr();
    assert!(stderr.contains("Plan: purview report"), "{stderr}");
    assert!(stderr.contains("rows per estimated item"), "{stderr}");
    let stdout = run.stdout();
    assert!(stdout.starts_with("Applied: purview report\n"), "{stdout}");
    assert!(stdout.contains("\"collection\": \"complete\""), "{stdout}");
}

#[tokio::test]
async fn the_size_limit_is_refused_ahead_of_a_possible_duplicate() {
    let setup = Setup::new().await;
    setup
        .preflight(
            setup.search(),
            json!({"value": [
                {"id": "aaaaaaaaaaaaaaaaaaaaaaaaaaaa0003", "action": "exportResult", "status": "running"},
            ]}),
            estimate("succeeded", json!(11 * GIB)),
        )
        .await;
    setup.accept().await;
    let run = setup.run(&["--json", "--yes"]).await;
    assert_eq!(run.json()["error"]["code"], "TooLarge");
    // --allow-concurrent does not cover the size.
    let run = setup.run(&["--json", "--yes", "--allow-concurrent"]).await;
    assert_eq!(run.json()["error"]["code"], "TooLarge");
    assert!(setup.posts().await.is_empty());
}

#[tokio::test]
async fn the_wait_deadline_resumes_with_the_check_never_download() {
    let setup = Setup::new().await;
    setup
        .preflight(
            setup.search(),
            json!({"value": []}),
            estimate("succeeded", json!(GIB)),
        )
        .await;
    setup.accept().await;
    let mut running = setup.succeeded();
    running["status"] = json!("running");
    setup.get(&operation_path(), running).await;
    let run = setup
        .run(&["--json", "--yes", "--wait-timeout", "30s"])
        .await;
    assert_eq!(run.outcome.exit_code, 5, "{}", run.stdout());
    let resume = run.json()["resume"].clone();
    assert_eq!(resume.as_array().unwrap().len(), 1, "{resume}");
    assert!(
        resume[0].as_str().unwrap().ends_with("--wait --check"),
        "{resume}"
    );
}

#[tokio::test]
async fn a_typed_latest_estimate_is_read_too() {
    let mut setup = Setup::new().await;
    setup.ready(false).await;
    let mut typed = estimate("succeeded", json!(11 * GIB));
    typed["@odata.type"] = json!("#microsoft.graph.security.ediscoveryEstimateOperation");
    Mock::given(method("GET"))
        .and(path(last_estimate_path()))
        .respond_with(json_response(200, typed))
        .with_priority(1)
        .mount(&setup.harness.graph)
        .await;
    let run = setup.run(&["--json", "--yes"]).await;
    assert_eq!(run.json()["error"]["code"], "TooLarge");
}

#[tokio::test]
async fn an_answer_with_no_operation_is_unchecked_and_allow_large_still_sends() {
    for answer in [ResponseTemplate::new(204), json_response(200, Value::Null)] {
        let mut setup = Setup::new().await;
        setup.ready(false).await;
        Mock::given(method("GET"))
            .and(path(last_estimate_path()))
            .respond_with(answer)
            .with_priority(1)
            .mount(&setup.harness.graph)
            .await;
        let run = setup.run(&["--json", "--yes"]).await;
        assert_eq!(
            run.json()["error"]["code"],
            "VolumeUnchecked",
            "{}",
            run.stdout()
        );
        assert!(run.json()["error"]["message"]
            .as_str()
            .unwrap()
            .contains("holds no operation"));
        let run = setup
            .run(&[
                "--json",
                "--yes",
                "--no-download",
                "--allow-large",
                "--reason",
                "none yet",
            ])
            .await;
        assert_eq!(run.outcome.exit_code, 0, "{}", run.stdout());
        assert_eq!(setup.posts().await.len(), 1);
    }
}

#[tokio::test]
async fn an_estimate_that_grows_past_the_limit_after_the_plan_stops_the_send() {
    let setup = Setup::new().await;
    // Same estimate id: the plan reads 1 GiB, the read after approval 11.
    Mock::given(method("GET"))
        .and(path(last_estimate_path()))
        .respond_with(json_response(200, estimate("succeeded", json!(GIB))))
        .up_to_n_times(1)
        .with_priority(1)
        .mount(&setup.harness.graph)
        .await;
    setup
        .preflight(
            setup.search(),
            json!({"value": []}),
            estimate("succeeded", json!(11 * GIB)),
        )
        .await;
    setup.accept().await;
    let run = setup.run(&["--json", "--yes"]).await;
    assert_eq!(run.json()["error"]["code"], "TooLarge", "{}", run.stdout());
    assert!(setup.posts().await.is_empty());
}

#[tokio::test]
async fn a_zip_without_locations_is_unchecked_and_strict_exits_4() {
    let mut setup = Setup::new().await;
    setup
        .ready_with(zip_of(&[(
            "Items_0_2026-01-05_09-00-00.csv",
            "\u{feff}Subject\r\nhello\r\n",
        )]))
        .await;
    let run = setup.run(&["--json", "--yes"]).await;
    assert_eq!(run.outcome.exit_code, 0, "{}", run.stdout());
    assert_eq!(run.json()["results"]["result"]["collection"], "unchecked");
    assert!(
        run.stderr().contains("warning: collection unchecked"),
        "{}",
        run.stderr()
    );
    let run = setup.run(&["--json", "--yes", "--strict"]).await;
    assert_eq!(run.outcome.exit_code, 4, "{}", run.stdout());
    assert_eq!(
        run.json()["outcome"]["reasons"][0]["code"],
        "EvidenceMissing"
    );
}

#[tokio::test]
async fn statistics_rows_do_not_change_a_report_s_collection() {
    let mut setup = Setup::new().await;
    let locations = format!(
        "{LOCATIONS_HEADER}Exchange,Mailbox,alex@contoso.example,id-1,Mailbox,PrimaryMailBox,12,2048,Succeeded,,q\r\n"
    );
    setup
        .ready_with(zip_of(&[
            ("Items_0_2026-01-05_09-00-00.csv", "\u{feff}Subject\r\nhello\r\n"),
            ("Locations-2026-01-05_09-00-00.csv", &locations),
            (
                "Statistics-2026-01-05_09-00-00.csv",
                "\u{feff}DataSourceName,DataSourceType,Location,LocationType,LocationSubType,StatType,StatName,OriginalStatName,Value\r\nExchange,Mailbox,pat@fabrikam.example,Mailbox,SystemMailbox,Error,OperationCanceledException,x,0\r\n",
            ),
        ]))
        .await;
    let run = setup.run(&["--json", "--yes", "--strict"]).await;
    assert_eq!(run.outcome.exit_code, 0, "{}", run.stdout());
    let result = &run.json()["results"]["result"];
    assert_eq!(result["collection"], "complete");
    assert_eq!(result["failedLocations"], json!([]));
}

#[tokio::test]
async fn an_estimate_only_volume_setting_does_not_stop_a_report() {
    let mut setup = Setup::new().await;
    setup.ready(false).await;
    set_config(
        &setup.harness,
        "volume",
        json!({"warn_hits": "bad", "warn_hits_per_location": -1}),
    );
    let run = setup.run(&["--json", "--yes", "--no-download"]).await;
    assert_eq!(run.outcome.exit_code, 0, "{}", run.stdout());
    // A bad max_export_size does.
    set_config(&setup.harness, "volume", json!({"max_export_size": 10}));
    let run = setup.run(&["--json", "--yes"]).await;
    assert_eq!(run.outcome.exit_code, 1);
    assert!(run.json()["error"]["message"]
        .as_str()
        .unwrap()
        .contains("volume.max_export_size"));
}

#[tokio::test]
async fn a_refresh_the_identity_platform_refuses_is_a_sign_in_error_not_a_size_check() {
    let mut setup = Setup::new().await;
    setup.ready(false).await;
    // Graph refuses the token on the estimate read, and the refresh that
    // follows is refused with HTTP 400.
    Mock::given(method("GET"))
        .and(path(last_estimate_path()))
        .respond_with(json_response(
            401,
            json!({"error": {"code": "InvalidAuthenticationToken"}}),
        ))
        .with_priority(1)
        .mount(&setup.harness.graph)
        .await;
    Mock::given(method("POST"))
        .and(path(token_path("token")))
        .respond_with(json_response(
            400,
            json!({"error": "invalid_grant", "error_description": "AADSTS70008: expired"}),
        ))
        .mount(&setup.harness.identity)
        .await;
    for args in [
        vec!["--json", "--yes"],
        vec!["--json", "--yes", "--allow-large", "--reason", "anyway"],
    ] {
        let run = setup.run(&args).await;
        assert_eq!(run.outcome.exit_code, 1, "{args:?}");
        let error = &run.json()["error"];
        assert_eq!(error["code"], "invalid_grant", "{args:?}: {error}");
        assert!(setup.posts().await.is_empty(), "{args:?}");
    }
}
