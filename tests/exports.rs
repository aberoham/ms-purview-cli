//! In-process flows of `export create` (`docs/SPEC.md` section 3.5)
//! through `cli::execute_with`: the action preflight and size limit it
//! shares with `report`, the `exportResult` body, polling, the download of
//! every part, and the collection check from the `Reports-…zip` part
//! alone. Every request to the mock Graph and download origin is recorded.

mod support;

use std::io::Write;
use std::net::SocketAddr;
use std::path::PathBuf;

use ms_purview_cli::download::DownloadRule;
use ms_purview_cli::env::Env;
use serde_json::{json, Value};
use support::*;
use wiremock::matchers::{method, path, query_param};
use wiremock::{Mock, MockServer, Request, ResponseTemplate};

const CASES: &str = "/v1.0/security/cases/ediscoveryCases";
const CASE: &str = "00000000-0000-4000-8000-000000000031";
const SEARCH: &str = "00000000-0000-4000-8000-000000000051";
const OP: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaa0001";
const ESTIMATE: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaa0009";
const ALPHA: &str = "alpha.proxyservice.ediscovery.svc.cloud.microsoft";
const FILE_PATH: &str = "/ediscovery/api/proxy/exportaedblobFileResult";
const GIB: u64 = 1 << 30;
/// A subject inside the items part, which no output may show.
const CANARY: &str = "canary-item-subject-7d1f";

const REPORT_NAME: &str = "Reports-Orders-orders-api-StartDirectExport-export-2026-01-05.zip";
const ITEMS_1: &str = "Items.1.001.export 2026-01-05 0900Z.zip";
const ITEMS_2: &str = "Items.1.002.export 2026-01-05 0900Z.zip";

fn search_path(tail: &str) -> String {
    format!("{CASES}/{CASE}/searches/{SEARCH}{tail}")
}

fn operation_path() -> String {
    format!("{CASES}/{CASE}/operations/{OP}")
}

const LOCATIONS_HEADER: &str = "\u{feff}DataSourceName,DataSourceType,Location,LocationId,LocationType,LocationSubType,Count,Size,Status,ErrorWarning,Query\r\n";

/// A zip of the given entries.
fn zip_of(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let mut buffer = std::io::Cursor::new(Vec::new());
    {
        let mut writer = zip::ZipWriter::new(&mut buffer);
        let options = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Deflated);
        for (name, body) in entries {
            writer.start_file(*name, options).unwrap();
            writer.write_all(body).unwrap();
        }
        writer.finish().unwrap();
    }
    buffer.into_inner()
}

/// The report part; `failed` adds one failed location.
fn report_part(failed: bool) -> Vec<u8> {
    let mut locations = String::from(LOCATIONS_HEADER);
    locations.push_str("Exchange,Mailbox,alex@contoso.example,id-1,Mailbox,PrimaryMailBox,12,2048,Succeeded,,q\r\n");
    if failed {
        locations.push_str("Exchange,Mailbox,kim@contoso.example,id-4,Mailbox,PrimaryMailBox,,,Failed,Timed out,q\r\n");
    }
    let items =
        "\u{feff}Subject,Sender,Location\r\nhello,alex@contoso.example,alex@contoso.example\r\n";
    zip_of(&[
        ("Items_0_2026-01-05_09-00-00.csv", items.as_bytes()),
        ("Locations-2026-01-05_09-00-00.csv", locations.as_bytes()),
    ])
}

/// An items part: a `.msg` stand-in holding the canary, and a Locations
/// file with a failed row, which the collection check must not read.
fn items_part() -> Vec<u8> {
    let mut locations = String::from(LOCATIONS_HEADER);
    locations.push_str(
        "Exchange,Mailbox,kim@contoso.example,id-4,Mailbox,PrimaryMailBox,,,Failed,Timed out,q\r\n",
    );
    zip_of(&[
        (
            "alex@contoso.example/Inbox/hello.msg",
            format!("Subject: {CANARY}").as_bytes(),
        ),
        ("Locations-2026-01-05_09-00-00.csv", locations.as_bytes()),
    ])
}

/// The search's latest estimate, with `size` bytes.
fn estimate(size: Value) -> Value {
    json!({
        "id": ESTIMATE,
        "action": "estimateStatistics",
        "status": "succeeded",
        "createdDateTime": "2026-01-04T09:00:00Z",
        "indexedItemCount": 120,
        "indexedItemsSize": size,
        "reportFileMetadata": [],
    })
}

/// One file an operation offers: its server name, the `part` query value
/// it is served under, and its bytes.
struct Part {
    name: &'static str,
    key: &'static str,
    bytes: Vec<u8>,
}

struct Setup {
    harness: Harness,
    alpha: MockServer,
    parts: Vec<Part>,
}

impl Setup {
    async fn new() -> Self {
        let harness = Harness::new().await;
        sign_in_alex(&harness).await;
        Self {
            harness,
            alpha: MockServer::start().await,
            parts: vec![
                Part {
                    name: REPORT_NAME,
                    key: "report",
                    bytes: report_part(false),
                },
                Part {
                    name: ITEMS_1,
                    key: "items1",
                    bytes: items_part(),
                },
            ],
        }
    }

    fn data_root(&self) -> PathBuf {
        self.harness.root.path().join("data")
    }

    fn file_url(&self, key: &str) -> String {
        format!(
            "http://{ALPHA}:{}{FILE_PATH}?downloadType=Export&part={key}",
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

    /// `operation get <case> <op> --check`, as a resume runs it.
    async fn check(&self) -> Run {
        self.harness
            .run_with(
                &["--json", "operation", "get", CASE, OP, "--check"],
                |env, _| self.configure(env),
            )
            .await
    }

    async fn run(&self, args: &[&str]) -> Run {
        let mut argv = vec!["export", "create", CASE, SEARCH];
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
    async fn preflight(&self, operations: Value, latest: Value) {
        self.get(
            &search_path(""),
            graph_fixture("search-get-mailboxes.json", &self.harness.graph.uri()),
        )
        .await;
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
        self.get(&search_path("/lastEstimateStatisticsOperation"), latest)
            .await;
    }

    async fn accept(&self) {
        let location = format!(
            "{}/v1.0/security/cases/ediscoverycases('{CASE}')/operations('{OP}')",
            self.harness.graph.uri()
        );
        Mock::given(method("POST"))
            .and(path(search_path("/exportResult")))
            .respond_with(ResponseTemplate::new(202).insert_header("Location", location))
            .mount(&self.harness.graph)
            .await;
    }

    /// A succeeded export of the setup's parts, as a single GET shows it.
    fn succeeded(&self) -> Value {
        let files: Vec<Value> = self
            .parts
            .iter()
            .map(|part| {
                json!({
                    "fileName": part.name,
                    "size": part.bytes.len(),
                    "downloadUrl": self.file_url(part.key),
                })
            })
            .collect();
        json!({
            "@odata.type": "#microsoft.graph.security.ediscoverySearchExportOperation",
            "id": OP,
            "action": "exportResult",
            "status": "succeeded",
            "createdDateTime": "2026-01-05T09:00:00Z",
            "displayName": "export 2026-01-05 0900Z",
            "exportCriteria": "searchHits",
            "exportLocation": "responsiveLocations",
            "additionalOptions": "teamsAndYammerConversations,includeReport",
            "exportFormat": "msg",
            "exportFileMetadata": files,
        })
    }

    /// The parts served by the download origin.
    async fn serve(&self) {
        for part in &self.parts {
            Mock::given(method("GET"))
                .and(path(FILE_PATH))
                .and(query_param("part", part.key))
                .respond_with(ResponseTemplate::new(200).set_body_bytes(part.bytes.clone()))
                .mount(&self.alpha)
                .await;
        }
    }

    /// A whole export: a small estimate, the 202, a succeeded operation
    /// and its parts.
    async fn ready(&self) {
        self.preflight(json!({"value": []}), estimate(json!(GIB)))
            .await;
        self.accept().await;
        self.get(&operation_path(), self.succeeded()).await;
        self.serve().await;
    }

    async fn posts(&self) -> Vec<Request> {
        self.harness
            .graph
            .received_requests()
            .await
            .expect("the mock Graph records requests")
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
async fn an_export_posts_the_observed_body_downloads_every_part_and_checks_the_report() {
    let setup = Setup::new().await;
    setup.ready().await;
    let run = setup.run(&["--json", "--yes"]).await;
    assert_eq!(
        run.outcome.exit_code,
        0,
        "{} {}",
        run.stdout(),
        run.stderr()
    );
    assert_eq!(
        setup.post_body().await,
        json!({
            "displayName": "export 2026-01-05 0900Z",
            "exportCriteria": "searchHits",
            "exportLocation": "responsiveLocations",
            "additionalOptions": "teamsAndYammerConversations,includeReport",
            "exportFormat": "msg",
        })
    );
    let plan = &run.json()["results"]["plan"];
    assert_eq!(plan["command"], "export create");
    let warnings = plan["warnings"].to_string();
    assert!(warnings.contains("about four times"), "{warnings}");
    assert!(warnings.contains("counted 120 items"), "{warnings}");
    assert!(warnings.contains("the download is large"), "{warnings}");
    assert!(!warnings.contains("rows per estimated item"), "{warnings}");
    let effects = plan["effects"].to_string();
    assert!(effects.contains(".msg files"), "{effects}");
    let preflight = plan["preflight"].to_string();
    assert!(
        preflight.contains("teamsAndYammerConversations,includeReport"),
        "{preflight}"
    );
    let result = &run.json()["results"]["result"];
    assert_eq!(result["operationId"], OP);
    assert_eq!(result["operationStatus"], "succeeded");
    // From the report part alone: the items part's failed row is not read.
    assert_eq!(result["collection"], "complete");
    assert_eq!(result["failedLocations"], json!([]));
    assert_eq!(result["estimateId"], ESTIMATE);
    let files = result["files"].as_array().unwrap();
    assert_eq!(files.len(), 2, "{files:?}");
    for file in files {
        let path = PathBuf::from(file["path"].as_str().unwrap());
        assert!(path.starts_with(setup.data_root().join("cases").join(CASE).join(OP)));
        assert!(path.exists());
    }
    assert_eq!(setup.downloads().await.len(), 2);
    assert!(!run.stdout().contains(CANARY));
    assert!(!run.stderr().contains(CANARY));
}

#[tokio::test]
async fn the_items_part_is_not_read_even_when_it_comes_first() {
    // The items part listed first, with a failed row of its own; the
    // report part has none, so the collection is complete.
    let mut setup = Setup::new().await;
    setup.parts.reverse();
    setup.ready().await;
    let run = setup.run(&["--json", "--yes"]).await;
    assert_eq!(run.outcome.exit_code, 0, "{}", run.stdout());
    let result = &run.json()["results"]["result"];
    assert_eq!(result["collection"], "complete");
    assert_eq!(result["failedLocations"], json!([]));
    assert_eq!(result["files"].as_array().unwrap().len(), 2);
}

#[tokio::test]
async fn a_failed_location_in_the_report_part_is_incomplete_and_strict_exits_4() {
    let mut setup = Setup::new().await;
    setup.parts[0].bytes = report_part(true);
    setup.ready().await;
    let run = setup.run(&["--json", "--yes"]).await;
    assert_eq!(run.outcome.exit_code, 0, "{}", run.stdout());
    let result = &run.json()["results"]["result"];
    assert_eq!(result["collection"], "incomplete");
    assert_eq!(result["failedLocations"].as_array().unwrap().len(), 1);
    assert!(
        run.stderr()
            .contains("the export succeeded, but 1 location was not searched in full"),
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
async fn an_export_without_a_report_part_is_unchecked_and_its_items_are_not_read() {
    let mut setup = Setup::new().await;
    setup.parts.remove(0);
    setup.ready().await;
    let run = setup.run(&["--json", "--yes"]).await;
    assert_eq!(run.outcome.exit_code, 0, "{}", run.stdout());
    assert_eq!(run.json()["results"]["result"]["collection"], "unchecked");
    assert!(
        run.stderr()
            .contains("lists no file that can hold its evidence (for an export, a Reports- file)"),
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
async fn every_items_part_is_downloaded() {
    let mut setup = Setup::new().await;
    setup.parts.push(Part {
        name: ITEMS_2,
        key: "items2",
        bytes: items_part(),
    });
    setup.ready().await;
    let run = setup.run(&["--json", "--yes"]).await;
    assert_eq!(run.outcome.exit_code, 0, "{}", run.stdout());
    let files = run.json()["results"]["result"]["files"].clone();
    let names: Vec<&str> = files
        .as_array()
        .unwrap()
        .iter()
        .map(|file| file["fileName"].as_str().unwrap())
        .collect();
    assert_eq!(names, [REPORT_NAME, ITEMS_1, ITEMS_2]);
    assert_eq!(setup.downloads().await.len(), 3);
}

#[tokio::test]
async fn teams_context_off_sends_include_report_alone() {
    let setup = Setup::new().await;
    setup.ready().await;
    let run = setup
        .run(&["--json", "--yes", "--no-download", "--no-teams-context"])
        .await;
    assert_eq!(run.outcome.exit_code, 0, "{}", run.stdout());
    let body = setup.post_body().await;
    assert_eq!(body["additionalOptions"], "includeReport");
    assert_eq!(body["exportFormat"], "msg");
    let plan = &run.json()["results"]["plan"];
    assert!(plan["warnings"].to_string().contains("experimental"));
    assert!(plan["preflight"]
        .to_string()
        .contains("Teams context: off (additionalOptions includeReport"));
    assert_eq!(run.json()["results"]["result"]["teamsContext"], false);
    assert!(setup.downloads().await.is_empty());

    let setup = Setup::new().await;
    setup.ready().await;
    set_config(&setup.harness, "defaults", json!({"teams_context": false}));
    let run = setup.run(&["--json", "--yes", "--no-download"]).await;
    assert_eq!(run.outcome.exit_code, 0, "{}", run.stdout());
    assert_eq!(
        setup.post_body().await["additionalOptions"],
        "includeReport"
    );
}

#[tokio::test]
async fn an_estimate_above_the_size_limit_blocks_the_export_and_allow_large_sends_it() {
    let setup = Setup::new().await;
    setup
        .preflight(json!({"value": []}), estimate(json!(11 * GIB)))
        .await;
    setup.accept().await;
    let run = setup.run(&["--json", "--yes"]).await;
    assert_eq!(run.outcome.exit_code, 1, "{}", run.stdout());
    assert_eq!(run.json()["error"]["code"], "TooLarge");
    assert!(setup.posts().await.is_empty());

    let run = setup
        .run(&[
            "--json",
            "--yes",
            "--no-wait",
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
}

#[tokio::test]
async fn a_search_without_an_estimate_is_refused_before_any_post() {
    let setup = Setup::new().await;
    setup.preflight(json!({"value": []}), json!(null)).await;
    setup.accept().await;
    let run = setup.run(&["--json", "--yes"]).await;
    assert_eq!(run.outcome.exit_code, 1, "{}", run.stdout());
    assert_eq!(run.json()["error"]["code"], "VolumeUnchecked");
    assert!(setup.posts().await.is_empty());
}

#[tokio::test]
async fn a_report_or_export_not_yet_finished_needs_allow_concurrent() {
    let setup = Setup::new().await;
    setup
        .preflight(
            json!({"value": [
                {"id": "aaaaaaaaaaaaaaaaaaaaaaaaaaaa0005", "action": "exportResult", "status": "running", "createdDateTime": "2026-01-05T08:00:00Z"},
            ]}),
            estimate(json!(GIB)),
        )
        .await;
    setup.accept().await;
    let run = setup.run(&["--json", "--yes"]).await;
    assert_eq!(run.outcome.exit_code, 1, "{}", run.stdout());
    assert_eq!(run.json()["error"]["code"], "ConcurrentOperation");
    assert!(setup.posts().await.is_empty());
}

#[tokio::test]
async fn an_operation_that_is_not_an_export_is_not_downloaded() {
    let setup = Setup::new().await;
    setup.ready().await;
    let mut report = setup.succeeded();
    report["action"] = json!("exportReport");
    Mock::given(method("GET"))
        .and(path(operation_path()))
        .respond_with(json_response(200, report))
        .with_priority(1)
        .mount(&setup.harness.graph)
        .await;
    let run = setup.run(&["--json", "--yes"]).await;
    assert_eq!(run.json()["error"]["code"], "UnexpectedLocation");
    assert!(run.json()["error"]["message"]
        .as_str()
        .unwrap()
        .contains("is not an export"));
    assert!(setup.downloads().await.is_empty());
}

#[tokio::test]
async fn no_wait_submits_and_resumes_with_the_check_never_download() {
    let setup = Setup::new().await;
    setup.ready().await;
    let run = setup.run(&["--json", "--yes", "--no-wait"]).await;
    assert_eq!(run.outcome.exit_code, 0, "{}", run.stdout());
    let result = &run.json()["results"]["result"];
    assert_eq!(result["operationId"], OP);
    assert_eq!(result["collection"], "unchecked");
    let resume = result["resume"].as_array().unwrap();
    assert_eq!(resume.len(), 1, "{resume:?}");
    assert!(resume[0]
        .as_str()
        .unwrap()
        .ends_with(&format!("operation get {CASE} {OP} --wait --check")));
    assert!(setup.downloads().await.is_empty());
}

#[tokio::test]
async fn an_unclear_export_lists_candidates_by_their_true_action() {
    let setup = Setup::new().await;
    setup
        .preflight(json!({"value": []}), estimate(json!(GIB)))
        .await;
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
            ]}),
        ))
        .with_priority(2)
        .mount(&setup.harness.graph)
        .await;
    let mut running = setup.succeeded();
    running["status"] = json!("running");
    setup.get(&operation_path(), running).await;
    Mock::given(method("POST"))
        .and(path(search_path("/exportResult")))
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
        message.contains(&format!("export {OP} (running")),
        "{message}"
    );
    assert!(!message.contains("report or export"), "{message}");
    assert_eq!(setup.posts().await.len(), 1);
}

#[tokio::test]
async fn a_human_run_shows_the_plan_and_never_the_items() {
    let setup = Setup::new().await;
    setup.ready().await;
    let run = setup.run(&["--yes"]).await;
    assert_eq!(run.outcome.exit_code, 0, "{}", run.stderr());
    let stderr = run.stderr();
    assert!(stderr.contains("Plan: purview export create"), "{stderr}");
    let stdout = run.stdout();
    assert!(
        stdout.starts_with("Applied: purview export create\n"),
        "{stdout}"
    );
    assert!(stdout.contains("\"collection\": \"complete\""), "{stdout}");
    assert!(!stdout.contains(CANARY) && !stderr.contains(CANARY));
}

#[tokio::test]
async fn a_dry_run_sends_nothing() {
    let setup = Setup::new().await;
    setup.ready().await;
    let run = setup.run(&["--json", "--dry-run"]).await;
    assert_eq!(run.outcome.exit_code, 0, "{}", run.stdout());
    assert_eq!(run.json()["results"]["applied"], false);
    assert!(setup.posts().await.is_empty());
    assert!(setup.downloads().await.is_empty());
}

#[tokio::test]
async fn an_export_whose_detail_is_not_an_export_is_not_downloaded() {
    let setup = Setup::new().await;
    setup.ready().await;
    let mut wrong = setup.succeeded();
    wrong["@odata.type"] = json!("#microsoft.graph.security.ediscoveryEstimateOperation");
    // The parts listed where an estimate lists its files, so that a
    // download would find them.
    wrong["reportFileMetadata"] = wrong["exportFileMetadata"].clone();
    Mock::given(method("GET"))
        .and(path(operation_path()))
        .respond_with(json_response(200, wrong))
        .with_priority(1)
        .mount(&setup.harness.graph)
        .await;
    let run = setup.run(&["--json", "--yes"]).await;
    assert_eq!(run.json()["error"]["code"], "UnexpectedLocation");
    assert!(setup.downloads().await.is_empty());
}

#[tokio::test]
async fn the_resume_check_never_fetches_an_items_part_whatever_the_action_says() {
    // An operation that says it is an item report but lists an export's
    // parts, items first with a failed row: the check fetches only the
    // file that is not an items part.
    let mut setup = Setup::new().await;
    setup.parts.reverse();
    setup.serve().await;
    let mut record = setup.succeeded();
    record["action"] = json!("exportReport");
    setup.get(&operation_path(), record).await;
    let run = setup.check().await;
    assert_eq!(
        run.outcome.exit_code,
        0,
        "{} {}",
        run.stdout(),
        run.stderr()
    );
    assert_eq!(run.json()["results"]["collection"], "complete");
    let downloads = setup.downloads().await;
    assert_eq!(downloads.len(), 1);
    assert!(downloads[0].url.query().unwrap().contains("part=report"));
    assert!(!run.stdout().contains(CANARY) && !run.stderr().contains(CANARY));
}

#[tokio::test]
async fn the_resume_check_fetches_nothing_when_the_detail_is_not_the_action_s() {
    let setup = Setup::new().await;
    setup.serve().await;
    let mut record = setup.succeeded();
    record["@odata.type"] = json!("#microsoft.graph.security.ediscoveryEstimateOperation");
    record["reportFileMetadata"] = record["exportFileMetadata"].clone();
    setup.get(&operation_path(), record).await;
    let run = setup.check().await;
    assert_eq!(
        run.json()["results"]["collection"],
        "unchecked",
        "{}",
        run.stdout()
    );
    assert!(
        run.stderr().contains("is not that of its action"),
        "{}",
        run.stderr()
    );
    assert!(setup.downloads().await.is_empty());
}

#[tokio::test]
async fn a_direct_export_and_its_resume_check_read_the_same_report_part() {
    // Two Reports- files: the first has no Locations, the second a failed
    // location. Both paths go on to the second.
    let mut setup = Setup::new().await;
    setup.parts.insert(
        0,
        Part {
            name: "Reports-first-without-locations.zip",
            key: "report0",
            bytes: zip_of(&[(
                "Summary-2026-01-05_09-00-00.csv",
                b"\xef\xbb\xbfJob ID,j,x\r\n",
            )]),
        },
    );
    setup.parts[1].bytes = report_part(true);
    setup.ready().await;
    let run = setup.run(&["--json", "--yes"]).await;
    assert_eq!(run.outcome.exit_code, 0, "{}", run.stdout());
    assert_eq!(run.json()["results"]["result"]["collection"], "incomplete");
    let run = setup.check().await;
    assert_eq!(run.outcome.exit_code, 0, "{}", run.stdout());
    assert_eq!(run.json()["results"]["collection"], "incomplete");
}

#[tokio::test]
async fn an_unclear_export_labels_an_item_report_candidate_by_its_own_read() {
    let setup = Setup::new().await;
    setup
        .preflight(json!({"value": []}), estimate(json!(GIB)))
        .await;
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
            ]}),
        ))
        .with_priority(2)
        .mount(&setup.harness.graph)
        .await;
    let mut report = setup.succeeded();
    report["action"] = json!("exportReport");
    report["status"] = json!("running");
    setup.get(&operation_path(), report).await;
    Mock::given(method("POST"))
        .and(path(search_path("/exportResult")))
        .respond_with(json_response(
            503,
            json!({"error": {"code": "ServiceUnavailable"}}),
        ))
        .mount(&setup.harness.graph)
        .await;
    let run = setup.run(&["--json", "--yes"]).await;
    let message = run.json()["error"]["message"].as_str().unwrap().to_owned();
    assert!(
        message.contains(&format!("item report {OP} (running")),
        "{message}"
    );
}

#[tokio::test]
async fn allow_concurrent_sends_the_export_despite_a_possible_duplicate() {
    let setup = Setup::new().await;
    setup
        .preflight(
            json!({"value": [
                {"id": "aaaaaaaaaaaaaaaaaaaaaaaaaaaa0005", "action": "exportResult", "status": "running", "createdDateTime": "2026-01-05T08:00:00Z"},
            ]}),
            estimate(json!(GIB)),
        )
        .await;
    setup.accept().await;
    let run = setup
        .run(&["--json", "--yes", "--no-wait", "--allow-concurrent"])
        .await;
    assert_eq!(run.outcome.exit_code, 0, "{}", run.stdout());
    assert_eq!(setup.posts().await.len(), 1);
    let warnings = run.json()["results"]["plan"]["warnings"].to_string();
    assert!(warnings.contains("may be a duplicate"), "{warnings}");
    // Without a download, the plan does not promise one.
    let effects = run.json()["results"]["plan"]["effects"].to_string();
    assert!(!effects.contains("Downloads every part"), "{effects}");
}

#[tokio::test]
async fn only_a_reports_file_is_an_export_s_evidence() {
    // A file of another name, listed first, with a failed location: an
    // export reads only its Reports- part, so the collection is complete.
    let mut setup = Setup::new().await;
    setup.parts.insert(
        0,
        Part {
            name: "Summary-of-the-export.zip",
            key: "other",
            bytes: report_part(true),
        },
    );
    setup.ready().await;
    let run = setup.run(&["--json", "--yes"]).await;
    assert_eq!(run.outcome.exit_code, 0, "{}", run.stdout());
    assert_eq!(run.json()["results"]["result"]["collection"], "complete");
    let run = setup.check().await;
    assert_eq!(run.json()["results"]["collection"], "complete");
}

#[tokio::test]
async fn the_first_usable_report_part_in_graph_s_order_decides_on_both_paths() {
    // Two usable Reports- files with opposite results: the first listed,
    // which has no failure, decides.
    let mut setup = Setup::new().await;
    setup.parts.push(Part {
        name: "Reports-second-with-a-failure.zip",
        key: "report2",
        bytes: report_part(true),
    });
    setup.ready().await;
    let run = setup.run(&["--json", "--yes"]).await;
    assert_eq!(run.json()["results"]["result"]["collection"], "complete");
    let run = setup.check().await;
    assert_eq!(run.json()["results"]["collection"], "complete");
}

#[tokio::test]
async fn a_direct_item_report_never_downloads_an_items_part() {
    // An item report that lists an export's parts: `report` fetches the
    // report part and leaves the items part on the service.
    let setup = Setup::new().await;
    setup
        .preflight(json!({"value": []}), estimate(json!(GIB)))
        .await;
    let location = format!(
        "{}/v1.0/security/cases/ediscoverycases('{CASE}')/operations('{OP}')",
        setup.harness.graph.uri()
    );
    Mock::given(method("POST"))
        .and(path(search_path("/exportReport")))
        .respond_with(ResponseTemplate::new(202).insert_header("Location", location))
        .mount(&setup.harness.graph)
        .await;
    let mut record = setup.succeeded();
    record["action"] = json!("exportReport");
    setup.get(&operation_path(), record).await;
    setup.serve().await;
    let run = setup
        .harness
        .run_with(&["report", CASE, SEARCH, "--json", "--yes"], |env, _| {
            setup.configure(env)
        })
        .await;
    assert_eq!(
        run.outcome.exit_code,
        0,
        "{} {}",
        run.stdout(),
        run.stderr()
    );
    assert_eq!(run.json()["results"]["result"]["collection"], "complete");
    let downloads = setup.downloads().await;
    assert_eq!(downloads.len(), 1);
    assert!(downloads[0].url.query().unwrap().contains("part=report"));
    assert_eq!(
        run.json()["results"]["result"]["files"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
}

#[tokio::test]
async fn no_download_leaves_the_download_out_of_the_plan() {
    let setup = Setup::new().await;
    setup.ready().await;
    let run = setup.run(&["--json", "--dry-run", "--no-download"]).await;
    let effects = run.json()["results"]["plan"]["effects"].to_string();
    assert!(!effects.contains("Downloads every part"), "{effects}");
    let run = setup.run(&["--json", "--dry-run"]).await;
    let effects = run.json()["results"]["plan"]["effects"].to_string();
    assert!(effects.contains("Downloads every part"), "{effects}");
}

#[tokio::test]
async fn the_check_reports_a_file_entry_with_no_name() {
    let setup = Setup::new().await;
    setup.serve().await;
    let mut record = setup.succeeded();
    record["action"] = json!("exportReport");
    record["exportFileMetadata"]
        .as_array_mut()
        .unwrap()
        .push(json!({"size": 10}));
    record["exportFileMetadata"]
        .as_array_mut()
        .unwrap()
        .push(json!({"fileName": "", "size": 10}));
    setup.get(&operation_path(), record).await;
    let run = setup.check().await;
    assert_eq!(run.json()["results"]["collection"], "complete");
    assert!(
        run.stderr()
            .contains("file 4 of the operation cannot be downloaded: it has no fileName"),
        "{}",
        run.stderr()
    );
    assert!(
        run.stderr()
            .contains("file 3 of the operation cannot be downloaded: it has no fileName"),
        "{}",
        run.stderr()
    );
}
