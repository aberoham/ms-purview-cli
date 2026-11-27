//! In-process flows of `purview download` (`docs/SPEC.md` section 8.5,
//! item 6) through `cli::execute_with`, against a wiremock Graph, mock
//! download origins reached through host names that match the production
//! host rule, an in-memory credential store and a manual clock.

mod support;

use std::io::Write;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use ms_purview_cli::download::DownloadRule;
use ms_purview_cli::env::Env;
use serde_json::{json, Value};
use support::*;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, Request, ResponseTemplate};

const CASES: &str = "/v1.0/security/cases/ediscoveryCases";
const CASE: &str = "00000000-0000-4000-8000-000000000031";
const OP: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaa0001";
const ALPHA: &str = "alpha.proxyservice.ediscovery.svc.cloud.microsoft";
const BETA: &str = "beta.proxyservice.ediscovery.svc.cloud.microsoft";
const FILE_PATH: &str = "/ediscovery/api/proxy/exportaedblobFileResult";
const NAME: &str = "Orders API mentions_Estimate.zip";
const GRAPH_TOKEN: &str = "canary-graph-access-0001";
const DOWNLOAD_TOKEN: &str = "canary-download-access-0001";

/// A signed-in harness with download origins: `alpha` (the one the
/// operation names), `beta` (a sibling host that also matches the rule)
/// and `other` (alpha's host name on another port).
struct Setup {
    harness: Harness,
    alpha: MockServer,
    beta: MockServer,
    other: MockServer,
}

impl Setup {
    async fn new() -> Self {
        let harness = Harness::new().await;
        sign_in_alex(&harness).await;
        Self {
            harness,
            alpha: MockServer::start().await,
            beta: MockServer::start().await,
            other: MockServer::start().await,
        }
    }

    fn url(&self, server: &MockServer, host: &str, tail: &str) -> String {
        format!("http://{host}:{}{tail}", server.address().port())
    }

    /// The `downloadUrl` of the default file.
    fn file_url(&self) -> String {
        self.url(
            &self.alpha,
            ALPHA,
            &format!("{FILE_PATH}?downloadType=Report"),
        )
    }

    fn data_root(&self) -> PathBuf {
        self.harness.root.path().join("data")
    }

    fn target_dir(&self) -> PathBuf {
        self.data_root().join("cases").join(CASE).join(OP)
    }

    fn configure(&self, env: &mut Env) {
        env.download_rule = DownloadRule {
            allow_http: true,
            any_port: true,
            ..DownloadRule::production()
        };
        let address = |server: &MockServer| -> SocketAddr { *server.address() };
        env.download_resolve = vec![
            (ALPHA.to_owned(), address(&self.alpha)),
            (BETA.to_owned(), address(&self.beta)),
        ];
        env.data_dir = Some(self.data_root());
    }

    async fn run(&self, args: &[&str]) -> Run {
        self.run_with(args, |_| {}).await
    }

    async fn run_with(&self, args: &[&str], more: impl FnOnce(&mut Env)) -> Run {
        self.harness
            .run_with(args, |env, _| {
                self.configure(env);
                more(env);
            })
            .await
    }

    /// Mounts the operation with these files and this status.
    async fn operation(&self, status: &str, files: Value) {
        self.harness.graph.reset().await;
        self.add_operation(OP, status, files).await;
    }

    /// Mounts another operation beside those mounted already.
    async fn add_operation(&self, op: &str, status: &str, files: Value) {
        let mut record = estimate(status, files);
        record["id"] = json!(op);
        Mock::given(method("GET"))
            .and(path(format!("{CASES}/{CASE}/operations/{op}")))
            .respond_with(json_response(200, record))
            .mount(&self.harness.graph)
            .await;
    }

    /// Sets `config.json`'s `download` object.
    fn configure_download(&self, download: Value) {
        let mut config = self.harness.config();
        config["download"] = download;
        std::fs::write(
            self.harness.config_dir().join("config.json"),
            serde_json::to_vec(&config).unwrap(),
        )
        .unwrap();
    }

    /// Mounts the default file at alpha.
    async fn serve(&self, body: Vec<u8>) {
        Mock::given(method("GET"))
            .and(path(FILE_PATH))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(body))
            .mount(&self.alpha)
            .await;
    }

    async fn requests(server: &MockServer) -> Vec<Request> {
        server.received_requests().await.unwrap()
    }
}

fn estimate(status: &str, files: Value) -> Value {
    json!({
        "@odata.type": "#microsoft.graph.security.ediscoveryEstimateOperation",
        "id": OP,
        "action": "estimateStatistics",
        "status": status,
        "indexedItemCount": 12,
        "reportFileMetadata": files,
    })
}

fn file(name: &str, size: u64, url: &str) -> Value {
    json!({"fileName": name, "size": size, "downloadUrl": url})
}

/// A small report zip with a `Summary.csv`.
fn zip_bytes(text: &str) -> Vec<u8> {
    let mut buffer = std::io::Cursor::new(Vec::new());
    {
        let mut writer = zip::ZipWriter::new(&mut buffer);
        writer
            .start_file("Summary.csv", zip::write::SimpleFileOptions::default())
            .unwrap();
        writer.write_all(text.as_bytes()).unwrap();
        writer.finish().unwrap();
    }
    buffer.into_inner()
}

fn sha256(bytes: &[u8]) -> String {
    use sha2::Digest;
    sha2::Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// Every name in `dir` but the lock file, which stays once made, sorted.
/// Temporary `.part` files are listed, so a test sees one left behind.
fn entries(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(dir)
        .map(|read| {
            read.map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
                .filter(|name| name != ms_purview_cli::download::LOCK_FILE)
                .collect()
        })
        .unwrap_or_default();
    names.sort();
    names
}

fn manifest(dir: &Path) -> Value {
    serde_json::from_slice(&std::fs::read(dir.join("manifest.json")).unwrap()).unwrap()
}

fn header(request: &Request, name: &str) -> Option<String> {
    request
        .headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned)
}

#[tokio::test]
async fn an_estimate_report_is_downloaded_with_the_download_token_and_recorded() {
    let setup = Setup::new().await;
    let body = zip_bytes("Locations,1\n");
    setup
        .operation("succeeded", json!([file(NAME, 0, &setup.file_url())]))
        .await;
    setup.serve(body.clone()).await;
    let run = setup.run(&["--json", "download", CASE, OP]).await;
    assert_eq!(run.outcome.exit_code, 0, "{}{}", run.stderr(), run.stdout());
    let target = setup.target_dir().join(NAME);
    assert_eq!(std::fs::read(&target).unwrap(), body);
    assert_eq!(
        run.json(),
        json!({
            "results": [{
                "fileName": NAME,
                "path": target.to_string_lossy(),
                "size": body.len(),
                "sha256": sha256(&body),
                "status": "downloaded",
            }],
            "count": 1,
        })
    );
    assert_eq!(entries(&setup.target_dir()), [NAME, "manifest.json"]);
    let recorded = manifest(&setup.target_dir());
    assert_eq!(recorded["version"], 1);
    assert_eq!(
        recorded["files"],
        json!([{
            "caseId": CASE,
            "operationId": OP,
            "action": "estimate",
            "serverFileName": NAME,
            "fileName": NAME,
            "size": body.len(),
            "sha256": sha256(&body),
            "downloadedAt": "2026-01-05T09:00:10Z",
        }])
    );
    // The download token, and only it, reaches the download origin, with
    // the header the service needs; the Graph token stays on Graph.
    let downloads = Setup::requests(&setup.alpha).await;
    assert_eq!(downloads.len(), 1);
    assert_eq!(
        header(&downloads[0], "authorization").as_deref(),
        Some(format!("Bearer {DOWNLOAD_TOKEN}").as_str())
    );
    assert_eq!(
        header(&downloads[0], "x-allowwithaadtoken").as_deref(),
        Some("true")
    );
    assert_eq!(header(&downloads[0], "accept-encoding"), None);
    for request in Setup::requests(&setup.harness.graph).await {
        assert_eq!(
            header(&request, "authorization").as_deref(),
            Some(format!("Bearer {GRAPH_TOKEN}").as_str())
        );
    }
    setup.harness.assert_no_canaries(&run);
}

#[tokio::test]
async fn a_verified_download_is_not_fetched_again_and_needs_no_token() {
    let setup = Setup::new().await;
    let body = zip_bytes("x\n");
    setup
        .operation("succeeded", json!([file(NAME, 0, &setup.file_url())]))
        .await;
    setup.serve(body.clone()).await;
    assert_eq!(
        setup.run(&["download", CASE, OP]).await.outcome.exit_code,
        0
    );
    let again = setup.run(&["--plain", "download", CASE, OP]).await;
    assert_eq!(again.outcome.exit_code, 0, "{}", again.stderr());
    assert_eq!(
        again.stdout(),
        format!(
            "alreadyDownloaded\t{}\t{}\n",
            body.len(),
            setup.target_dir().join(NAME).display()
        )
    );
    assert_eq!(Setup::requests(&setup.alpha).await.len(), 1);
    assert!(setup
        .harness
        .identity
        .received_requests()
        .await
        .unwrap()
        .is_empty());
}

#[tokio::test]
async fn a_401_is_download_refused_and_leaves_no_file() {
    let setup = Setup::new().await;
    setup
        .operation("succeeded", json!([file(NAME, 0, &setup.file_url())]))
        .await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(401))
        .mount(&setup.alpha)
        .await;
    let run = setup.run(&["--json", "download", CASE, OP]).await;
    assert_eq!(run.outcome.exit_code, 1);
    let error = &run.json()["error"];
    assert_eq!(error["code"], "DownloadRefused");
    assert_eq!(error["status"], 401);
    assert!(error["message"]
        .as_str()
        .unwrap()
        .contains("eDiscovery.Download.Read"));
    assert_eq!(entries(&setup.target_dir()), Vec::<String>::new());
}

#[tokio::test]
async fn a_same_origin_redirect_is_followed_with_the_same_headers() {
    let setup = Setup::new().await;
    let body = zip_bytes("moved\n");
    setup
        .operation("succeeded", json!([file(NAME, 0, &setup.file_url())]))
        .await;
    Mock::given(method("GET"))
        .and(path(FILE_PATH))
        .respond_with(
            ResponseTemplate::new(302).insert_header("location", "/moved?sig=canary-sig-0001"),
        )
        .mount(&setup.alpha)
        .await;
    Mock::given(method("GET"))
        .and(path("/moved"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(body.clone()))
        .mount(&setup.alpha)
        .await;
    let trace = setup.harness.root.path().join("trace");
    let run = setup
        .run(&[
            "--verbose",
            "--trace",
            trace.to_str().unwrap(),
            "download",
            CASE,
            OP,
        ])
        .await;
    assert_eq!(run.outcome.exit_code, 0, "{}", run.stderr());
    assert_eq!(std::fs::read(setup.target_dir().join(NAME)).unwrap(), body);
    let downloads = Setup::requests(&setup.alpha).await;
    assert_eq!(downloads.len(), 2);
    for request in &downloads {
        assert_eq!(
            header(request, "authorization").as_deref(),
            Some(format!("Bearer {DOWNLOAD_TOKEN}").as_str())
        );
        assert_eq!(
            header(request, "x-allowwithaadtoken").as_deref(),
            Some("true")
        );
    }
    // The signature in the redirect never reaches output or the trace.
    setup
        .harness
        .assert_absent(&run, &["canary-sig-0001", DOWNLOAD_TOKEN, GRAPH_TOKEN]);
    // The trace records the download's length, never its bytes.
    let records: Vec<Value> = std::fs::read_dir(&trace)
        .unwrap()
        .map(|entry| {
            serde_json::from_slice(&std::fs::read(entry.unwrap().path()).unwrap()).unwrap()
        })
        .collect();
    let file_record = records
        .iter()
        .find(|record| {
            record["request"]["url"]
                .as_str()
                .unwrap()
                .contains("/moved")
        })
        .expect("a trace of the redirected request");
    assert_eq!(file_record["response"]["status"], 200);
    assert_eq!(file_record["response"]["bytes"], body.len());
    assert_eq!(file_record["response"]["body"], Value::Null);
    assert!(run
        .stderr()
        .contains("[verbose] following a redirect on the same origin"));
}

#[tokio::test]
async fn a_redirect_to_a_sibling_host_or_another_port_is_refused_and_never_contacted() {
    let setup = Setup::new().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(zip_bytes("no\n")))
        .mount(&setup.beta)
        .await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(zip_bytes("no\n")))
        .mount(&setup.other)
        .await;
    let targets = [
        setup.url(&setup.beta, BETA, "/x"),
        setup.url(&setup.other, ALPHA, "/x"),
        format!("https://{ALPHA}:{}/x", setup.alpha.address().port()),
    ];
    for target in targets {
        setup.alpha.reset().await;
        setup
            .operation("succeeded", json!([file(NAME, 0, &setup.file_url())]))
            .await;
        Mock::given(method("GET"))
            .and(path(FILE_PATH))
            .respond_with(ResponseTemplate::new(307).insert_header("location", target.as_str()))
            .mount(&setup.alpha)
            .await;
        let run = setup.run(&["--json", "download", CASE, OP]).await;
        assert_eq!(run.outcome.exit_code, 1, "{target}");
        assert_eq!(
            run.json()["error"]["code"],
            "CrossOriginRedirect",
            "{target}"
        );
        assert_eq!(entries(&setup.target_dir()), Vec::<String>::new());
    }
    assert!(Setup::requests(&setup.beta).await.is_empty());
    assert!(Setup::requests(&setup.other).await.is_empty());
}

#[tokio::test]
async fn more_than_three_redirects_are_refused() {
    let setup = Setup::new().await;
    setup
        .operation("succeeded", json!([file(NAME, 0, &setup.file_url())]))
        .await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(302).insert_header("location", "/again"))
        .mount(&setup.alpha)
        .await;
    let run = setup.run(&["download", CASE, OP]).await;
    assert_eq!(run.outcome.exit_code, 1);
    assert!(
        run.stderr().contains("redirected more than 3 times"),
        "{}",
        run.stderr()
    );
    assert_eq!(Setup::requests(&setup.alpha).await.len(), 4);
}

/// A server that sends a `Content-Length` of 100, ten bytes, then closes.
async fn truncating_server() -> SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        while let Ok((mut stream, _)) = listener.accept().await {
            let mut buffer = [0u8; 4096];
            let _ = stream.read(&mut buffer).await;
            let _ = stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n0123456789")
                .await;
            let _ = stream.shutdown().await;
        }
    });
    address
}

/// A server that sends a chunked body of 64 KiB with no `Content-Length`.
async fn chunked_server() -> SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        while let Ok((mut stream, _)) = listener.accept().await {
            let mut buffer = [0u8; 4096];
            let _ = stream.read(&mut buffer).await;
            let _ = stream
                .write_all(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n")
                .await;
            for _ in 0..16 {
                let _ = stream.write_all(b"1000\r\n").await;
                let _ = stream.write_all(&[b'x'; 4096]).await;
                let _ = stream.write_all(b"\r\n").await;
            }
            let _ = stream.write_all(b"0\r\n\r\n").await;
            let _ = stream.shutdown().await;
        }
    });
    address
}

#[tokio::test]
async fn a_body_with_no_length_is_stopped_once_it_passes_the_size_graph_gave() {
    let setup = Setup::new().await;
    let address = chunked_server().await;
    let url = format!("http://{ALPHA}:{}/x", address.port());
    setup
        .operation("succeeded", json!([file(NAME, 100, &url)]))
        .await;
    let run = setup
        .run_with(&["download", CASE, OP], |env| {
            env.download_resolve = vec![(ALPHA.to_owned(), address)];
        })
        .await;
    assert_eq!(run.outcome.exit_code, 1);
    assert!(
        run.stderr().contains("passed the 100 bytes Graph gave"),
        "{}",
        run.stderr()
    );
    assert_eq!(entries(&setup.target_dir()), Vec::<String>::new());
}

#[tokio::test]
async fn a_truncated_body_leaves_no_final_file_and_no_temporary_file() {
    let setup = Setup::new().await;
    let address = truncating_server().await;
    let url = format!("http://{ALPHA}:{}/x", address.port());
    setup
        .operation("succeeded", json!([file(NAME, 0, &url)]))
        .await;
    let run = setup
        .run_with(&["download", CASE, OP], |env| {
            env.download_resolve = vec![(ALPHA.to_owned(), address)];
        })
        .await;
    assert_eq!(run.outcome.exit_code, 1);
    assert!(run.stderr().contains("cut off"), "{}", run.stderr());
    assert_eq!(entries(&setup.target_dir()), Vec::<String>::new());
}

#[tokio::test]
async fn a_body_longer_or_shorter_than_the_size_graph_gave_is_refused() {
    let setup = Setup::new().await;
    let body = zip_bytes("sized\n");
    setup.serve(body.clone()).await;
    for size in [5, body.len() as u64 + 10] {
        setup
            .operation("succeeded", json!([file(NAME, size, &setup.file_url())]))
            .await;
        let run = setup.run(&["download", CASE, OP]).await;
        assert_eq!(run.outcome.exit_code, 1, "{size}");
        assert_eq!(entries(&setup.target_dir()), Vec::<String>::new(), "{size}");
    }
    setup
        .operation(
            "succeeded",
            json!([file(NAME, body.len() as u64, &setup.file_url())]),
        )
        .await;
    assert_eq!(
        setup.run(&["download", CASE, OP]).await.outcome.exit_code,
        0
    );
}

#[tokio::test]
async fn an_unknown_size_obeys_the_configured_limit() {
    let setup = Setup::new().await;
    let body = zip_bytes(&"a".repeat(4096));
    setup
        .operation("succeeded", json!([file(NAME, 0, &setup.file_url())]))
        .await;
    setup.serve(body).await;
    std::fs::write(
        setup.harness.config_dir().join("config.json"),
        serde_json::to_vec(&{
            let mut config = setup.harness.config();
            config["download"] = json!({"max_unknown_size": "100B"});
            config
        })
        .unwrap(),
    )
    .unwrap();
    let run = setup.run(&["download", CASE, OP]).await;
    assert_eq!(run.outcome.exit_code, 1);
    assert!(run.stderr().contains("100-byte limit"), "{}", run.stderr());
    assert_eq!(entries(&setup.target_dir()), Vec::<String>::new());
}

#[tokio::test]
async fn a_body_that_is_not_a_zip_is_not_published() {
    let setup = Setup::new().await;
    setup
        .operation("succeeded", json!([file(NAME, 0, &setup.file_url())]))
        .await;
    setup.serve(b"<html>sign in</html>".to_vec()).await;
    let run = setup.run(&["download", CASE, OP]).await;
    assert_eq!(run.outcome.exit_code, 1);
    assert!(run.stderr().contains("not a zip"), "{}", run.stderr());
    // Files are named by position, never by their tenant-written names.
    assert!(
        run.stderr().contains("downloading file 1 of 1"),
        "{}",
        run.stderr()
    );
    assert!(!run.stderr().contains("Orders API"), "{}", run.stderr());
    assert_eq!(entries(&setup.target_dir()), Vec::<String>::new());
}

#[tokio::test]
async fn an_existing_file_needs_overwrite_and_is_refused_before_any_request() {
    let setup = Setup::new().await;
    let body = zip_bytes("fresh\n");
    setup
        .operation("succeeded", json!([file(NAME, 0, &setup.file_url())]))
        .await;
    setup.serve(body.clone()).await;
    std::fs::create_dir_all(setup.target_dir()).unwrap();
    let target = setup.target_dir().join(NAME);
    std::fs::write(&target, b"someone else's file").unwrap();
    let run = setup.run(&["--json", "download", CASE, OP]).await;
    assert_eq!(run.outcome.exit_code, 1);
    assert_eq!(run.json()["error"]["code"], "TargetExists");
    assert!(Setup::requests(&setup.alpha).await.is_empty());
    assert!(setup
        .harness
        .identity
        .received_requests()
        .await
        .unwrap()
        .is_empty());
    assert_eq!(std::fs::read(&target).unwrap(), b"someone else's file");
    let run = setup.run(&["download", CASE, OP, "--overwrite"]).await;
    assert_eq!(run.outcome.exit_code, 0, "{}", run.stderr());
    assert_eq!(std::fs::read(&target).unwrap(), body);
}

#[cfg(unix)]
#[tokio::test]
async fn a_linked_target_is_refused_even_with_overwrite() {
    let setup = Setup::new().await;
    setup
        .operation("succeeded", json!([file(NAME, 0, &setup.file_url())]))
        .await;
    setup.serve(zip_bytes("x\n")).await;
    std::fs::create_dir_all(setup.target_dir()).unwrap();
    let elsewhere = setup.harness.root.path().join("elsewhere.zip");
    std::fs::write(&elsewhere, b"keep").unwrap();
    std::os::unix::fs::symlink(&elsewhere, setup.target_dir().join(NAME)).unwrap();
    for args in [
        vec!["download", CASE, OP],
        vec!["download", CASE, OP, "--overwrite"],
    ] {
        let run = setup.run(&args).await;
        assert_eq!(run.outcome.exit_code, 1);
        assert!(run.stderr().contains("is a link"), "{}", run.stderr());
    }
    assert!(Setup::requests(&setup.alpha).await.is_empty());
    assert_eq!(std::fs::read(&elsewhere).unwrap(), b"keep");
}

#[tokio::test]
async fn a_file_another_writer_creates_meanwhile_is_kept() {
    let setup = Setup::new().await;
    setup
        .operation("succeeded", json!([file(NAME, 0, &setup.file_url())]))
        .await;
    setup.serve(zip_bytes("ours\n")).await;
    let run = setup
        .run_with(&["--json", "download", CASE, OP], |env| {
            env.download_faults.before_publish = Some(Arc::new(|target: &Path| {
                std::fs::write(target, b"theirs").unwrap();
            }));
        })
        .await;
    assert_eq!(run.outcome.exit_code, 1);
    assert_eq!(run.json()["error"]["code"], "TargetAppeared");
    assert_eq!(
        std::fs::read(setup.target_dir().join(NAME)).unwrap(),
        b"theirs"
    );
    assert_eq!(entries(&setup.target_dir()), [NAME]);
}

#[tokio::test]
async fn a_failed_manifest_write_keeps_the_file_and_the_next_run_recovers_it() {
    let setup = Setup::new().await;
    let body = zip_bytes("kept\n");
    setup
        .operation("succeeded", json!([file(NAME, 0, &setup.file_url())]))
        .await;
    setup.serve(body.clone()).await;
    let run = setup
        .run_with(&["--json", "download", CASE, OP], |env| {
            env.download_faults.manifest_write = true;
        })
        .await;
    assert_eq!(run.outcome.exit_code, 1);
    assert_eq!(run.json()["error"]["code"], "ManifestWriteFailed");
    assert_eq!(entries(&setup.target_dir()), [NAME]);
    let again = setup.run(&["--json", "download", CASE, OP]).await;
    assert_eq!(again.outcome.exit_code, 0, "{}", again.stderr());
    assert_eq!(again.json()["results"][0]["status"], "recovered");
    assert_eq!(Setup::requests(&setup.alpha).await.len(), 1);
    let recorded = manifest(&setup.target_dir());
    assert_eq!(recorded["files"][0]["recovered"], true);
    assert_eq!(recorded["files"][0]["sha256"], sha256(&body));
}

#[tokio::test]
async fn a_file_with_no_usable_url_is_left_out_and_the_others_are_downloaded() {
    let setup = Setup::new().await;
    let body = zip_bytes("good\n");
    setup.serve(body.clone()).await;
    let graph_url = format!("{}/v1.0/steal", setup.harness.graph.uri());
    setup
        .operation(
            "succeeded",
            json!([
                file(NAME, 0, &setup.file_url()),
                file("Foreign.zip", 0, &graph_url),
                {"fileName": "Missing.zip", "size": 0},
                {"size": 0, "downloadUrl": setup.file_url()},
            ]),
        )
        .await;
    let run = setup.run(&["--json", "download", CASE, OP]).await;
    assert_eq!(run.outcome.exit_code, 4, "{}", run.stderr());
    let document = run.json();
    assert_eq!(document["count"], 1);
    assert_eq!(document["results"][0]["fileName"], NAME);
    assert_eq!(document["outcome"]["code"], "Incomplete");
    let reasons = document["outcome"]["reasons"].as_array().unwrap();
    assert_eq!(reasons.len(), 3);
    assert!(reasons
        .iter()
        .all(|reason| reason["code"] == "FileNotDownloadable"));
    assert!(reasons[0]["message"]
        .as_str()
        .unwrap()
        .contains("not a Purview download host"));
    // The foreign URL got no request, and no token.
    assert!(Setup::requests(&setup.harness.graph)
        .await
        .iter()
        .all(|request| request.url.path() != "/v1.0/steal"));
    assert_eq!(entries(&setup.target_dir()), [NAME, "manifest.json"]);
}

#[tokio::test]
async fn an_operation_that_did_not_succeed_downloads_its_files_and_exits_4() {
    let setup = Setup::new().await;
    setup.serve(zip_bytes("partial\n")).await;
    setup
        .operation(
            "partiallySucceeded",
            json!([file(NAME, 0, &setup.file_url())]),
        )
        .await;
    let run = setup
        .run(&["--json", "--results-only", "download", CASE, OP])
        .await;
    assert_eq!(run.outcome.exit_code, 4);
    let document = run.json();
    assert_eq!(document["count"], 1);
    assert_eq!(
        document["outcome"]["reasons"][0]["code"],
        "OperationPartiallySucceeded"
    );
}

#[tokio::test]
async fn a_running_operation_is_refused_before_any_download() {
    let setup = Setup::new().await;
    setup.serve(zip_bytes("early\n")).await;
    setup
        .operation("running", json!([file(NAME, 0, &setup.file_url())]))
        .await;
    let run = setup.run(&["download", CASE, OP]).await;
    assert_eq!(run.outcome.exit_code, 1);
    assert!(run.stderr().contains("is running"), "{}", run.stderr());
    assert!(run.stderr().contains("--wait"), "{}", run.stderr());
    assert!(Setup::requests(&setup.alpha).await.is_empty());
}

#[tokio::test]
async fn file_picks_one_file_by_its_exact_name() {
    let setup = Setup::new().await;
    setup.serve(zip_bytes("one\n")).await;
    setup
        .operation(
            "succeeded",
            json!([
                file(NAME, 0, &setup.file_url()),
                file("Other.zip", 0, &setup.url(&setup.alpha, ALPHA, "/other")),
            ]),
        )
        .await;
    let run = setup.run(&["download", CASE, OP, "--file", NAME]).await;
    assert_eq!(run.outcome.exit_code, 0, "{}", run.stderr());
    assert_eq!(entries(&setup.target_dir()), [NAME, "manifest.json"]);
    let missing = setup
        .run(&["download", CASE, OP, "--file", "Secret project.zip"])
        .await;
    assert_eq!(missing.outcome.exit_code, 1);
    assert!(
        !missing.stderr().contains("Secret project"),
        "{}",
        missing.stderr()
    );
}

#[tokio::test]
async fn out_names_the_directory_and_a_blank_one_is_refused_before_sign_in() {
    let setup = Setup::new().await;
    let body = zip_bytes("out\n");
    setup.serve(body.clone()).await;
    setup
        .operation("succeeded", json!([file(NAME, 0, &setup.file_url())]))
        .await;
    let out = setup.harness.root.path().join("evidence");
    let run = setup
        .run(&["download", CASE, OP, "--out", out.to_str().unwrap()])
        .await;
    assert_eq!(run.outcome.exit_code, 0, "{}", run.stderr());
    assert_eq!(std::fs::read(out.join(NAME)).unwrap(), body);
    assert!(!setup.target_dir().exists());
    setup.harness.graph.reset().await;
    let blank = setup.run(&["download", CASE, OP, "--out", " "]).await;
    assert_eq!(blank.outcome.exit_code, 1);
    let bad_op = setup.run(&["download", CASE, "not-an-op"]).await;
    assert_eq!(bad_op.outcome.exit_code, 1);
    assert!(Setup::requests(&setup.harness.graph).await.is_empty());
}

#[tokio::test]
async fn names_that_collide_on_a_case_insensitive_file_system_both_get_a_suffix() {
    let setup = Setup::new().await;
    setup.serve(zip_bytes("a\n")).await;
    Mock::given(method("GET"))
        .and(path("/second"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(zip_bytes("b\n")))
        .mount(&setup.alpha)
        .await;
    setup
        .operation(
            "succeeded",
            json!([
                file("Report:1.zip", 0, &setup.file_url()),
                file(
                    "report?1.zip",
                    0,
                    &setup.url(&setup.alpha, ALPHA, "/second")
                ),
            ]),
        )
        .await;
    let run = setup.run(&["--json", "download", CASE, OP]).await;
    assert_eq!(run.outcome.exit_code, 0, "{}", run.stderr());
    let names = entries(&setup.target_dir());
    assert_eq!(names.len(), 3, "{names:?}");
    assert!(
        names.iter().filter(|name| name.contains('~')).count() == 2,
        "{names:?}"
    );
    let recorded = manifest(&setup.target_dir());
    let servers: Vec<&str> = recorded["files"]
        .as_array()
        .unwrap()
        .iter()
        .map(|entry| entry["serverFileName"].as_str().unwrap())
        .collect();
    assert_eq!(servers, ["Report:1.zip", "report?1.zip"]);
}

#[tokio::test]
async fn a_directory_another_download_holds_is_refused_after_the_wait() {
    let setup = Setup::new().await;
    setup.serve(zip_bytes("x\n")).await;
    setup
        .operation("succeeded", json!([file(NAME, 0, &setup.file_url())]))
        .await;
    std::fs::create_dir_all(setup.target_dir()).unwrap();
    let clock = setup.harness.clock.clone();
    let held = ms_purview_cli::download::DirLock::acquire(&setup.target_dir(), clock.as_ref())
        .await
        .unwrap();
    let run = setup.run(&["download", CASE, OP]).await;
    assert_eq!(run.outcome.exit_code, 1);
    assert!(run.stderr().contains("busy"), "{}", run.stderr());
    assert!(Setup::requests(&setup.alpha).await.is_empty());
    drop(held);
    assert_eq!(
        setup.run(&["download", CASE, OP]).await.outcome.exit_code,
        0
    );
}

#[tokio::test]
async fn another_operation_s_file_under_an_equivalent_name_is_never_recovered() {
    const OTHER: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaa0002";
    let setup = Setup::new().await;
    setup.serve(zip_bytes("first\n")).await;
    let out = setup.harness.root.path().join("shared");
    let out_text = out.to_str().unwrap().to_owned();
    setup
        .operation(
            "succeeded",
            json!([file("Report.zip", 0, &setup.file_url())]),
        )
        .await;
    setup
        .add_operation(
            OTHER,
            "succeeded",
            json!([file("report.zip", 0, &setup.file_url())]),
        )
        .await;
    let first = setup.run(&["download", CASE, OP, "--out", &out_text]).await;
    assert_eq!(first.outcome.exit_code, 0, "{}", first.stderr());
    let insensitive = out.join("REPORT.ZIP").exists();
    let second = setup
        .run(&["--json", "download", CASE, OTHER, "--out", &out_text])
        .await;
    if insensitive {
        assert_eq!(second.outcome.exit_code, 1);
        assert_eq!(second.json()["error"]["code"], "TargetExists");
    } else {
        assert_eq!(second.outcome.exit_code, 0);
        assert_eq!(second.json()["results"][0]["status"], "downloaded");
    }
}

#[tokio::test]
async fn ctrl_c_keeps_the_files_published_and_leaves_no_temporary_file() {
    let setup = Setup::new().await;
    setup.serve(zip_bytes("first\n")).await;
    Mock::given(method("GET"))
        .and(path("/second"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(zip_bytes("second\n")))
        .mount(&setup.alpha)
        .await;
    setup
        .operation(
            "succeeded",
            json!([
                file(NAME, 0, &setup.file_url()),
                file("Second.zip", 0, &setup.url(&setup.alpha, ALPHA, "/second")),
            ]),
        )
        .await;
    let interrupt = Arc::new(ms_purview_cli::env::ManualInterrupt::default());
    let fired = interrupt.clone();
    let run = setup
        .run_with(&["--json", "download", CASE, OP], |env| {
            env.interrupt = interrupt.clone();
            // Ctrl-C arrives while the first file is being published.
            env.download_faults.before_publish = Some(Arc::new(move |_: &Path| fired.fire()));
        })
        .await;
    assert_eq!(run.outcome.exit_code, 130, "{}", run.stdout());
    let document = run.json();
    assert_eq!(document["error"]["code"], "Interrupted");
    assert_eq!(document["count"], 1);
    assert_eq!(document["results"][0]["fileName"], NAME);
    assert_eq!(entries(&setup.target_dir()), [NAME, "manifest.json"]);
    assert!(Setup::requests(&setup.alpha)
        .await
        .iter()
        .all(|request| request.url.path() != "/second"));
}

#[tokio::test]
async fn a_known_size_over_the_limit_is_refused_before_any_request() {
    let setup = Setup::new().await;
    setup.serve(zip_bytes("x\n")).await;
    setup.configure_download(json!({"max_size": "100B"}));
    setup
        .operation("succeeded", json!([file(NAME, 5000, &setup.file_url())]))
        .await;
    let run = setup.run(&["download", CASE, OP]).await;
    assert_eq!(run.outcome.exit_code, 1);
    assert!(run.stderr().contains("100-byte limit"), "{}", run.stderr());
    assert!(Setup::requests(&setup.alpha).await.is_empty());
    assert!(setup
        .harness
        .identity
        .received_requests()
        .await
        .unwrap()
        .is_empty());
}

#[tokio::test]
async fn file_gives_a_colliding_file_the_name_a_full_download_does_and_is_not_trimmed() {
    let setup = Setup::new().await;
    setup.serve(zip_bytes("a\n")).await;
    setup
        .operation(
            "succeeded",
            json!([
                file("Report:1.zip", 0, &setup.file_url()),
                file(
                    "report?1.zip",
                    0,
                    &setup.url(&setup.alpha, ALPHA, "/second")
                ),
                file("lead.zip", 0, &setup.url(&setup.alpha, ALPHA, "/third")),
            ]),
        )
        .await;
    let run = setup
        .run(&["--json", "download", CASE, OP, "--file", "Report:1.zip"])
        .await;
    assert_eq!(run.outcome.exit_code, 0, "{}", run.stdout());
    assert!(run.json()["results"][0]["path"]
        .as_str()
        .unwrap()
        .contains('~'));
    let spaced = setup
        .run(&["download", CASE, OP, "--file", " lead.zip"])
        .await;
    assert_eq!(spaced.outcome.exit_code, 1);
    assert!(
        spaced.stderr().contains("no file with the name"),
        "{}",
        spaced.stderr()
    );
}

#[tokio::test]
async fn an_overwrite_whose_manifest_write_fails_replaces_nothing() {
    let setup = Setup::new().await;
    let first = zip_bytes("v1\n");
    setup.serve(first.clone()).await;
    setup
        .operation("succeeded", json!([file(NAME, 0, &setup.file_url())]))
        .await;
    assert_eq!(
        setup.run(&["download", CASE, OP]).await.outcome.exit_code,
        0
    );
    setup.alpha.reset().await;
    setup.serve(zip_bytes("v2, a different body\n")).await;
    let failed = setup
        .run_with(&["--json", "download", CASE, OP, "--overwrite"], |env| {
            env.download_faults.manifest_write = true;
        })
        .await;
    assert_eq!(failed.outcome.exit_code, 1);
    assert!(failed.json()["error"]["message"]
        .as_str()
        .unwrap()
        .contains("nothing was replaced"));
    assert_eq!(std::fs::read(setup.target_dir().join(NAME)).unwrap(), first);
    assert_eq!(entries(&setup.target_dir()), [NAME, "manifest.json"]);
    let again = setup.run(&["--json", "download", CASE, OP]).await;
    assert_eq!(again.outcome.exit_code, 0, "{}", again.stdout());
    assert_eq!(again.json()["results"][0]["status"], "alreadyDownloaded");
    assert_eq!(again.json()["results"][0]["sha256"], sha256(&first));
}

#[tokio::test]
async fn a_failed_overwrite_never_gives_the_old_file_to_the_new_operation() {
    const OTHER: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaa0002";
    let setup = Setup::new().await;
    setup.serve(zip_bytes("operation one\n")).await;
    let out = setup.harness.root.path().join("shared");
    let out_text = out.to_str().unwrap().to_owned();
    let failing = setup.url(&setup.alpha, ALPHA, "/fails");
    setup
        .operation("succeeded", json!([file(NAME, 0, &setup.file_url())]))
        .await;
    setup
        .add_operation(OTHER, "succeeded", json!([file(NAME, 0, &failing)]))
        .await;
    Mock::given(method("GET"))
        .and(path("/fails"))
        .respond_with(ResponseTemplate::new(500))
        .mount(&setup.alpha)
        .await;
    let first = setup.run(&["download", CASE, OP, "--out", &out_text]).await;
    assert_eq!(first.outcome.exit_code, 0, "{}", first.stderr());
    let overwrite = setup
        .run(&["download", CASE, OTHER, "--out", &out_text, "--overwrite"])
        .await;
    assert_eq!(overwrite.outcome.exit_code, 1);
    let retry = setup
        .run(&["--json", "download", CASE, OTHER, "--out", &out_text])
        .await;
    assert_eq!(retry.outcome.exit_code, 1);
    assert_eq!(retry.json()["error"]["code"], "TargetExists");
    let recorded = manifest(&out);
    assert_eq!(recorded["files"].as_array().unwrap().len(), 1);
    assert_eq!(recorded["files"][0]["operationId"], OP);
}

#[tokio::test]
async fn an_overwrite_under_an_equivalent_name_takes_over_the_entry() {
    const OTHER: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaa0002";
    let setup = Setup::new().await;
    setup.serve(zip_bytes("one\n")).await;
    Mock::given(method("GET"))
        .and(path("/second"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(zip_bytes("two\n")))
        .mount(&setup.alpha)
        .await;
    let out = setup.harness.root.path().join("shared");
    let out_text = out.to_str().unwrap().to_owned();
    setup
        .operation(
            "succeeded",
            json!([file("Report.zip", 0, &setup.file_url())]),
        )
        .await;
    let second = setup.url(&setup.alpha, ALPHA, "/second");
    setup
        .add_operation(OTHER, "succeeded", json!([file("report.zip", 0, &second)]))
        .await;
    let first = setup.run(&["download", CASE, OP, "--out", &out_text]).await;
    assert_eq!(first.outcome.exit_code, 0);
    let insensitive = out.join("REPORT.ZIP").exists();
    let replaced = setup
        .run(&["download", CASE, OTHER, "--out", &out_text, "--overwrite"])
        .await;
    assert_eq!(replaced.outcome.exit_code, 0, "{}", replaced.stderr());
    let again = setup
        .run(&["--json", "download", CASE, OTHER, "--out", &out_text])
        .await;
    assert_eq!(again.outcome.exit_code, 0, "{}", again.stdout());
    assert_eq!(again.json()["results"][0]["status"], "alreadyDownloaded");
    let left = manifest(&out)["files"].as_array().unwrap().len();
    assert_eq!(left, if insensitive { 1 } else { 2 });
}

#[tokio::test]
async fn an_invalid_size_is_warned_about_and_read_as_unknown() {
    let setup = Setup::new().await;
    setup.serve(zip_bytes("x\n")).await;
    setup
        .operation(
            "succeeded",
            json!([{"fileName": NAME, "size": -5, "downloadUrl": setup.file_url()}]),
        )
        .await;
    let run = setup.run(&["download", CASE, OP]).await;
    assert_eq!(run.outcome.exit_code, 0, "{}", run.stderr());
    assert!(run.stderr().contains("not counts"), "{}", run.stderr());
}

#[tokio::test]
async fn without_hard_links_overwrite_publishes_by_renaming() {
    let setup = Setup::new().await;
    setup.serve(zip_bytes("x\n")).await;
    setup
        .operation("succeeded", json!([file(NAME, 0, &setup.file_url())]))
        .await;
    let no_links = |env: &mut Env| env.download_faults.no_hard_links = true;
    let refused = setup
        .run_with(&["--json", "download", CASE, OP], no_links)
        .await;
    assert_eq!(refused.outcome.exit_code, 1);
    assert_eq!(refused.json()["error"]["code"], "PublishUnsupported");
    assert_eq!(entries(&setup.target_dir()), Vec::<String>::new());
    let renamed = setup
        .run_with(&["download", CASE, OP, "--overwrite"], no_links)
        .await;
    assert_eq!(renamed.outcome.exit_code, 0, "{}", renamed.stderr());
    assert_eq!(entries(&setup.target_dir()), [NAME, "manifest.json"]);
}

#[tokio::test]
async fn a_file_name_that_holds_a_web_address_is_left_out() {
    let setup = Setup::new().await;
    setup.serve(zip_bytes("x\n")).await;
    let named = [
        "report ",
        "https",
        "://h.example/f?sig=canary-sig-0002",
        ".zip",
    ]
    .concat();
    let plain = ["report ", "https", "://h.example/f.zip"].concat();
    let url = setup.file_url();
    setup
        .operation(
            "succeeded",
            json!([file(&named, 0, &url), file(&plain, 0, &url)]),
        )
        .await;
    let run = setup.run(&["--json", "download", CASE, OP]).await;
    assert_eq!(run.outcome.exit_code, 4);
    let reasons = run.json()["outcome"]["reasons"].clone();
    let reasons = reasons.as_array().unwrap();
    assert_eq!(reasons.len(), 2, "{reasons:?}");
    assert!(reasons
        .iter()
        .all(|reason| reason["code"] == "FileNotDownloadable"));
    setup.harness.assert_absent(&run, &["canary-sig-0002"]);
}

#[cfg(unix)]
#[tokio::test]
async fn a_link_inside_the_managed_data_path_is_refused() {
    let setup = Setup::new().await;
    setup.serve(zip_bytes("x\n")).await;
    setup
        .operation("succeeded", json!([file(NAME, 0, &setup.file_url())]))
        .await;
    let elsewhere = setup.harness.root.path().join("elsewhere");
    std::fs::create_dir_all(&elsewhere).unwrap();
    std::fs::create_dir_all(setup.data_root()).unwrap();
    std::os::unix::fs::symlink(&elsewhere, setup.data_root().join("cases")).unwrap();
    let run = setup.run(&["download", CASE, OP]).await;
    assert_eq!(run.outcome.exit_code, 1);
    assert!(run.stderr().contains("is a link"), "{}", run.stderr());
    assert!(entries(&elsewhere).is_empty());
    assert!(Setup::requests(&setup.alpha).await.is_empty());
}

/// A server that sends a `Content-Length` of 100 and ten bytes, then holds
/// the connection open without sending more.
async fn stalling_server() -> SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buffer = [0u8; 4096];
                let _ = stream.read(&mut buffer).await;
                let _ = stream
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n0123456789")
                    .await;
                tokio::time::sleep(std::time::Duration::from_secs(30)).await;
            });
        }
    });
    address
}

#[tokio::test]
async fn a_stalled_download_ends_at_the_idle_timeout_and_leaves_nothing() {
    let setup = Setup::new().await;
    let address = stalling_server().await;
    let url = format!("http://{ALPHA}:{}/x", address.port());
    setup
        .operation("succeeded", json!([file(NAME, 0, &url)]))
        .await;
    let run = setup
        .run_with(&["download", CASE, OP], |env| {
            env.download_resolve = vec![(ALPHA.to_owned(), address)];
            env.download_idle_timeout = std::time::Duration::from_secs(1);
        })
        .await;
    assert_eq!(run.outcome.exit_code, 1);
    assert!(
        run.stderr().contains("no data arrived for 1 seconds"),
        "{}",
        run.stderr()
    );
    assert_eq!(entries(&setup.target_dir()), Vec::<String>::new());
}

#[tokio::test]
async fn ctrl_c_while_a_file_streams_removes_its_temporary_file() {
    let setup = Setup::new().await;
    let address = stalling_server().await;
    let url = format!("http://{ALPHA}:{}/x", address.port());
    setup
        .operation("succeeded", json!([file(NAME, 0, &url)]))
        .await;
    let interrupt = Arc::new(ms_purview_cli::env::ManualInterrupt::default());
    let fired = interrupt.clone();
    tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        fired.fire();
    });
    let run = setup
        .run_with(&["--json", "download", CASE, OP], |env| {
            env.download_resolve = vec![(ALPHA.to_owned(), address)];
            env.interrupt = interrupt.clone();
        })
        .await;
    assert_eq!(run.outcome.exit_code, 130, "{}", run.stdout());
    assert_eq!(run.json()["error"]["code"], "Interrupted");
    assert_eq!(run.json()["count"], 0);
    assert_eq!(entries(&setup.target_dir()), Vec::<String>::new());
}

#[tokio::test]
async fn a_recorded_file_that_changed_is_refused_before_any_request() {
    let setup = Setup::new().await;
    setup.serve(zip_bytes("recorded\n")).await;
    setup
        .operation("succeeded", json!([file(NAME, 0, &setup.file_url())]))
        .await;
    assert_eq!(
        setup.run(&["download", CASE, OP]).await.outcome.exit_code,
        0
    );
    let target = setup.target_dir().join(NAME);
    std::fs::write(&target, zip_bytes("tampered\n")).unwrap();
    let run = setup.run(&["--json", "download", CASE, OP]).await;
    assert_eq!(run.outcome.exit_code, 1);
    assert_eq!(run.json()["error"]["code"], "TargetExists");
    assert_eq!(Setup::requests(&setup.alpha).await.len(), 1);
}

#[tokio::test]
async fn an_unrecorded_file_that_is_not_a_zip_is_not_recovered() {
    let setup = Setup::new().await;
    setup.serve(zip_bytes("x\n")).await;
    setup
        .operation("succeeded", json!([file(NAME, 0, &setup.file_url())]))
        .await;
    std::fs::create_dir_all(setup.target_dir()).unwrap();
    std::fs::write(setup.target_dir().join(NAME), b"not a zip").unwrap();
    let run = setup.run(&["--json", "download", CASE, OP]).await;
    assert_eq!(run.outcome.exit_code, 1);
    assert_eq!(run.json()["error"]["code"], "TargetExists");
    assert!(Setup::requests(&setup.alpha).await.is_empty());
}

#[tokio::test]
async fn a_403_is_download_refused_with_its_status() {
    let setup = Setup::new().await;
    setup
        .operation("succeeded", json!([file(NAME, 0, &setup.file_url())]))
        .await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(403))
        .mount(&setup.alpha)
        .await;
    let run = setup.run(&["--json", "download", CASE, OP]).await;
    assert_eq!(run.outcome.exit_code, 1);
    assert_eq!(run.json()["error"]["code"], "DownloadRefused");
    assert_eq!(run.json()["error"]["status"], 403);
}

#[tokio::test]
async fn defaults_data_dir_replaces_the_data_root() {
    let setup = Setup::new().await;
    setup.serve(zip_bytes("x\n")).await;
    setup
        .operation("succeeded", json!([file(NAME, 0, &setup.file_url())]))
        .await;
    let configured = setup.harness.root.path().join("configured");
    let mut config = setup.harness.config();
    config["defaults"] = json!({"data_dir": configured.to_str().unwrap()});
    std::fs::write(
        setup.harness.config_dir().join("config.json"),
        serde_json::to_vec(&config).unwrap(),
    )
    .unwrap();
    let run = setup.run(&["download", CASE, OP]).await;
    assert_eq!(run.outcome.exit_code, 0, "{}", run.stderr());
    assert!(configured
        .join("cases")
        .join(CASE)
        .join(OP)
        .join(NAME)
        .is_file());
    assert!(!setup.target_dir().exists());
}

#[tokio::test]
async fn wrap_untrusted_wraps_the_server_file_name() {
    let setup = Setup::new().await;
    setup.serve(zip_bytes("x\n")).await;
    setup
        .operation("succeeded", json!([file(NAME, 0, &setup.file_url())]))
        .await;
    let run = setup
        .run(&["--json", "--wrap-untrusted", "download", CASE, OP])
        .await;
    assert_eq!(run.outcome.exit_code, 0, "{}", run.stdout());
    let name = run.json()["results"][0]["fileName"]
        .as_str()
        .unwrap()
        .to_owned();
    assert!(name.starts_with("[UNTRUSTED:"), "{name}");
    assert!(name.contains(NAME), "{name}");
}

#[tokio::test]
async fn an_expired_download_token_is_refreshed_and_no_token_leaks_into_trace_or_output() {
    let setup = Setup::new().await;
    setup.serve(zip_bytes("x\n")).await;
    setup
        .operation("succeeded", json!([file(NAME, 0, &setup.file_url())]))
        .await;
    // The download token (valid for 3599 seconds) is past its 5-minute
    // margin; the Graph token (4271 seconds) is not.
    setup
        .harness
        .clock
        .advance(std::time::Duration::from_secs(3600));
    Mock::given(method("POST"))
        .and(path(token_path("token")))
        .and(Form::new(&[
            ("grant_type", "refresh_token"),
            ("refresh_token", "canary-refresh-0002"),
        ]))
        .respond_with(json_response(
            200,
            token(
                "canary-download-access-0002",
                "canary-refresh-0004",
                "b26e684c-5068-4120-a679-64a5d2c909d9/eDiscovery.Download.Read",
            ),
        ))
        .expect(1)
        .mount(&setup.harness.identity)
        .await;
    let trace = setup.harness.root.path().join("trace");
    let run = setup
        .run(&[
            "--verbose",
            "--trace",
            trace.to_str().unwrap(),
            "download",
            CASE,
            OP,
        ])
        .await;
    assert_eq!(run.outcome.exit_code, 0, "{}", run.stderr());
    let downloads = Setup::requests(&setup.alpha).await;
    assert_eq!(
        header(&downloads[0], "authorization").as_deref(),
        Some("Bearer canary-download-access-0002")
    );
    setup.harness.assert_no_canaries(&run);
}

#[tokio::test]
async fn ctrl_c_during_the_zip_check_publishes_nothing() {
    let setup = Setup::new().await;
    let first = zip_bytes("kept\n");
    setup.serve(first.clone()).await;
    setup
        .operation("succeeded", json!([file(NAME, 0, &setup.file_url())]))
        .await;
    assert_eq!(
        setup.run(&["download", CASE, OP]).await.outcome.exit_code,
        0
    );
    setup.alpha.reset().await;
    setup.serve(zip_bytes("replacement\n")).await;
    let interrupt = Arc::new(ms_purview_cli::env::ManualInterrupt::default());
    let fired = interrupt.clone();
    let run = setup
        .run_with(&["--json", "download", CASE, OP, "--overwrite"], |env| {
            env.interrupt = interrupt.clone();
            env.download_faults.before_zip_check = Some(Arc::new(move |_: &Path| fired.fire()));
        })
        .await;
    assert_eq!(run.outcome.exit_code, 130, "{}", run.stdout());
    assert_eq!(std::fs::read(setup.target_dir().join(NAME)).unwrap(), first);
    assert_eq!(entries(&setup.target_dir()), [NAME, "manifest.json"]);
    assert_eq!(
        manifest(&setup.target_dir())["files"][0]["sha256"],
        sha256(&first)
    );
}
