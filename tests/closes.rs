//! In-process flows of `case close` through `cli::execute_with`
//! (`docs/SPEC.md` section 8.5, flow 8), against a wiremock Graph and
//! identity platform that record every request, an in-memory credential
//! store and a manual clock.

mod support;

use std::sync::Arc;
use std::time::Duration;

use ms_purview_cli::env::ScriptedInput;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use support::*;
use wiremock::matchers::{method, path, query_param};
use wiremock::{Mock, Request, ResponseTemplate};

const CASES: &str = "/v1.0/security/cases/ediscoveryCases";
const CASE: &str = "00000000-0000-4000-8000-000000000031";
const CASE_NAME: &str = "Records research - Orders review 2026-01";
const MARKED: &str = "Requested by alex.wilber@contoso.example. Tenant-wide mailbox search \
                      with no custodians or holds. [created-by:purview-cli]";

fn case_path() -> String {
    format!("{CASES}/{CASE}")
}

fn close_path() -> String {
    format!("{CASES}/{CASE}/close")
}

fn hold_path(name: &str) -> String {
    format!("{CASES}/{CASE}/{name}")
}

const HOLD_READS: [&str; 3] = ["custodians", "noncustodialDataSources", "legalHolds"];

fn case(status: &str, description: &str) -> Value {
    json!({
        "id": CASE,
        "displayName": CASE_NAME,
        "description": description,
        "status": status,
        "createdDateTime": "2026-01-05T09:00:00Z",
    })
}

fn page(items: Vec<Value>) -> Value {
    json!({ "value": items })
}

async fn signed_in() -> Harness {
    let harness = Harness::new().await;
    sign_in_alex(&harness).await;
    harness
}

/// The case read answers each of `answers` once, in order, and the last
/// one from then on.
async fn mount_case(harness: &Harness, answers: &[Value]) {
    let last = answers.len() - 1;
    for (at, answer) in answers.iter().enumerate() {
        let mock = Mock::given(method("GET"))
            .and(path(case_path()))
            .respond_with(json_response(200, answer.clone()))
            .with_priority(u8::try_from(at + 1).unwrap());
        let mock = if at == last {
            mock
        } else {
            mock.up_to_n_times(1)
        };
        mock.mount(&harness.graph).await;
    }
}

/// Every hold read answers an empty list, except those in `listed`.
async fn mount_holds(harness: &Harness, listed: &[(&str, Value)]) {
    for name in HOLD_READS {
        let body = listed
            .iter()
            .find(|(listed, _)| *listed == name)
            .map_or_else(|| page(vec![]), |(_, body)| body.clone());
        Mock::given(method("GET"))
            .and(path(hold_path(name)))
            .respond_with(json_response(200, body))
            .with_priority(5)
            .mount(&harness.graph)
            .await;
    }
}

async fn mount_close(harness: &Harness, response: ResponseTemplate) {
    Mock::given(method("POST"))
        .and(path(close_path()))
        .respond_with(response)
        .mount(&harness.graph)
        .await;
}

/// A signed-in harness with an active, marked case that holds nothing,
/// read as `after` once the close is sent, and a close that answers 204.
async fn ready(after: &[Value]) -> Harness {
    let harness = signed_in().await;
    let mut answers = vec![case("active", MARKED), case("active", MARKED)];
    answers.extend_from_slice(after);
    mount_case(&harness, &answers).await;
    mount_holds(&harness, &[]).await;
    mount_close(&harness, ResponseTemplate::new(204)).await;
    harness
}

async fn graph_requests(harness: &Harness) -> Vec<Request> {
    harness
        .graph
        .received_requests()
        .await
        .expect("the mock Graph records requests")
}

async fn writes(harness: &Harness) -> Vec<Request> {
    graph_requests(harness)
        .await
        .into_iter()
        .filter(|request| request.method.as_str() != "GET")
        .collect()
}

fn close(extra: &[&'static str]) -> Vec<&'static str> {
    let mut args = vec!["case", "close", CASE];
    args.extend_from_slice(extra);
    args
}

fn sha256_hex(text: &str) -> String {
    Sha256::digest(text.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[tokio::test]
async fn case_close_with_yes_sends_one_post_with_no_body() {
    let harness = ready(&[case("closed", MARKED)]).await;
    let run = harness.run(&close(&["--json", "--yes"])).await;
    assert_eq!(run.outcome.exit_code, 0, "{}", run.stderr());
    let posts = writes(&harness).await;
    assert_eq!(posts.len(), 1);
    assert_eq!(posts[0].url.path(), close_path());
    assert!(posts[0].body.is_empty());
    assert!(posts[0].headers.get("content-type").is_none());
    // Graph answers a POST that does not say its length with HTTP 411
    // (Observed).
    assert_eq!(
        posts[0]
            .headers
            .get("content-length")
            .map(|value| value.to_str().unwrap()),
        Some("0")
    );
    let results = &run.json()["results"];
    assert_eq!(results["applied"], true);
    assert_eq!(results["plan"]["command"], "case close");
    assert_eq!(results["plan"]["body"], Value::Null);
    assert_eq!(
        results["plan"]["digest"],
        sha256_hex(&format!(
            "POST\n/security/cases/ediscoveryCases/{CASE}/close\n"
        ))
    );
    let preflight = results["plan"]["preflight"].to_string();
    for name in HOLD_READS {
        assert!(preflight.contains(&format!("{name}: 0")), "{preflight}");
    }
    assert_eq!(results["result"]["status"], "closed");
    // Each hold read in preflight and again after approval, and the case
    // before, after approval and after the close.
    let gets: Vec<String> = graph_requests(&harness)
        .await
        .iter()
        .filter(|request| request.method.as_str() == "GET")
        .map(|request| request.url.path().to_owned())
        .collect();
    for name in HOLD_READS {
        assert_eq!(
            gets.iter().filter(|got| **got == hold_path(name)).count(),
            2,
            "{name}: {gets:?}"
        );
    }
    assert_eq!(gets.iter().filter(|got| **got == case_path()).count(), 3);
}

#[tokio::test]
async fn a_dry_run_reads_the_holds_and_sends_nothing() {
    let harness = ready(&[]).await;
    let run = harness.run(&close(&["--json", "--dry-run"])).await;
    assert_eq!(run.outcome.exit_code, 0, "{}", run.stderr());
    assert_eq!(run.json()["results"]["applied"], false);
    assert!(writes(&harness).await.is_empty());
    let reads = graph_requests(&harness).await;
    for name in HOLD_READS {
        assert!(reads
            .iter()
            .any(|request| request.url.path() == hold_path(name)));
    }
}

#[tokio::test]
async fn holds_refuse_the_close_with_counts_and_no_entry() {
    for name in HOLD_READS {
        let harness = signed_in().await;
        mount_case(&harness, &[case("active", MARKED)]).await;
        let entry = json!({"id": "00000000-0000-4000-8000-000000000071", "displayName": "Kim Example hold"});
        mount_holds(&harness, &[(name, page(vec![entry]))]).await;
        mount_close(&harness, ResponseTemplate::new(204)).await;
        let run = harness.run(&close(&["--json", "--yes"])).await;
        assert_eq!(run.outcome.exit_code, 1, "{name}");
        let error = &run.json()["error"];
        assert_eq!(error["code"], "CaseHasHolds", "{name}");
        let message = error["message"].as_str().unwrap();
        assert!(message.contains(&format!("1 {name}")), "{message}");
        assert!(!message.contains("Kim Example"), "{message}");
        assert!(writes(&harness).await.is_empty(), "{name}");
    }
}

#[tokio::test]
async fn a_hold_list_whose_second_page_fails_refuses_the_close() {
    let harness = signed_in().await;
    mount_case(&harness, &[case("active", MARKED)]).await;
    let next = format!(
        "{}{}?$skiptoken=2",
        harness.graph.uri(),
        hold_path("legalHolds")
    );
    Mock::given(method("GET"))
        .and(path(hold_path("legalHolds")))
        .and(query_param("$skiptoken", "2"))
        .respond_with(json_response(
            500,
            json!({"error": {"code": "InternalServerError"}}),
        ))
        .with_priority(1)
        .mount(&harness.graph)
        .await;
    mount_holds(
        &harness,
        &[("legalHolds", json!({"value": [], "@odata.nextLink": next}))],
    )
    .await;
    mount_close(&harness, ResponseTemplate::new(204)).await;
    let run = harness.run(&close(&["--json", "--yes"])).await;
    assert_eq!(run.outcome.exit_code, 1);
    assert_eq!(run.json()["error"]["code"], "ClosePrecheckFailed");
    assert!(writes(&harness).await.is_empty());
}

#[tokio::test]
async fn a_case_without_the_marker_is_refused_unless_any_case() {
    let harness = signed_in().await;
    mount_case(&harness, &[case("active", "A case made in the portal")]).await;
    mount_holds(&harness, &[]).await;
    mount_close(&harness, ResponseTemplate::new(204)).await;
    let run = harness.run(&close(&["--json", "--yes"])).await;
    assert_eq!(run.outcome.exit_code, 1);
    let error = &run.json()["error"];
    assert_eq!(error["code"], "ClosePrecheckFailed");
    assert!(error["message"].as_str().unwrap().contains("--any-case"));
    assert!(writes(&harness).await.is_empty());

    let run = harness
        .run(&close(&["--json", "--dry-run", "--any-case"]))
        .await;
    assert_eq!(run.outcome.exit_code, 0, "{}", run.stdout());
    let plan = &run.json()["results"]["plan"];
    assert!(plan["warnings"][0].as_str().unwrap().contains("--any-case"));
}

#[tokio::test]
async fn a_case_that_is_not_active_is_refused_before_any_hold_read() {
    for status in ["closed", "closing"] {
        let harness = signed_in().await;
        mount_case(&harness, &[case(status, MARKED)]).await;
        mount_holds(&harness, &[]).await;
        let run = harness.run(&close(&["--json", "--yes"])).await;
        assert_eq!(run.outcome.exit_code, 1, "{status}");
        assert_eq!(run.json()["error"]["code"], "ClosePrecheckFailed");
        let reads = graph_requests(&harness).await;
        assert!(
            !reads
                .iter()
                .any(|request| request.url.path().ends_with("/legalHolds")),
            "{status}"
        );
        assert!(writes(&harness).await.is_empty(), "{status}");
    }
}

async fn at_a_terminal(harness: &Harness, answers: &[&str]) -> (Run, usize) {
    let input = Arc::new(ScriptedInput::new(answers));
    let reads = input.clone();
    let run = harness
        .run_with(&close(&["--json"]), move |env, _| {
            env.stdin_is_terminal = true;
            env.stderr_is_terminal = true;
            env.input = input;
        })
        .await;
    (run, reads.reads())
}

#[tokio::test]
async fn at_a_terminal_only_the_typed_case_name_closes_the_case() {
    let harness = ready(&[case("closed", MARKED)]).await;
    let (run, reads) = at_a_terminal(&harness, &[&format!("  {CASE_NAME} ")]).await;
    assert_eq!(run.outcome.exit_code, 0, "{}", run.stdout());
    assert_eq!(reads, 1);
    assert!(
        run.stderr()
            .contains(&format!("Type the case name to apply ({CASE_NAME}): ")),
        "{}",
        run.stderr()
    );
    assert_eq!(writes(&harness).await.len(), 1);

    for answers in [&["y"][..], &["yes"], &[""], &[], &["Records research"]] {
        let harness = ready(&[]).await;
        let (run, _) = at_a_terminal(&harness, answers).await;
        assert_eq!(run.outcome.exit_code, 3, "{answers:?}");
        assert_eq!(run.json()["error"]["code"], "Declined", "{answers:?}");
        assert!(writes(&harness).await.is_empty(), "{answers:?}");
    }
}

#[tokio::test]
async fn holds_added_while_the_person_answers_stop_the_close() {
    let harness = signed_in().await;
    mount_case(&harness, &[case("active", MARKED)]).await;
    // The first read of legalHolds is empty, the recheck finds one.
    Mock::given(method("GET"))
        .and(path(hold_path("legalHolds")))
        .respond_with(json_response(200, page(vec![])))
        .up_to_n_times(1)
        .with_priority(1)
        .mount(&harness.graph)
        .await;
    mount_holds(&harness, &[("legalHolds", page(vec![json!({"id": "x"})]))]).await;
    mount_close(&harness, ResponseTemplate::new(204)).await;
    let run = harness.run(&close(&["--json", "--yes"])).await;
    assert_eq!(run.outcome.exit_code, 1, "{}", run.stdout());
    assert_eq!(run.json()["error"]["code"], "CaseHasHolds");
    assert!(writes(&harness).await.is_empty());
}

#[tokio::test]
async fn a_post_timeout_reconciles_through_a_read_of_the_case() {
    let harness = signed_in().await;
    mount_case(
        &harness,
        &[
            case("active", MARKED),
            case("active", MARKED),
            case("closing", MARKED),
        ],
    )
    .await;
    mount_holds(&harness, &[]).await;
    mount_close(
        &harness,
        ResponseTemplate::new(204).set_delay(Duration::from_secs(3)),
    )
    .await;
    let run = harness
        .run(&close(&["--json", "--yes", "--timeout", "1"]))
        .await;
    assert_eq!(run.outcome.exit_code, 1);
    let error = &run.json()["error"];
    assert_eq!(error["code"], "WriteOutcomeUnknown");
    let message = error["message"].as_str().unwrap();
    assert!(
        message.contains(&format!("case {CASE}: closing")),
        "{message}"
    );
    assert_eq!(writes(&harness).await.len(), 1);
}

#[tokio::test]
async fn wait_reads_the_case_until_it_is_closed() {
    let harness = ready(&[case("closing", MARKED), case("closed", MARKED)]).await;
    let run = harness
        .run(&close(&[
            "--json",
            "--yes",
            "--wait",
            "--poll-interval",
            "5s",
        ]))
        .await;
    assert_eq!(run.outcome.exit_code, 0, "{}", run.stdout());
    assert_eq!(run.json()["results"]["result"]["status"], "closed");
}

#[tokio::test]
async fn the_wait_deadline_gives_the_case_close_shape() {
    let harness = ready(&[case("closing", MARKED)]).await;
    let run = harness
        .run(&close(&[
            "--json",
            "--yes",
            "--wait",
            "--wait-timeout",
            "1m",
            "--poll-interval",
            "10s",
        ]))
        .await;
    assert_eq!(run.outcome.exit_code, 5, "{}", run.stdout());
    let document = run.json();
    assert_eq!(document["error"]["code"], "WaitTimeout");
    assert_eq!(document["caseId"], CASE);
    assert_eq!(document["caseStatus"], "closing");
    assert_eq!(
        document["resume"],
        json!([format!("purview --account={ALEX} case get {CASE}")])
    );
    assert!(document["elapsedSeconds"].as_u64().unwrap() >= 60);
    assert_eq!(writes(&harness).await.len(), 1);
}

#[tokio::test]
async fn wait_flags_need_wait() {
    let harness = signed_in().await;
    let run = harness
        .run(&close(&["--json", "--yes", "--wait-timeout", "1m"]))
        .await;
    assert_eq!(run.outcome.exit_code, 1);
    assert_eq!(run.json()["error"]["code"], "CommandFailed");
    assert!(graph_requests(&harness).await.is_empty());
}

#[tokio::test]
async fn a_hold_list_paging_link_to_another_case_is_refused() {
    let harness = signed_in().await;
    mount_case(&harness, &[case("active", MARKED)]).await;
    let other = format!(
        "{}{CASES}/00000000-0000-4000-8000-000000000032/legalHolds",
        harness.graph.uri()
    );
    Mock::given(method("GET"))
        .and(path(format!(
            "{CASES}/00000000-0000-4000-8000-000000000032/legalHolds"
        )))
        .respond_with(json_response(200, page(vec![])))
        .mount(&harness.graph)
        .await;
    mount_holds(
        &harness,
        &[("legalHolds", json!({"value": [], "@odata.nextLink": other}))],
    )
    .await;
    mount_close(&harness, ResponseTemplate::new(204)).await;
    let run = harness.run(&close(&["--json", "--yes"])).await;
    assert_eq!(run.outcome.exit_code, 1, "{}", run.stdout());
    assert_eq!(run.json()["error"]["code"], "ClosePrecheckFailed");
    assert!(writes(&harness).await.is_empty());
}

#[tokio::test]
async fn a_marker_removed_while_the_person_answers_stops_the_close() {
    let harness = signed_in().await;
    mount_case(
        &harness,
        &[
            case("active", MARKED),
            case("active", "Edited in the portal"),
        ],
    )
    .await;
    mount_holds(&harness, &[]).await;
    mount_close(&harness, ResponseTemplate::new(204)).await;
    let run = harness.run(&close(&["--json", "--yes"])).await;
    assert_eq!(run.outcome.exit_code, 1, "{}", run.stdout());
    assert_eq!(run.json()["error"]["code"], "ClosePrecheckFailed");
    assert!(writes(&harness).await.is_empty());
}

#[tokio::test]
async fn a_failed_hold_read_never_repeats_graphs_message() {
    let harness = signed_in().await;
    mount_case(&harness, &[case("active", MARKED)]).await;
    Mock::given(method("GET"))
        .and(path(hold_path("legalHolds")))
        .respond_with(json_response(
            403,
            json!({"error": {"code": "Forbidden", "message": "No access to Kim Example hold"}}),
        ))
        .with_priority(1)
        .mount(&harness.graph)
        .await;
    mount_holds(&harness, &[]).await;
    let run = harness.run(&close(&["--json", "--yes"])).await;
    assert_eq!(run.outcome.exit_code, 1);
    let error = &run.json()["error"];
    assert_eq!(error["code"], "ClosePrecheckFailed");
    let message = error["message"].as_str().unwrap();
    assert!(message.contains("HTTP 403"), "{message}");
    assert!(!message.contains("Kim Example"), "{message}");
    assert!(writes(&harness).await.is_empty());
}

#[tokio::test]
async fn the_prompt_shows_a_url_in_the_case_name_without_its_query() {
    let name = "Review of https://portal.contoso.example/a?sig=promptsecret";
    let harness = signed_in().await;
    let named = |status: &str| {
        let mut record = case(status, MARKED);
        record["displayName"] = json!(name);
        record
    };
    mount_case(
        &harness,
        &[named("active"), named("active"), named("closed")],
    )
    .await;
    mount_holds(&harness, &[]).await;
    mount_close(&harness, ResponseTemplate::new(204)).await;
    let (run, _) = at_a_terminal(&harness, &[name]).await;
    assert_eq!(run.outcome.exit_code, 0, "{}", run.stdout());
    assert!(!run.stderr().contains("promptsecret"), "{}", run.stderr());
    assert_eq!(writes(&harness).await.len(), 1);
}

#[tokio::test]
async fn a_status_the_tool_does_not_know_ends_the_wait_with_exit_4() {
    let harness = ready(&[case("closedWithError", MARKED)]).await;
    let run = harness
        .run(&close(&[
            "--json",
            "--yes",
            "--wait",
            "--poll-interval",
            "5s",
        ]))
        .await;
    assert_eq!(run.outcome.exit_code, 4, "{}", run.stdout());
    let document = run.json();
    assert_eq!(document["outcome"]["reasons"][0]["code"], "UnknownStatus");
    assert_eq!(document["results"]["result"]["status"], "closedWithError");
}

#[tokio::test]
async fn a_case_read_with_no_status_ends_the_wait() {
    let mut unreadable = case("active", MARKED);
    unreadable.as_object_mut().unwrap().remove("status");
    let harness = ready(&[unreadable]).await;
    let run = harness
        .run(&close(&[
            "--json",
            "--yes",
            "--wait",
            "--poll-interval",
            "5s",
        ]))
        .await;
    assert_eq!(run.outcome.exit_code, 1, "{}", run.stdout());
    assert_eq!(writes(&harness).await.len(), 1);
}

#[tokio::test]
async fn ctrl_c_during_the_wait_gives_the_case_close_shape() {
    let harness = ready(&[case("closing", MARKED)]).await;
    let interrupt = Arc::new(ms_purview_cli::env::ManualInterrupt::default());
    interrupt.fire();
    let run = harness
        .run_with(&close(&["--json", "--yes", "--wait"]), |env, _| {
            env.interrupt = interrupt.clone();
        })
        .await;
    assert_eq!(run.outcome.exit_code, 130, "{}", run.stdout());
    let document = run.json();
    assert_eq!(document["error"]["code"], "Interrupted");
    assert_eq!(document["caseId"], CASE);
    assert_eq!(
        document["resume"],
        json!([format!("purview --account={ALEX} case get {CASE}")])
    );
    assert_eq!(writes(&harness).await.len(), 1);
}

#[tokio::test]
async fn a_name_with_a_hidden_character_is_confirmed_as_shown() {
    let hidden = "Records\u{200b} research";
    let harness = signed_in().await;
    let named = |status: &str| {
        let mut record = case(status, MARKED);
        record["displayName"] = json!(hidden);
        record
    };
    mount_case(
        &harness,
        &[named("active"), named("active"), named("closed")],
    )
    .await;
    mount_holds(&harness, &[]).await;
    mount_close(&harness, ResponseTemplate::new(204)).await;
    let (run, _) = at_a_terminal(&harness, &["Records research"]).await;
    assert_eq!(run.outcome.exit_code, 0, "{}", run.stdout());
    assert_eq!(writes(&harness).await.len(), 1);
}

#[tokio::test]
async fn a_name_the_terminal_shows_as_nothing_is_confirmed_by_the_case_id() {
    let harness = signed_in().await;
    let named = |status: &str| {
        let mut record = case(status, MARKED);
        record["displayName"] = json!("\u{200b}\u{200b}");
        record
    };
    mount_case(
        &harness,
        &[named("active"), named("active"), named("closed")],
    )
    .await;
    mount_holds(&harness, &[]).await;
    mount_close(&harness, ResponseTemplate::new(204)).await;
    let (run, _) = at_a_terminal(&harness, &[CASE]).await;
    assert_eq!(run.outcome.exit_code, 0, "{}", run.stdout());
    assert!(
        run.stderr()
            .contains(&format!("Type the case name to apply ({CASE}): ")),
        "{}",
        run.stderr()
    );
    assert_eq!(writes(&harness).await.len(), 1);
}
