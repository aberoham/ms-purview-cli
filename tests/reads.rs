//! In-process flows of the read commands (`case`, `search` and
//! `operation`) through `cli::execute_with`, against a wiremock Graph and
//! identity platform, an in-memory credential store and a manual clock.

mod support;

use std::sync::Arc;
use std::time::Duration;

use ms_purview_cli::env::ManualInterrupt;
use serde_json::{json, Value};
use support::*;
use wiremock::matchers::{method, path, query_param};
use wiremock::{Mock, Request, Respond, ResponseTemplate};

const CASES: &str = "/v1.0/security/cases/ediscoveryCases";
const CASE: &str = "00000000-0000-4000-8000-000000000031";
const SEARCH: &str = "00000000-0000-4000-8000-000000000051";
const ESTIMATE: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaa0001";

fn case_path(tail: &str) -> String {
    format!("{CASES}/{CASE}{tail}")
}

async fn mount(harness: &Harness, at: &str, status: u16, fixture: &str) {
    Mock::given(method("GET"))
        .and(path(at))
        .respond_with(json_response(
            status,
            graph_fixture(fixture, &harness.graph.uri()),
        ))
        .mount(&harness.graph)
        .await;
}

async fn signed_in() -> Harness {
    let harness = Harness::new().await;
    sign_in_alex(&harness).await;
    harness
}

/// The sleeps the command asked for, after the `before` that sign-in and
/// earlier commands took.
fn sleeps_since(harness: &Harness, before: usize) -> Vec<Duration> {
    harness.clock.sleeps()[before..].to_vec()
}

async fn requests(harness: &Harness) -> Vec<Request> {
    harness.graph.received_requests().await.unwrap()
}

fn fixture_value(harness: &Harness, name: &str) -> Value {
    graph_fixture(name, &harness.graph.uri())
}

#[tokio::test]
async fn case_list_shows_every_case_with_placeholders_and_ages() {
    let harness = signed_in().await;
    mount(&harness, CASES, 200, "cases-list.json").await;
    let run = harness.run(&["--plain", "case", "list"]).await;
    assert_eq!(run.outcome.exit_code, 0, "{}", run.stderr());
    assert_eq!(
        run.stdout(),
        "00000000-0000-4000-8000-000000000031\tRecords research - Orders review\tactive\t\
         2026-01-02\t2\talex.w@contoso.example\n\
         00000000-0000-4000-8000-000000000032\tSupplier contract\tclosing\t2025-12-01\t35\t\
         sam.taylor@contoso.example\n\
         00000000-0000-4000-8000-000000000033\tSupplier contract\tclosed\t2025-06-15\t204\t\
         alex.w@contoso.example\n\
         00000000-0000-4000-8000-000000000034\t?\tactive\t2026-01-04\t0\t\
         sam.taylor@contoso.example\n\
         ?\tLegacy hold review\tclosed\t\t\t\n"
    );
    assert_eq!(
        run.stderr(),
        "warning: 2 cases have no id or no name; '?' stands in for it\n"
    );
    let table = harness.run(&["case", "list", "--status", "closing"]).await;
    assert_eq!(
        table.stdout(),
        "ID                                    NAME               STATUS   CREATED     AGE (DAYS)  \
         CREATED BY\n\
         00000000-0000-4000-8000-000000000032  Supplier contract  closing  2025-12-01  35          \
         sam.taylor@contoso.example\n"
    );
    harness.assert_no_canaries(&run);
}

#[tokio::test]
async fn case_list_json_keeps_graph_s_records_as_they_came() {
    let harness = signed_in().await;
    mount(&harness, CASES, 200, "cases-list.json").await;
    let run = harness.run(&["--json", "case", "list"]).await;
    assert_eq!(run.outcome.exit_code, 0, "{}", run.stderr());
    let expected = fixture_value(&harness, "cases-list.json")["value"].clone();
    assert_eq!(run.json(), json!({"results": expected, "count": 5}));
    assert_eq!(run.outcome.stdout_value, Some(run.json()));
}

#[tokio::test]
async fn case_list_filters_on_status_name_dates_and_creator() {
    let harness = signed_in().await;
    mount(&harness, CASES, 200, "cases-list.json").await;
    let ids = |run: &Run| -> Vec<String> {
        run.stdout()
            .lines()
            .map(|line| line.split('\t').next().unwrap().to_owned())
            .collect()
    };
    let id = |tail: &str| format!("00000000-0000-4000-8000-0000000000{tail}");
    for (args, expected) in [
        (&["--status", "closed"][..], vec![id("33"), "?".to_owned()]),
        (&["--status", "active"][..], vec![id("31"), id("34")]),
        (&["--name", "SUPPLIER"][..], vec![id("32"), id("33")]),
        (
            &[
                "--created-after",
                "2026-01-02",
                "--created-before",
                "2026-01-04",
            ][..],
            vec![id("31"), id("34")],
        ),
        (
            &["--created-before", "2025-12-01"][..],
            vec![id("32"), id("33")],
        ),
        // By object id for one, by user principal name for the record
        // without an id.
        (&["--mine"][..], vec![id("31"), id("33")]),
    ] {
        let mut argv = vec!["--plain", "case", "list"];
        argv.extend_from_slice(args);
        let run = harness.run(&argv).await;
        assert_eq!(run.outcome.exit_code, 0, "{args:?}: {}", run.stderr());
        assert_eq!(ids(&run), expected, "{args:?}");
    }
}

#[tokio::test]
async fn case_list_follows_paging_links_on_the_graph_origin() {
    let harness = signed_in().await;
    Mock::given(method("GET"))
        .and(path(CASES))
        .and(query_param("$skiptoken", "page-0002"))
        .respond_with(json_response(
            200,
            fixture_value(&harness, "cases-list-page2.json"),
        ))
        .with_priority(1)
        .mount(&harness.graph)
        .await;
    mount(&harness, CASES, 200, "cases-list-page1.json").await;
    let run = harness.run(&["--json", "case", "list"]).await;
    assert_eq!(run.outcome.exit_code, 0, "{}", run.stderr());
    assert_eq!(run.json()["count"], 3);
    assert_eq!(requests(&harness).await.len(), 2);
}

#[tokio::test]
async fn bad_case_list_arguments_are_refused_before_sign_in() {
    let harness = Harness::new().await;
    for args in [
        &["case", "list", "--status", "open"][..],
        &["case", "list", "--created-after", "05/01/2026"][..],
        &["case", "list", "--name", ""][..],
        &["case", "get", " "][..],
    ] {
        let mut argv = vec!["--json"];
        argv.extend_from_slice(args);
        let run = harness.run(&argv).await;
        assert_eq!(run.outcome.exit_code, 1, "{args:?}");
        let message = run.json()["error"]["message"].as_str().unwrap().to_owned();
        assert!(!message.contains("signed in"), "{args:?}: {message}");
    }
    assert!(requests(&harness).await.is_empty());
}

#[tokio::test]
async fn case_get_by_id_prints_the_case() {
    let harness = signed_in().await;
    mount(&harness, &case_path(""), 200, "case-get.json").await;
    let run = harness.run(&["case", "get", CASE]).await;
    assert_eq!(run.outcome.exit_code, 0, "{}", run.stderr());
    assert_eq!(
        run.stdout(),
        "ID:               00000000-0000-4000-8000-000000000031\n\
         Name:             Records research - Orders review\n\
         Status:           active\n\
         Description:      Requested by alex.w@contoso.example. Tenant-wide mailbox search with \
         no custodians or holds. [created-by:purview-cli]\n\
         External ID:      REQ-0001\n\
         Created:          2026-01-02T10:15:00Z\n\
         Created by:       alex.w@contoso.example\n\
         Last modified:    2026-01-03T08:00:00Z\n\
         Last modified by: alex.w@contoso.example\n\
         Closed:\n\
         Closed by:\n"
    );
    assert!(run.stderr().is_empty(), "{}", run.stderr());
    let json = harness.run(&["--json", "case", "get", CASE]).await;
    assert_eq!(
        json.json(),
        json!({"results": fixture_value(&harness, "case-get.json"), "count": 1})
    );
}

#[tokio::test]
async fn a_case_name_matches_exactly_across_statuses() {
    let harness = signed_in().await;
    mount(&harness, CASES, 200, "cases-list.json").await;
    mount(&harness, &case_path(""), 200, "case-get.json").await;
    let run = harness
        .run(&["--json", "case", "get", "Records research - Orders review"])
        .await;
    assert_eq!(run.outcome.exit_code, 0, "{}", run.stderr());
    // The matched case is read by its id: the entity, not the list row.
    assert_eq!(
        run.json()["results"],
        fixture_value(&harness, "case-get.json")
    );
    assert_eq!(requests(&harness).await.len(), 2);
    assert_eq!(
        run.stderr(),
        format!("notice: matched case {CASE} by its display name\n")
    );

    let ambiguous = harness
        .run(&["--json", "case", "get", "Supplier contract"])
        .await;
    assert_eq!(ambiguous.outcome.exit_code, 1);
    let error = &ambiguous.json()["error"];
    assert_eq!(error["code"], "AmbiguousCase");
    assert_eq!(
        error["message"],
        "2 cases have that display name; pass the id of one: \
         00000000-0000-4000-8000-000000000032 (closing, created 2025-12-01); \
         00000000-0000-4000-8000-000000000033 (closed, created 2025-06-15)"
    );
    assert!(ambiguous.stderr().is_empty());

    for name in ["supplier contract", "Supplier"] {
        let missing = harness.run(&["--json", "case", "get", name]).await;
        assert_eq!(missing.json()["error"]["code"], "CaseNotFound", "{name}");
    }
}

#[tokio::test]
async fn a_case_name_needs_the_whole_case_list() {
    let harness = signed_in().await;
    Mock::given(method("GET"))
        .and(path(CASES))
        .and(query_param("$skiptoken", "page-0002"))
        .respond_with(json_response(
            200,
            fixture_value(&harness, "cases-list-page1.json"),
        ))
        .with_priority(1)
        .mount(&harness.graph)
        .await;
    mount(&harness, CASES, 200, "cases-list-page1.json").await;
    let run = harness
        .run(&["--json", "case", "get", "Records research - Orders review"])
        .await;
    assert_eq!(run.outcome.exit_code, 1);
    let message = run.json()["error"]["message"].as_str().unwrap().to_owned();
    assert!(
        message.starts_with("matching the case name: Graph's paging repeated a link"),
        "{message}"
    );
}

#[tokio::test]
async fn a_case_id_graph_does_not_know_keeps_graph_s_error() {
    let harness = signed_in().await;
    mount(&harness, &case_path(""), 404, "error-404.json").await;
    let run = harness.run(&["--json", "case", "get", CASE]).await;
    assert_eq!(run.outcome.exit_code, 1);
    assert_eq!(run.json()["error"]["code"], "NotFound");
    assert_eq!(run.json()["error"]["status"], 404);
    assert_eq!(requests(&harness).await.len(), 1);
}

#[tokio::test]
async fn wrap_untrusted_marks_names_descriptions_and_identities_in_json_only() {
    let harness = signed_in().await;
    mount(&harness, &case_path(""), 200, "case-get.json").await;
    let run = harness
        .run(&["--json", "--wrap-untrusted", "case", "get", CASE])
        .await;
    assert_eq!(run.outcome.exit_code, 0, "{}", run.stderr());
    let document = run.json();
    let name = document["results"]["displayName"].as_str().unwrap();
    let id = name
        .strip_prefix("[UNTRUSTED:")
        .and_then(|rest| rest.split(']').next())
        .unwrap()
        .to_owned();
    assert_eq!(
        name,
        format!("[UNTRUSTED:{id}]Records research - Orders review[/UNTRUSTED:{id}]")
    );
    for pointer in [
        "/results/description",
        "/results/externalId",
        "/results/createdBy/user/displayName",
    ] {
        let value = document.pointer(pointer).unwrap().as_str().unwrap();
        assert!(value.starts_with(&format!("[UNTRUSTED:{id}]")), "{pointer}");
    }
    assert_eq!(document["results"]["status"], "active");
    assert_eq!(
        document["results"]["createdBy"]["user"]["userPrincipalName"],
        "alex.w@contoso.example"
    );
    assert!(document["untrustedNotice"]
        .as_str()
        .unwrap()
        .contains(&format!("[UNTRUSTED:{id}]")));

    let mut env_vars = harness
        .run_with(&["case", "get", CASE], |env, _| {
            env.vars
                .insert("PURVIEW_WRAP_UNTRUSTED".into(), "true".into());
        })
        .await;
    assert_eq!(env_vars.outcome.exit_code, 0);
    // Human output is never wrapped.
    assert!(!std::mem::take(&mut env_vars.captured.stdout)
        .text()
        .contains("UNTRUSTED"));
}

#[tokio::test]
async fn search_list_cuts_the_query_and_shows_the_scope() {
    let harness = signed_in().await;
    mount(&harness, &case_path("/searches"), 200, "searches-list.json").await;
    let run = harness
        .run(&[
            "--plain",
            "--select",
            "ID,SCOPE,QUERY",
            "search",
            "list",
            CASE,
        ])
        .await;
    assert_eq!(run.outcome.exit_code, 0, "{}", run.stderr());
    let text = run.stdout();
    let lines: Vec<Vec<&str>> = text
        .lines()
        .map(|line| line.split('\t').collect())
        .collect();
    assert_eq!(lines.len(), 3, "{text}");
    assert_eq!(
        lines[0],
        [
            SEARCH,
            "allTenantMailboxes",
            "participants:alex@contoso.example AND \"orders-api\""
        ]
    );
    assert_eq!(lines[1][1], "");
    assert_eq!(lines[1][2].chars().count(), 80);
    assert!(lines[1][2].ends_with('…'));
    assert_eq!(lines[2][1], "allTenantMailboxes,allTenantSites");

    let json = harness.run(&["--json", "search", "list", CASE]).await;
    let full = fixture_value(&harness, "searches-list.json")["value"].clone();
    assert_eq!(json.json(), json!({"results": full, "count": 3}));
}

async fn mount_sources(harness: &Harness, search: &str, additional: &str) {
    for (segment, fixture) in [
        ("custodianSources", "search-sources-empty.json"),
        ("noncustodialSources", "search-sources-empty.json"),
        ("additionalSources", additional),
    ] {
        mount(
            harness,
            &case_path(&format!("/searches/{search}/{segment}")),
            200,
            fixture,
        )
        .await;
    }
}

#[tokio::test]
async fn search_get_adds_the_three_source_lists_under_graph_s_names() {
    let harness = signed_in().await;
    mount(
        &harness,
        &case_path(&format!("/searches/{SEARCH}")),
        200,
        "search-get-mailboxes.json",
    )
    .await;
    mount_sources(&harness, SEARCH, "search-sources-one.json").await;
    let run = harness
        .run(&["--json", "search", "get", CASE, SEARCH])
        .await;
    assert_eq!(run.outcome.exit_code, 0, "{}", run.stderr());
    let mut expected = fixture_value(&harness, "search-get-mailboxes.json");
    expected["custodianSources"] = json!([]);
    expected["noncustodialSources"] = json!([]);
    expected["additionalSources"] =
        fixture_value(&harness, "search-sources-one.json")["value"].clone();
    assert_eq!(run.json(), json!({"results": expected, "count": 1}));
    assert_eq!(requests(&harness).await.len(), 4);

    let human = harness.run(&["search", "get", CASE, SEARCH]).await;
    let text = human.stdout();
    for line in [
        "Scope:                 allTenantMailboxes\n",
        "Custodian sources:     0\n",
        "Non-custodial sources: 0\n",
        "Additional sources:    1\n",
        "Query:                 participants:alex@contoso.example AND \"orders-api\"\n",
    ] {
        assert!(text.contains(line), "{line:?} in {text}");
    }
}

#[tokio::test]
async fn a_source_list_that_cannot_be_read_is_a_warning_and_shows_unknown() {
    let harness = signed_in().await;
    let search = "00000000-0000-4000-8000-000000000052";
    mount(
        &harness,
        &case_path(&format!("/searches/{search}")),
        200,
        "search-get-no-scope.json",
    )
    .await;
    for segment in ["custodianSources", "noncustodialSources"] {
        mount(
            &harness,
            &case_path(&format!("/searches/{search}/{segment}")),
            200,
            "search-sources-empty.json",
        )
        .await;
    }
    mount(
        &harness,
        &case_path(&format!("/searches/{search}/additionalSources")),
        403,
        "error-403.json",
    )
    .await;
    let run = harness.run(&["search", "get", CASE, search]).await;
    assert_eq!(run.outcome.exit_code, 0, "{}", run.stderr());
    assert!(run
        .stdout()
        .contains("Scope:                 (not returned)\n"));
    assert!(run.stdout().contains("Additional sources:    unknown\n"));
    assert!(
        run.stderr().starts_with(
            "warning: could not read the search's additionalSources: Microsoft Graph returned \
             HTTP 403"
        ),
        "{}",
        run.stderr()
    );
    let json = harness
        .run(&["--json", "search", "get", CASE, search])
        .await;
    assert!(json.json()["results"].get("additionalSources").is_none());
}

#[tokio::test]
async fn a_search_name_matches_within_the_case() {
    let harness = signed_in().await;
    mount(&harness, &case_path("/searches"), 200, "searches-list.json").await;
    let search = "00000000-0000-4000-8000-000000000052";
    mount(
        &harness,
        &case_path(&format!("/searches/{search}")),
        200,
        "search-get-no-scope.json",
    )
    .await;
    mount_sources(&harness, search, "search-sources-empty.json").await;
    let run = harness
        .run(&["--json", "search", "get", CASE, "Long query"])
        .await;
    assert_eq!(run.outcome.exit_code, 0, "{}", run.stderr());
    assert_eq!(run.json()["results"]["id"], search);
    assert_eq!(
        run.stderr(),
        format!("notice: matched search {search} by its display name\n")
    );
    let ambiguous = harness
        .run(&["--json", "search", "get", CASE, "Orders API mentions"])
        .await;
    assert_eq!(ambiguous.json()["error"]["code"], "AmbiguousSearch");
    let missing = harness
        .run(&["--json", "search", "get", CASE, "orders api mentions"])
        .await;
    assert_eq!(missing.json()["error"]["code"], "SearchNotFound");
}

#[tokio::test]
async fn operation_list_marks_ambiguous_exports_and_explains_them() {
    let harness = signed_in().await;
    mount(
        &harness,
        &case_path("/operations"),
        200,
        "operations-list.json",
    )
    .await;
    let run = harness.run(&["--plain", "operation", "list", CASE]).await;
    assert_eq!(run.outcome.exit_code, 0, "{}", run.stderr());
    assert_eq!(
        run.stdout(),
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaa0001\testimate\tsucceeded\t2026-01-02\t2026-01-02\t\
         alex.w@contoso.example\t\t\n\
         aaaaaaaaaaaaaaaaaaaaaaaaaaaa0002\texportResult?\tsucceeded\t2026-01-02\t2026-01-02\t\
         alex.w@contoso.example\t\t\n\
         aaaaaaaaaaaaaaaaaaaaaaaaaaaa0003\texportResult?\trunning\t2026-01-02\t\t\
         alex.w@contoso.example\t\t\n\
         aaaaaaaaaaaaaaaaaaaaaaaaaaaa0004\taddToReviewSet\tfailed\t2026-01-02\t2026-01-02\t\
         sam.taylor@contoso.example\t\t\n"
    );
    assert!(
        run.stderr()
            .starts_with("note: the operation list shows both item reports and exports"),
        "{}",
        run.stderr()
    );
    let json = harness
        .run(&["--json", "operation", "list", CASE, "--status", "RUNNING"])
        .await;
    let mut entry = fixture_value(&harness, "operations-list.json")["value"][2].clone();
    entry["actionSource"] = json!("list");
    assert_eq!(json.json(), json!({"results": [entry], "count": 1}));
}

#[tokio::test]
async fn report_and_export_filters_need_resolve_and_are_refused_before_sign_in() {
    let harness = Harness::new().await;
    for action in ["report", "export"] {
        let run = harness
            .run(&["--json", "operation", "list", CASE, "--action", action])
            .await;
        assert_eq!(run.outcome.exit_code, 1, "{action}");
        assert_eq!(run.json()["error"]["code"], "ResolveRequired", "{action}");
    }
    let run = harness
        .run(&["--json", "operation", "list", CASE, "--status", "done"])
        .await;
    assert!(run.json()["error"]["message"]
        .as_str()
        .unwrap()
        .starts_with("--status must be one of notStarted, running"));
    assert!(requests(&harness).await.is_empty());
}

#[tokio::test]
async fn resolve_reads_only_the_candidates_and_reports_their_true_action() {
    let harness = signed_in().await;
    mount(
        &harness,
        &case_path("/operations"),
        200,
        "operations-list.json",
    )
    .await;
    mount(
        &harness,
        &case_path("/operations/aaaaaaaaaaaaaaaaaaaaaaaaaaaa0002"),
        200,
        "operation-exportreport-succeeded.json",
    )
    .await;
    mount(
        &harness,
        &case_path("/operations/aaaaaaaaaaaaaaaaaaaaaaaaaaaa0003"),
        200,
        "operation-exportresult-running.json",
    )
    .await;
    let run = harness
        .run(&[
            "--json",
            "operation",
            "list",
            CASE,
            "--resolve",
            "--action",
            "report",
        ])
        .await;
    assert_eq!(run.outcome.exit_code, 0, "{}", run.stderr());
    let mut expected = fixture_value(&harness, "operation-exportreport-succeeded.json");
    expected["actionSource"] = json!("get");
    assert_eq!(run.json(), json!({"results": [expected], "count": 1}));
    let paths: Vec<String> = requests(&harness)
        .await
        .iter()
        .map(|request| request.url.path().to_owned())
        .collect();
    assert_eq!(paths.len(), 3, "{paths:?}");
    assert!(!paths
        .iter()
        .any(|path| path.ends_with("0001") || path.ends_with("0004")));

    let table = harness
        .run(&[
            "--plain",
            "operation",
            "list",
            CASE,
            "--resolve",
            "--action",
            "export",
        ])
        .await;
    assert_eq!(
        table.stdout(),
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaa0003\texport\trunning\t2026-01-02\t\t\
         alex.w@contoso.example\t\t0\n"
    );
    assert!(table.stderr().is_empty(), "{}", table.stderr());
}

fn operation_path(id: &str) -> String {
    case_path(&format!("/operations/{id}"))
}

#[tokio::test]
async fn operation_get_shows_counts_files_and_an_unchecked_collection() {
    let harness = signed_in().await;
    mount(
        &harness,
        &operation_path(ESTIMATE),
        200,
        "operation-estimate-succeeded.json",
    )
    .await;
    let run = harness
        .run(&["--json", "operation", "get", CASE, ESTIMATE])
        .await;
    assert_eq!(run.outcome.exit_code, 0, "{}", run.stderr());
    let mut expected = fixture_value(&harness, "operation-estimate-succeeded.json");
    expected["collection"] = json!("unchecked");
    assert_eq!(run.json(), json!({"results": expected, "count": 1}));

    let human = harness.run(&["operation", "get", CASE, ESTIMATE]).await;
    let text = human.stdout();
    for line in [
        "Action:              estimate\n",
        "Status:              succeeded\n",
        "Completed:           2026-01-02T10:26:00Z\n",
        "Indexed items:       1234\n",
        "Unindexed items:     0\n",
        "Locations with hits: 17\n",
        "File:                Orders API mentions_Estimate.zip (size unknown)\n",
        "Collection:          unchecked\n",
    ] {
        assert!(text.contains(line), "{line:?} in {text}");
    }
    assert!(!text.contains("proxyservice"), "{text}");
}

#[tokio::test]
async fn a_finished_operation_that_did_not_succeed_exits_4_with_its_reason() {
    for (fixture, code, message) in [
        (
            "operation-failed.json",
            "OperationFailed",
            "the operation finished with status failed: The search could not be completed.; \
             code 2; subcode 17",
        ),
        (
            "operation-partially-succeeded.json",
            "OperationPartiallySucceeded",
            "the operation finished with status partiallySucceeded: Some locations could not be \
             searched.; code 1; subcode 0",
        ),
        (
            "operation-submission-failed.json",
            "OperationSubmissionFailed",
            "the operation finished with status submissionFailed: The operation could not be \
             submitted.; code 3; subcode 4",
        ),
        (
            "operation-failed-resultinfo-strings.json",
            "OperationFailed",
            "the operation finished with status failed: The search could not be completed.",
        ),
        (
            "operation-unknown-status.json",
            "UnknownStatus",
            "the operation finished with status unknownFutureValue",
        ),
    ] {
        let harness = signed_in().await;
        mount(&harness, &operation_path(ESTIMATE), 200, fixture).await;
        let run = harness
            .run(&[
                "--json",
                "--results-only",
                "operation",
                "get",
                CASE,
                ESTIMATE,
            ])
            .await;
        assert_eq!(run.outcome.exit_code, 4, "{fixture}: {}", run.stderr());
        let document = run.json();
        assert_eq!(
            document["outcome"],
            json!({"code": "Incomplete", "reasons": [{"code": code, "message": message}]}),
            "{fixture}"
        );
        assert_eq!(document["count"], 1, "{fixture}");
        assert_eq!(document["results"]["id"], ESTIMATE, "{fixture}");
        assert_eq!(run.outcome.stdout_value, Some(document));
        assert!(run.stderr().is_empty(), "{fixture}: {}", run.stderr());

        let human = harness.run(&["operation", "get", CASE, ESTIMATE]).await;
        assert_eq!(human.outcome.exit_code, 4);
        assert!(human.stdout().starts_with("ID:"), "{fixture}");
        assert_eq!(
            human.stderr(),
            format!("warning: operation {ESTIMATE}: {message}\n"),
            "{fixture}"
        );
    }
}

#[tokio::test]
async fn odd_operation_records_still_show_or_fail_with_a_targeted_error() {
    let harness = signed_in().await;
    mount(
        &harness,
        &operation_path(ESTIMATE),
        200,
        "operation-negative-count.json",
    )
    .await;
    let run = harness.run(&["operation", "get", CASE, ESTIMATE]).await;
    assert_eq!(run.outcome.exit_code, 0, "{}", run.stderr());
    assert!(
        run.stdout().contains("Indexed items:\n"),
        "{}",
        run.stdout()
    );
    assert_eq!(
        run.stderr(),
        format!(
            "warning: operation {ESTIMATE} has fields that are not counts (percentProgress, \
             indexedItemCount); they are shown as unknown\n"
        )
    );

    let harness = signed_in().await;
    mount(
        &harness,
        &operation_path(ESTIMATE),
        200,
        "operation-file-missing-url.json",
    )
    .await;
    let run = harness.run(&["operation", "get", CASE, ESTIMATE]).await;
    assert_eq!(run.outcome.exit_code, 0, "{}", run.stderr());
    assert!(run.stdout().contains("(size unknown)"));

    let harness = signed_in().await;
    mount(
        &harness,
        &operation_path(ESTIMATE),
        200,
        "operation-missing-id.json",
    )
    .await;
    let run = harness
        .run(&["--json", "operation", "get", CASE, ESTIMATE])
        .await;
    assert_eq!(run.outcome.exit_code, 1);
    assert_eq!(
        run.json()["error"]["message"],
        "Graph returned an operation without a valid id"
    );
}

#[tokio::test]
async fn bad_operation_arguments_are_refused_before_sign_in() {
    let harness = Harness::new().await;
    for args in [
        &[
            "operation",
            "get",
            CASE,
            "00000000-0000-4000-8000-000000000031",
        ][..],
        &["operation", "get", CASE, ESTIMATE, "--wait-timeout", "5m"][..],
        &[
            "operation",
            "get",
            CASE,
            ESTIMATE,
            "--wait",
            "--poll-interval",
            "2s",
        ][..],
        &[
            "operation",
            "get",
            CASE,
            ESTIMATE,
            "--wait",
            "--wait-timeout",
            "soon",
        ][..],
    ] {
        let mut argv = vec!["--json"];
        argv.extend_from_slice(args);
        let run = harness.run(&argv).await;
        assert_eq!(run.outcome.exit_code, 1, "{args:?}");
        assert_eq!(run.json()["error"]["code"], "CommandFailed", "{args:?}");
    }
    assert!(requests(&harness).await.is_empty());
}

/// Mounts the operation read: `running` answers first, then `last`.
async fn mount_poll(harness: &Harness, running: u64, last: ResponseTemplate) {
    Mock::given(method("GET"))
        .and(path(operation_path(ESTIMATE)))
        .respond_with(json_response(
            200,
            fixture_value(harness, "operation-estimate-running.json"),
        ))
        .up_to_n_times(running)
        .with_priority(1)
        .mount(&harness.graph)
        .await;
    Mock::given(method("GET"))
        .and(path(operation_path(ESTIMATE)))
        .respond_with(last)
        .with_priority(2)
        .mount(&harness.graph)
        .await;
}

#[tokio::test]
async fn wait_reads_on_the_schedule_until_the_operation_finishes() {
    let harness = signed_in().await;
    let before = harness.clock.sleeps().len();
    mount_poll(
        &harness,
        2,
        json_response(
            200,
            fixture_value(&harness, "operation-estimate-succeeded.json"),
        ),
    )
    .await;
    let run = harness
        .run(&["--json", "operation", "get", CASE, ESTIMATE, "--wait"])
        .await;
    assert_eq!(run.outcome.exit_code, 0, "{}", run.stderr());
    assert_eq!(run.json()["results"]["status"], "succeeded");
    assert_eq!(
        sleeps_since(&harness, before),
        [Duration::from_secs(10), Duration::from_secs(10)]
    );
    assert_eq!(requests(&harness).await.len(), 3);
    // No progress lines: stderr is not a terminal.
    assert!(run.stderr().is_empty(), "{}", run.stderr());
}

#[tokio::test]
async fn progress_goes_to_a_terminal_stderr_unless_verbose() {
    let harness = signed_in().await;
    mount_poll(
        &harness,
        1,
        json_response(
            200,
            fixture_value(&harness, "operation-estimate-succeeded.json"),
        ),
    )
    .await;
    let run = harness
        .run_with(&["operation", "get", CASE, ESTIMATE, "--wait"], |env, _| {
            env.stderr_is_terminal = true;
        })
        .await;
    assert_eq!(run.outcome.exit_code, 0, "{}", run.stderr());
    assert_eq!(run.stderr(), "estimate aaaaaaaa…: running · 0s\n");
}

#[tokio::test]
async fn the_deadline_exits_5_with_the_last_status_and_the_resume_command() {
    let harness = signed_in().await;
    let before = harness.clock.sleeps().len();
    mount_poll(
        &harness,
        100,
        json_response(
            200,
            fixture_value(&harness, "operation-estimate-running.json"),
        ),
    )
    .await;
    let run = harness
        .run(&[
            "--json",
            "--results-only",
            "operation",
            "get",
            CASE,
            ESTIMATE,
            "--wait",
            "--wait-timeout",
            "25s",
        ])
        .await;
    assert_eq!(run.outcome.exit_code, 5, "{}", run.stderr());
    assert_eq!(
        run.json(),
        json!({
            "caseId": CASE,
            "operationId": ESTIMATE,
            "status": "running",
            "elapsedSeconds": 25,
            "resume": [format!("purview --account={ALEX} operation get {CASE} {ESTIMATE} --wait")],
            "error": {
                "code": "WaitTimeout",
                "status": 0,
                "message": "stopped waiting after 25s; the service carries on running the operation",
            },
        })
    );
    assert_eq!(
        sleeps_since(&harness, before),
        [
            Duration::from_secs(10),
            Duration::from_secs(10),
            Duration::from_secs(5)
        ]
    );
    assert_eq!(requests(&harness).await.len(), 3);
    assert!(run.stderr().is_empty(), "{}", run.stderr());

    let human = harness
        .run(&[
            "operation",
            "get",
            CASE,
            ESTIMATE,
            "--wait",
            "--wait-timeout",
            "20s",
            "--poll-interval",
            "15s",
        ])
        .await;
    assert_eq!(human.outcome.exit_code, 5);
    assert!(human.stdout().is_empty());
    assert_eq!(
        human.stderr(),
        format!(
            "stopped waiting after 20s; the service carries on running the operation. Operation \
             {ESTIMATE} was running. Resume with: purview --account={ALEX} operation get {CASE} {ESTIMATE} --wait\n"
        )
    );
}

#[tokio::test]
async fn the_deadline_also_ends_a_read_in_flight() {
    let harness = signed_in().await;
    Mock::given(method("GET"))
        .and(path(operation_path(ESTIMATE)))
        .respond_with(
            json_response(
                200,
                fixture_value(&harness, "operation-estimate-running.json"),
            )
            .set_delay(Duration::from_secs(5)),
        )
        .mount(&harness.graph)
        .await;
    let started = std::time::Instant::now();
    let run = harness
        .run(&[
            "--json",
            "operation",
            "get",
            CASE,
            ESTIMATE,
            "--wait",
            "--wait-timeout",
            "1s",
        ])
        .await;
    assert_eq!(run.outcome.exit_code, 5, "{}", run.stderr());
    assert_eq!(run.json()["status"], Value::Null);
    assert!(started.elapsed() < Duration::from_secs(4));
}

#[tokio::test]
async fn a_long_retry_after_spaces_the_next_read_instead_of_ending_the_wait() {
    let harness = signed_in().await;
    let before = harness.clock.sleeps().len();
    Mock::given(method("GET"))
        .and(path(operation_path(ESTIMATE)))
        .respond_with(
            json_response(503, json!({"error": {"code": "ServiceUnavailable"}}))
                .insert_header("Retry-After", "120"),
        )
        .up_to_n_times(1)
        .with_priority(1)
        .mount(&harness.graph)
        .await;
    Mock::given(method("GET"))
        .and(path(operation_path(ESTIMATE)))
        .respond_with(json_response(
            200,
            fixture_value(&harness, "operation-estimate-succeeded.json"),
        ))
        .with_priority(2)
        .mount(&harness.graph)
        .await;
    let run = harness
        .run(&["--json", "operation", "get", CASE, ESTIMATE, "--wait"])
        .await;
    assert_eq!(run.outcome.exit_code, 0, "{}", run.stderr());
    assert_eq!(sleeps_since(&harness, before), [Duration::from_secs(120)]);
    assert!(
        run.stderr()
            .starts_with("warning: reading the operation failed (Graph asked to retry after 120"),
        "{}",
        run.stderr()
    );
}

#[tokio::test]
async fn a_long_retry_after_never_outlasts_the_deadline() {
    let harness = signed_in().await;
    let before = harness.clock.sleeps().len();
    Mock::given(method("GET"))
        .and(path(operation_path(ESTIMATE)))
        .respond_with(
            json_response(503, json!({"error": {"code": "ServiceUnavailable"}}))
                .insert_header("Retry-After", "3000"),
        )
        .mount(&harness.graph)
        .await;
    let run = harness
        .run(&[
            "--json",
            "operation",
            "get",
            CASE,
            ESTIMATE,
            "--wait",
            "--wait-timeout",
            "90s",
        ])
        .await;
    assert_eq!(run.outcome.exit_code, 5, "{}", run.stderr());
    assert_eq!(run.json()["elapsedSeconds"], 90);
    assert_eq!(sleeps_since(&harness, before), [Duration::from_secs(90)]);
}

#[tokio::test]
async fn a_missing_operation_fails_at_once_even_while_waiting() {
    let harness = signed_in().await;
    let before = harness.clock.sleeps().len();
    mount(&harness, &operation_path(ESTIMATE), 404, "error-404.json").await;
    let run = harness
        .run(&["--json", "operation", "get", CASE, ESTIMATE, "--wait"])
        .await;
    assert_eq!(run.outcome.exit_code, 1);
    assert_eq!(run.json()["error"]["code"], "NotFound");
    assert_eq!(requests(&harness).await.len(), 1);
    assert!(sleeps_since(&harness, before).is_empty());
}

/// Answers `running` and fires Ctrl-C, as a person pressing it while the
/// command waits.
struct InterruptingAnswer {
    body: Value,
    interrupt: Arc<ManualInterrupt>,
    reads: std::sync::atomic::AtomicUsize,
    /// The read, counted from 0, that fires Ctrl-C while it is in flight.
    fire_on: usize,
}

impl Respond for InterruptingAnswer {
    fn respond(&self, _request: &Request) -> ResponseTemplate {
        if self.reads.fetch_add(1, std::sync::atomic::Ordering::SeqCst) == self.fire_on {
            self.interrupt.fire();
        }
        json_response(200, self.body.clone())
    }
}

#[tokio::test]
async fn ctrl_c_ends_the_wait_with_exit_130_and_the_resume_command() {
    let harness = signed_in().await;
    let before = harness.clock.sleeps().len();
    let interrupt = Arc::new(ManualInterrupt::default());
    Mock::given(method("GET"))
        .and(path(operation_path(ESTIMATE)))
        .respond_with(InterruptingAnswer {
            body: fixture_value(&harness, "operation-estimate-running.json"),
            interrupt: interrupt.clone(),
            reads: Default::default(),
            fire_on: 1,
        })
        .mount(&harness.graph)
        .await;
    let run = harness
        .run_with(
            &["--json", "operation", "get", CASE, ESTIMATE, "--wait"],
            |env, _| env.interrupt = interrupt.clone(),
        )
        .await;
    assert_eq!(run.outcome.exit_code, 130, "{}", run.stderr());
    let document = run.json();
    assert_eq!(document["error"]["code"], "Interrupted");
    assert_eq!(document["status"], "running");
    assert_eq!(
        document["resume"],
        json!([format!(
            "purview --account={ALEX} operation get {CASE} {ESTIMATE} --wait"
        )])
    );
    assert_eq!(requests(&harness).await.len(), 2);
    assert_eq!(sleeps_since(&harness, before), [Duration::from_secs(10)]);
}

#[tokio::test]
async fn ctrl_c_during_the_first_read_abandons_it() {
    let harness = signed_in().await;
    let before = harness.clock.sleeps().len();
    let interrupt = Arc::new(ManualInterrupt::default());
    Mock::given(method("GET"))
        .and(path(operation_path(ESTIMATE)))
        .respond_with(InterruptingAnswer {
            body: fixture_value(&harness, "operation-estimate-running.json"),
            interrupt: interrupt.clone(),
            reads: Default::default(),
            fire_on: 0,
        })
        .mount(&harness.graph)
        .await;
    let run = harness
        .run_with(&["operation", "get", CASE, ESTIMATE, "--wait"], |env, _| {
            env.interrupt = interrupt.clone()
        })
        .await;
    assert_eq!(run.outcome.exit_code, 130, "{}", run.stderr());
    assert!(run.stdout().is_empty());
    assert_eq!(
        run.stderr(),
        format!(
            "interrupted after 0s; the service carries on running the operation. Operation \
             {ESTIMATE} was not read yet. Resume with: purview --account={ALEX} operation get {CASE} {ESTIMATE} \
             --wait\n"
        )
    );
    assert!(sleeps_since(&harness, before).is_empty());
}

#[tokio::test]
async fn reads_with_trace_and_verbose_leak_no_token() {
    let harness = signed_in().await;
    mount(&harness, CASES, 200, "cases-list.json").await;
    mount(&harness, &case_path(""), 200, "case-get.json").await;
    mount(&harness, &case_path("/searches"), 200, "searches-list.json").await;
    mount(
        &harness,
        &case_path(&format!("/searches/{SEARCH}")),
        200,
        "search-get-mailboxes.json",
    )
    .await;
    mount_sources(&harness, SEARCH, "search-sources-one.json").await;
    mount(
        &harness,
        &case_path("/operations"),
        200,
        "operations-list.json",
    )
    .await;
    mount_poll(
        &harness,
        1,
        json_response(
            200,
            fixture_value(&harness, "operation-estimate-succeeded.json"),
        ),
    )
    .await;
    let mut traced = 0;
    for (index, args) in [
        &["case", "list"][..],
        &["case", "get", CASE][..],
        &["search", "list", CASE][..],
        &["search", "get", CASE, SEARCH][..],
        &["operation", "list", CASE][..],
        &["operation", "get", CASE, ESTIMATE, "--wait"][..],
    ]
    .into_iter()
    .enumerate()
    {
        for json in [true, false] {
            // The manual clock stands still, so each run gets a directory
            // of its own for its time-stamped file names.
            let trace = harness.root.path().join(format!("trace-{index}-{json}"));
            let trace_arg = trace.display().to_string();
            let mut argv = vec!["--verbose", "--trace", &trace_arg];
            if json {
                argv.push("--json");
            }
            argv.extend_from_slice(args);
            let run = harness.run(&argv).await;
            assert_eq!(run.outcome.exit_code, 0, "{args:?}: {}", run.stderr());
            assert!(run.stderr().contains("[verbose] GET "), "{args:?}");
            assert!(
                !run.stderr().contains("could not write"),
                "{}",
                run.stderr()
            );
            harness.assert_no_canaries(&run);
            traced += std::fs::read_dir(&trace).unwrap().count();
        }
    }
    assert_eq!(traced, 19);
}

/// The estimate fixture with a synthetic signature on its download URL and
/// a URL with one in its result message.
fn signed(harness: &Harness, fixture: &str) -> Value {
    let mut body = fixture_value(harness, fixture);
    body["reportFileMetadata"] = json!([{
        "fileName": "a.zip",
        "size": 0,
        "downloadUrl": "https://eur.proxyservice.ediscovery.svc.cloud.microsoft/ediscovery/api/proxy/exportaedblobFileResult?downloadType=Report&sig=canary-sig-0001",
    }]);
    body["resultInfo"] = json!({
        "code": 2,
        "message": "see https://eur.proxyservice.ediscovery.svc.cloud.microsoft/ediscovery/api/proxy/exportaedblobFileResult?sig=canary-sig-0002 for details",
    });
    body
}

#[tokio::test]
async fn signed_urls_reach_no_output_of_the_operation_commands() {
    let harness = signed_in().await;
    mount(
        &harness,
        &case_path("/operations"),
        200,
        "operations-list.json",
    )
    .await;
    for (id, status) in [
        ("0001", "succeeded"),
        ("0002", "failed"),
        ("0003", "running"),
        ("0004", "failed"),
    ] {
        let mut body = signed(&harness, "operation-estimate-succeeded.json");
        body["id"] = json!(format!("aaaaaaaaaaaaaaaaaaaaaaaaaaaa{id}"));
        body["status"] = json!(status);
        Mock::given(method("GET"))
            .and(path(operation_path(&format!(
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaa{id}"
            ))))
            .respond_with(json_response(200, body))
            .mount(&harness.graph)
            .await;
    }
    let failed = "aaaaaaaaaaaaaaaaaaaaaaaaaaaa0002";
    let mut values: Vec<&str> = CANARIES.to_vec();
    values.extend(["canary-sig-0001", "canary-sig-0002"]);
    for args in [
        &["--json", "operation", "get", CASE, ESTIMATE][..],
        &["operation", "get", CASE, ESTIMATE][..],
        &["--json", "operation", "get", CASE, failed][..],
        &["operation", "get", CASE, failed][..],
        &["--json", "operation", "list", CASE, "--resolve"][..],
        &["--verbose", "operation", "list", CASE, "--resolve"][..],
        &[
            "--json",
            "--wrap-untrusted",
            "operation",
            "get",
            CASE,
            ESTIMATE,
        ][..],
    ] {
        let run = harness.run(args).await;
        assert!(
            matches!(run.outcome.exit_code, 0 | 4),
            "{args:?}: {} {}",
            run.stdout(),
            run.stderr()
        );
        harness.assert_absent(&run, &values);
    }
    let run = harness
        .run(&["--json", "operation", "get", CASE, ESTIMATE])
        .await;
    assert_eq!(
        run.json()["results"]["reportFileMetadata"][0]["downloadUrl"],
        "https://eur.proxyservice.ediscovery.svc.cloud.microsoft/ediscovery/api/proxy/exportaedblobFileResult?downloadType=Report&sig=REDACTED"
    );
}

#[tokio::test]
async fn a_secret_across_the_query_cut_leaves_no_prefix() {
    let harness = signed_in().await;
    let mut body = fixture_value(&harness, "searches-list.json");
    let secret = "canary-graph-access-0001";
    body["value"][0]["contentQuery"] = json!(format!("{}{secret} tail", "x".repeat(70)));
    Mock::given(method("GET"))
        .and(path(case_path("/searches")))
        .respond_with(json_response(200, body))
        .mount(&harness.graph)
        .await;
    for format in ["--plain", "--select=QUERY"] {
        let run = harness.run(&[format, "search", "list", CASE]).await;
        assert_eq!(run.outcome.exit_code, 0, "{}", run.stderr());
        assert!(!run.stdout().contains("canary"), "{}", run.stdout());
    }
}

#[tokio::test]
async fn an_unknown_select_column_is_refused_before_sign_in() {
    let harness = Harness::new().await;
    for args in [
        &["case", "list"][..],
        &["search", "list", CASE][..],
        &["operation", "list", CASE, "--resolve"][..],
    ] {
        for json in [false, true] {
            let mut argv = vec!["--select", "canary-sig-0004"];
            if json {
                argv.push("--json");
            }
            argv.extend_from_slice(args);
            let run = harness.run(&argv).await;
            assert_eq!(run.outcome.exit_code, 1, "{args:?}");
            let text = format!("{}{}", run.stdout(), run.stderr());
            assert!(text.contains("does not have"), "{args:?}: {text}");
            assert!(!text.contains("canary"), "{args:?}: {text}");
        }
    }
    assert!(requests(&harness).await.is_empty());
}

#[tokio::test]
async fn a_rejected_operation_id_is_not_repeated() {
    let harness = Harness::new().await;
    let pasted = "https://graph.example/x?sig=canary-sig-0003";
    let run = harness
        .run(&["--json", "operation", "get", CASE, pasted])
        .await;
    assert_eq!(run.outcome.exit_code, 1);
    assert!(!run.stdout().contains("canary"), "{}", run.stdout());
}

/// Moves the manual clock on while the read is in flight, as a slow read
/// near the deadline would.
struct SlowAnswer {
    body: Value,
    clock: Arc<ms_purview_cli::env::ManualClock>,
}

impl Respond for SlowAnswer {
    fn respond(&self, _request: &Request) -> ResponseTemplate {
        self.clock.advance(Duration::from_secs(5));
        json_response(200, self.body.clone())
    }
}

#[tokio::test]
async fn a_read_that_ends_after_the_deadline_does_not_count() {
    let harness = signed_in().await;
    Mock::given(method("GET"))
        .and(path(operation_path(ESTIMATE)))
        .respond_with(SlowAnswer {
            body: fixture_value(&harness, "operation-estimate-succeeded.json"),
            clock: harness.clock.clone(),
        })
        .mount(&harness.graph)
        .await;
    let run = harness
        .run(&[
            "--json",
            "operation",
            "get",
            CASE,
            ESTIMATE,
            "--wait",
            "--wait-timeout",
            "1s",
        ])
        .await;
    assert_eq!(run.outcome.exit_code, 5, "{}", run.stderr());
    assert_eq!(run.json()["status"], "succeeded");
}

#[tokio::test]
async fn a_read_for_another_operation_or_without_an_id_ends_the_wait() {
    for change in [
        json!({"id": "aaaaaaaaaaaaaaaaaaaaaaaaaaaa0009"}),
        json!({"id": null}),
    ] {
        let harness = signed_in().await;
        let mut body = fixture_value(&harness, "operation-estimate-running.json");
        for (key, value) in change.as_object().unwrap() {
            body[key] = value.clone();
        }
        Mock::given(method("GET"))
            .and(path(operation_path(ESTIMATE)))
            .respond_with(json_response(200, body))
            .mount(&harness.graph)
            .await;
        let run = harness
            .run(&["--json", "operation", "get", CASE, ESTIMATE, "--wait"])
            .await;
        assert_eq!(run.outcome.exit_code, 1, "{change}");
        assert_eq!(requests(&harness).await.len(), 1, "{change}");
    }
}

#[tokio::test]
async fn any_5xx_while_waiting_is_waited_out() {
    let harness = signed_in().await;
    Mock::given(method("GET"))
        .and(path(operation_path(ESTIMATE)))
        .respond_with(json_response(
            507,
            json!({"error": {"code": "InsufficientStorage"}}),
        ))
        .up_to_n_times(1)
        .with_priority(1)
        .mount(&harness.graph)
        .await;
    Mock::given(method("GET"))
        .and(path(operation_path(ESTIMATE)))
        .respond_with(json_response(
            200,
            fixture_value(&harness, "operation-estimate-succeeded.json"),
        ))
        .with_priority(2)
        .mount(&harness.graph)
        .await;
    let run = harness
        .run(&["--json", "operation", "get", CASE, ESTIMATE, "--wait"])
        .await;
    assert_eq!(run.outcome.exit_code, 0, "{}", run.stderr());
}

#[tokio::test]
async fn waiting_stops_on_each_terminal_status_and_continues_while_not_started() {
    for (status, exit) in [
        ("succeeded", 0),
        ("partiallySucceeded", 4),
        ("failed", 4),
        ("submissionFailed", 4),
        ("unknownFutureValue", 4),
    ] {
        let harness = signed_in().await;
        let before = harness.clock.sleeps().len();
        let mut waiting = fixture_value(&harness, "operation-estimate-running.json");
        waiting["status"] = json!("notStarted");
        Mock::given(method("GET"))
            .and(path(operation_path(ESTIMATE)))
            .respond_with(json_response(200, waiting))
            .up_to_n_times(1)
            .with_priority(1)
            .mount(&harness.graph)
            .await;
        let mut last = fixture_value(&harness, "operation-estimate-succeeded.json");
        last["status"] = json!(status);
        Mock::given(method("GET"))
            .and(path(operation_path(ESTIMATE)))
            .respond_with(json_response(200, last))
            .with_priority(2)
            .mount(&harness.graph)
            .await;
        let run = harness
            .run(&["--json", "operation", "get", CASE, ESTIMATE, "--wait"])
            .await;
        assert_eq!(run.outcome.exit_code, exit, "{status}: {}", run.stderr());
        assert_eq!(run.json()["results"]["status"], status);
        assert_eq!(
            sleeps_since(&harness, before),
            [Duration::from_secs(10)],
            "{status}"
        );
    }
}

#[tokio::test]
async fn an_incomplete_or_null_source_list_is_not_given_as_a_list() {
    let harness = signed_in().await;
    let mut search = fixture_value(&harness, "search-get-mailboxes.json");
    search["custodianSources"] = Value::Null;
    Mock::given(method("GET"))
        .and(path(case_path(&format!("/searches/{SEARCH}"))))
        .respond_with(json_response(200, search))
        .mount(&harness.graph)
        .await;
    for segment in ["custodianSources", "noncustodialSources"] {
        mount(
            &harness,
            &case_path(&format!("/searches/{SEARCH}/{segment}")),
            200,
            "search-sources-empty.json",
        )
        .await;
    }
    // A paging link that leads back to itself.
    let sources = case_path(&format!("/searches/{SEARCH}/additionalSources"));
    Mock::given(method("GET"))
        .and(path(sources.as_str()))
        .respond_with(json_response(
            200,
            json!({
                "value": [],
                "@odata.nextLink": format!("{}{sources}", harness.graph.uri()),
            }),
        ))
        .mount(&harness.graph)
        .await;
    let run = harness
        .run(&["--json", "search", "get", CASE, SEARCH])
        .await;
    assert_eq!(run.outcome.exit_code, 0, "{}", run.stderr());
    let results = &run.json()["results"];
    assert_eq!(results["custodianSources"], json!([]));
    assert!(results.get("additionalSources").is_none(), "{results}");
    assert!(
        run.stderr()
            .contains("warning: the additionalSources list is incomplete"),
        "{}",
        run.stderr()
    );
}

/// Moves the clock past the deadline during the read, then answers with
/// `status` and `body`.
struct LateAnswer {
    status: u16,
    body: Value,
    clock: Arc<ms_purview_cli::env::ManualClock>,
}

impl Respond for LateAnswer {
    fn respond(&self, _request: &Request) -> ResponseTemplate {
        self.clock.advance(Duration::from_secs(5));
        json_response(self.status, self.body.clone())
    }
}

#[tokio::test]
async fn any_read_that_ends_after_the_deadline_exits_5() {
    let harness = signed_in().await;
    let mut no_id = fixture_value(&harness, "operation-estimate-running.json");
    no_id["id"] = Value::Null;
    let mut odd = fixture_value(&harness, "operation-estimate-running.json");
    odd["status"] = json!("https://graph.example/x?sig=canary-sig-0005");
    for (status, body, expected) in [
        (200, no_id, Value::Null),
        (403, fixture_value(&harness, "error-403.json"), Value::Null),
        (200, odd, json!("https://graph.example/x?sig=REDACTED")),
    ] {
        harness.graph.reset().await;
        Mock::given(method("GET"))
            .and(path(operation_path(ESTIMATE)))
            .respond_with(LateAnswer {
                status,
                body,
                clock: harness.clock.clone(),
            })
            .mount(&harness.graph)
            .await;
        let run = harness
            .run(&[
                "--json",
                "operation",
                "get",
                CASE,
                ESTIMATE,
                "--wait",
                "--wait-timeout",
                "1s",
            ])
            .await;
        assert_eq!(run.outcome.exit_code, 5, "{status}: {}", run.stderr());
        assert_eq!(run.json()["status"], expected, "{status}");
        assert!(!run.stdout().contains("canary"));
    }
}

#[tokio::test]
async fn a_late_finished_read_does_not_say_the_service_is_still_running() {
    let harness = signed_in().await;
    Mock::given(method("GET"))
        .and(path(operation_path(ESTIMATE)))
        .respond_with(LateAnswer {
            status: 200,
            body: fixture_value(&harness, "operation-estimate-succeeded.json"),
            clock: harness.clock.clone(),
        })
        .mount(&harness.graph)
        .await;
    let run = harness
        .run(&[
            "operation",
            "get",
            CASE,
            ESTIMATE,
            "--wait",
            "--wait-timeout",
            "1s",
        ])
        .await;
    assert_eq!(run.outcome.exit_code, 5);
    assert!(
        run.stderr()
            .starts_with("stopped waiting after 5s. Operation"),
        "{}",
        run.stderr()
    );
    assert!(run.stderr().contains("was succeeded"), "{}", run.stderr());
}

#[tokio::test]
async fn progress_lines_redact_graph_s_text() {
    let harness = signed_in().await;
    let mut running = fixture_value(&harness, "operation-estimate-running.json");
    running["action"] = json!("https://graph.example/x?sig=canary-sig-0006");
    Mock::given(method("GET"))
        .and(path(operation_path(ESTIMATE)))
        .respond_with(json_response(200, running))
        .up_to_n_times(1)
        .with_priority(1)
        .mount(&harness.graph)
        .await;
    mount(
        &harness,
        &operation_path(ESTIMATE),
        200,
        "operation-estimate-succeeded.json",
    )
    .await;
    let run = harness
        .run_with(&["operation", "get", CASE, ESTIMATE, "--wait"], |env, _| {
            env.stderr_is_terminal = true;
        })
        .await;
    assert_eq!(run.outcome.exit_code, 0, "{}", run.stderr());
    assert!(run.stderr().contains("sig=REDACTED"), "{}", run.stderr());
    assert!(!run.stderr().contains("canary"));
}

#[tokio::test]
async fn a_read_of_another_operation_fails_without_wait_too() {
    let harness = signed_in().await;
    let mut other = fixture_value(&harness, "operation-estimate-succeeded.json");
    other["id"] = json!("aaaaaaaaaaaaaaaaaaaaaaaaaaaa0009");
    Mock::given(method("GET"))
        .and(path(operation_path(ESTIMATE)))
        .respond_with(json_response(200, other))
        .mount(&harness.graph)
        .await;
    let run = harness
        .run(&["--json", "operation", "get", CASE, ESTIMATE])
        .await;
    assert_eq!(run.outcome.exit_code, 1);
    assert!(run.json()["error"]["message"]
        .as_str()
        .unwrap()
        .contains("with operation aaaaaaaaaaaaaaaaaaaaaaaaaaaa0009"));
}

#[tokio::test]
async fn a_url_cut_short_in_the_query_column_keeps_the_width() {
    let harness = signed_in().await;
    let mut body = fixture_value(&harness, "searches-list.json");
    body["value"][0]["contentQuery"] = json!(format!(
        "{} https://contoso.example/aaaaaaaaaaaaaaaaaaaa",
        "x".repeat(60)
    ));
    Mock::given(method("GET"))
        .and(path(case_path("/searches")))
        .respond_with(json_response(200, body))
        .mount(&harness.graph)
        .await;
    let run = harness
        .run(&["--plain", "--select", "QUERY", "search", "list", CASE])
        .await;
    let first = run.stdout().lines().next().unwrap().to_owned();
    assert_eq!(first.chars().count(), 80, "{first}");
    assert!(first.ends_with('…'), "{first}");
}

#[tokio::test]
async fn a_failed_resolve_read_with_trace_and_verbose_leaks_no_secret() {
    let harness = signed_in().await;
    mount(
        &harness,
        &case_path("/operations"),
        200,
        "operations-list.json",
    )
    .await;
    Mock::given(method("GET"))
        .and(path(operation_path("aaaaaaaaaaaaaaaaaaaaaaaaaaaa0002")))
        .respond_with(json_response(
            403,
            json!({"error": {
                "code": "Forbidden",
                "message": "see https://graph.example/x?sig=canary-sig-0007",
            }}),
        ))
        .mount(&harness.graph)
        .await;
    for id in ["0001", "0003", "0004"] {
        let mut body = signed(&harness, "operation-estimate-succeeded.json");
        body["id"] = json!(format!("aaaaaaaaaaaaaaaaaaaaaaaaaaaa{id}"));
        Mock::given(method("GET"))
            .and(path(operation_path(&format!(
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaa{id}"
            ))))
            .respond_with(json_response(200, body))
            .mount(&harness.graph)
            .await;
    }
    let trace = harness.root.path().join("trace-resolve");
    let trace_arg = trace.display().to_string();
    for json in [true, false] {
        let mut argv = vec!["--verbose", "--trace", &trace_arg];
        if json {
            argv.push("--json");
        }
        argv.extend_from_slice(&["operation", "list", CASE, "--resolve"]);
        let run = harness.run(&argv).await;
        assert_eq!(run.outcome.exit_code, 1, "{}", run.stderr());
        let mut values: Vec<&str> = CANARIES.to_vec();
        values.extend(["canary-sig-0001", "canary-sig-0002", "canary-sig-0007"]);
        harness.assert_absent(&run, &values);
    }
}
