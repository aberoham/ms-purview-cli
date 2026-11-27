//! In-process flows of `case create` and `search create` through
//! `cli::execute_with` (`docs/SPEC.md` section 8.5, flows 1, 2 and 7),
//! against a wiremock Graph and identity platform that record every
//! request, an in-memory credential store and a manual clock.

mod support;

use std::time::Duration;

use serde_json::{json, Value};
use support::*;
use wiremock::matchers::{method, path};
use wiremock::{Mock, Request, ResponseTemplate};

const CASES: &str = "/v1.0/security/cases/ediscoveryCases";
const CASE: &str = "00000000-0000-4000-8000-000000000031";
const NEW_CASE: &str = "00000000-0000-4000-8000-000000000041";
const NEW_SEARCH: &str = "00000000-0000-4000-8000-000000000061";
/// The default case name for `--topic "Orders review"` at the harness's
/// clock, 2026-01-05.
const CASE_NAME: &str = "Records research - Orders review 2026-01";
const CASE_DESCRIPTION: &str = "Requested by alex.wilber@contoso.example. Tenant-wide mailbox \
                                search with no custodians or holds. [created-by:purview-cli]";
const QUERY: &str = "\"orders-api\" AND participants:alex@contoso.example";

fn searches_path() -> String {
    format!("{CASES}/{CASE}/searches")
}

async fn signed_in() -> Harness {
    let harness = Harness::new().await;
    sign_in_alex(&harness).await;
    harness
}

fn page(items: Vec<Value>) -> Value {
    json!({ "value": items })
}

fn case(id: &str, name: &str, status: &str) -> Value {
    json!({
        "id": id,
        "displayName": name,
        "status": status,
        "createdDateTime": "2025-06-15T09:00:00Z",
    })
}

fn search(id: &str, name: &str) -> Value {
    json!({
        "id": id,
        "displayName": name,
        "contentQuery": "\"supplier-contract\"",
        "dataSourceScopes": "allTenantMailboxes",
        "createdDateTime": "2026-01-02T10:20:00Z",
    })
}

async fn mount_get(harness: &Harness, at: &str, body: Value) {
    Mock::given(method("GET"))
        .and(path(at))
        .respond_with(json_response(200, body))
        .mount(&harness.graph)
        .await;
}

/// A GET that answers `first` once, then `later`: a list before and after
/// a write.
async fn mount_get_then(harness: &Harness, at: &str, first: Value, later: Value) {
    Mock::given(method("GET"))
        .and(path(at))
        .respond_with(json_response(200, first))
        .up_to_n_times(1)
        .with_priority(1)
        .mount(&harness.graph)
        .await;
    Mock::given(method("GET"))
        .and(path(at))
        .respond_with(json_response(200, later))
        .with_priority(2)
        .mount(&harness.graph)
        .await;
}

async fn mount_post(harness: &Harness, at: &str, response: ResponseTemplate) {
    Mock::given(method("POST"))
        .and(path(at))
        .respond_with(response)
        .mount(&harness.graph)
        .await;
}

fn created_case() -> ResponseTemplate {
    json_response(201, {
        let mut record = case(NEW_CASE, CASE_NAME, "active");
        record["description"] = json!(CASE_DESCRIPTION);
        record
    })
}

fn created_search(query: &str) -> ResponseTemplate {
    json_response(
        201,
        json!({
            "id": NEW_SEARCH,
            "displayName": "orders-api-mail",
            "contentQuery": query,
            "dataSourceScopes": "allTenantMailboxes",
        }),
    )
}

async fn graph_requests(harness: &Harness) -> Vec<Request> {
    harness.graph.received_requests().await.unwrap_or_default()
}

/// The Graph requests that were not GETs.
async fn writes(harness: &Harness) -> Vec<Request> {
    graph_requests(harness)
        .await
        .into_iter()
        .filter(|request| request.method.as_str() != "GET")
        .collect()
}

fn case_create(extra: &[&'static str]) -> Vec<&'static str> {
    let mut args = vec!["case", "create", "--topic", "Orders review"];
    args.extend_from_slice(extra);
    args
}

fn search_create(extra: &[&'static str]) -> Vec<&'static str> {
    let mut args = vec![
        "search",
        "create",
        CASE,
        "--name",
        "orders-api-mail",
        "--term",
        "orders-api",
        "--participant",
        "alex@contoso.example",
    ];
    args.extend_from_slice(extra);
    args
}

/// Writes `naming` into config.json, keeping the rest.
fn set_naming(harness: &Harness, naming: Value) {
    let file = harness.config_dir().join("config.json");
    let mut config = harness.config();
    config["naming"] = naming;
    std::fs::write(&file, serde_json::to_vec_pretty(&config).unwrap()).unwrap();
}

// Flow 1: case create.

#[tokio::test]
async fn case_create_with_yes_sends_the_planned_body_once() {
    let harness = signed_in().await;
    mount_get(
        &harness,
        CASES,
        page(vec![case(
            CASE,
            "Records research - Orders review 2025-12",
            "active",
        )]),
    )
    .await;
    mount_post(&harness, CASES, created_case()).await;
    let run = harness.run(&case_create(&["--json", "--yes"])).await;
    assert_eq!(run.outcome.exit_code, 0, "{}", run.stderr());
    let posts = writes(&harness).await;
    assert_eq!(posts.len(), 1);
    assert_eq!(posts[0].method.as_str(), "POST");
    assert_eq!(posts[0].url.path(), CASES);
    let expected =
        format!("{{\"description\":\"{CASE_DESCRIPTION}\",\"displayName\":\"{CASE_NAME}\"}}");
    assert_eq!(String::from_utf8_lossy(&posts[0].body), expected);
    let document = run.json();
    let results = &document["results"];
    assert_eq!(results["applied"], true);
    assert_eq!(results["plan"]["command"], "case create");
    assert_eq!(results["plan"]["path"], "/security/cases/ediscoveryCases");
    assert_eq!(results["plan"]["body"]["displayName"], CASE_NAME);
    assert_eq!(
        results["plan"]["digest"],
        sha256_hex(&format!(
            "POST\n/security/cases/ediscoveryCases\n{expected}"
        ))
    );
    assert_eq!(results["result"]["id"], NEW_CASE);
    assert_eq!(results["result"]["status"], "active");
    assert!(run.stderr().is_empty(), "{}", run.stderr());
}

fn sha256_hex(text: &str) -> String {
    use sha2::{Digest, Sha256};
    Sha256::digest(text.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[tokio::test]
async fn case_create_without_yes_exits_3_and_sends_nothing() {
    let harness = signed_in().await;
    mount_get(&harness, CASES, page(vec![])).await;
    mount_post(&harness, CASES, created_case()).await;
    let run = harness.run(&case_create(&["--json"])).await;
    assert_eq!(run.outcome.exit_code, 3, "{}", run.stdout());
    let document = run.json();
    assert_eq!(document["error"]["code"], "ConfirmationRequired");
    assert_eq!(document["plan"]["body"]["displayName"], CASE_NAME);
    assert_eq!(
        document["plan"]["preflight"][0],
        "cases listed: 0; none has this name"
    );
    assert!(writes(&harness).await.is_empty());
}

#[tokio::test]
async fn case_create_dry_run_plans_without_sending() {
    let harness = signed_in().await;
    mount_get(&harness, CASES, page(vec![])).await;
    mount_post(&harness, CASES, created_case()).await;
    let run = harness.run(&case_create(&["--dry-run", "--yes"])).await;
    assert_eq!(run.outcome.exit_code, 0, "{}", run.stderr());
    let text = run.stdout();
    assert!(text.contains("Plan: purview case create"), "{text}");
    assert!(text.contains(CASE_NAME), "{text}");
    assert!(
        text.contains("Adds no custodians, data sources or holds."),
        "{text}"
    );
    assert!(text.ends_with("Dry run: nothing was sent.\n"), "{text}");
    assert!(writes(&harness).await.is_empty());
}

#[tokio::test]
async fn a_name_used_by_a_closed_case_is_refused_with_ids_not_the_name() {
    let harness = signed_in().await;
    mount_get(
        &harness,
        CASES,
        page(vec![
            case(CASE, CASE_NAME, "closed"),
            case(NEW_CASE, "Another case", "active"),
        ]),
    )
    .await;
    mount_post(&harness, CASES, created_case()).await;
    for extra in [
        &["--json", "--yes"][..],
        &["--json", "--yes", "--reuse-existing"],
    ] {
        let run = harness.run(&case_create(extra)).await;
        assert_eq!(run.outcome.exit_code, 1, "{extra:?}");
        let error = &run.json()["error"];
        assert_eq!(error["code"], "CaseNameInUse", "{extra:?}");
        let message = error["message"].as_str().unwrap();
        assert!(message.contains(&format!("{CASE} (closed")), "{message}");
        assert!(!message.contains("Orders review"), "{message}");
        assert!(!message.contains(NEW_CASE), "{message}");
    }
    assert!(writes(&harness).await.is_empty());
}

#[tokio::test]
async fn one_active_case_with_the_name_is_reused_only_when_asked() {
    let harness = signed_in().await;
    mount_get(&harness, CASES, page(vec![case(CASE, CASE_NAME, "active")])).await;
    mount_post(&harness, CASES, created_case()).await;
    let run = harness.run(&case_create(&["--json", "--yes"])).await;
    assert_eq!(run.outcome.exit_code, 1);
    let message = run.json()["error"]["message"].as_str().unwrap().to_owned();
    assert_eq!(run.json()["error"]["code"], "CaseNameInUse");
    assert!(message.contains("--reuse-existing"), "{message}");

    let run = harness
        .run(&case_create(&["--json", "--yes", "--reuse-existing"]))
        .await;
    assert_eq!(run.outcome.exit_code, 0, "{}", run.stderr());
    let results = &run.json()["results"];
    assert_eq!(results["applied"], false);
    assert_eq!(results["reused"], true);
    assert_eq!(results["plan"], Value::Null);
    assert_eq!(results["result"]["id"], CASE);

    let run = harness.run(&case_create(&["--reuse-existing"])).await;
    assert_eq!(run.outcome.exit_code, 0, "{}", run.stderr());
    assert!(
        run.stdout().starts_with(&format!(
            "Reused: case {CASE} is active and has the name; nothing was sent.\n"
        )),
        "{}",
        run.stdout()
    );
    assert!(writes(&harness).await.is_empty());
}

#[tokio::test]
async fn two_cases_with_the_name_are_refused_even_with_reuse() {
    let harness = signed_in().await;
    mount_get(
        &harness,
        CASES,
        page(vec![
            case(CASE, CASE_NAME, "active"),
            case(NEW_CASE, CASE_NAME, "active"),
        ]),
    )
    .await;
    let run = harness
        .run(&case_create(&["--json", "--yes", "--reuse-existing"]))
        .await;
    assert_eq!(run.outcome.exit_code, 1);
    let error = &run.json()["error"];
    assert_eq!(error["code"], "CaseNameInUse");
    let message = error["message"].as_str().unwrap();
    assert!(message.starts_with("2 cases"), "{message}");
    assert!(
        message.contains(CASE) && message.contains(NEW_CASE),
        "{message}"
    );
    assert!(writes(&harness).await.is_empty());
}

#[tokio::test]
async fn a_case_list_that_does_not_reach_its_last_page_refuses() {
    let harness = signed_in().await;
    let next = format!("{}{CASES}?$skiptoken=2", harness.graph.uri());
    Mock::given(method("GET"))
        .and(path(CASES))
        .and(wiremock::matchers::query_param("$skiptoken", "2"))
        .respond_with(json_response(
            500,
            json!({"error": {"code": "InternalServerError"}}),
        ))
        .with_priority(1)
        .mount(&harness.graph)
        .await;
    mount_get(
        &harness,
        CASES,
        json!({"value": [], "@odata.nextLink": next}),
    )
    .await;
    mount_post(&harness, CASES, created_case()).await;
    let run = harness.run(&case_create(&["--json", "--yes"])).await;
    assert_eq!(run.outcome.exit_code, 1);
    assert!(writes(&harness).await.is_empty());
}

#[tokio::test]
async fn overrides_keep_the_marker_and_the_requester_is_used() {
    let harness = signed_in().await;
    mount_get(&harness, CASES, page(vec![])).await;
    let run = harness
        .run(&case_create(&["--json", "--requester", "Legal team"]))
        .await;
    assert_eq!(run.outcome.exit_code, 3);
    assert_eq!(
        run.json()["plan"]["body"]["description"],
        "Requested by Legal team. Tenant-wide mailbox search with no custodians or holds. \
         [created-by:purview-cli]"
    );
    let run = harness
        .run(&case_create(&[
            "--json",
            "--name",
            "  Orders review  ",
            "--description",
            "For the orders audit",
        ]))
        .await;
    assert_eq!(run.outcome.exit_code, 3);
    let body = &run.json()["plan"]["body"];
    assert_eq!(body["displayName"], "Orders review");
    assert_eq!(
        body["description"],
        "For the orders audit [created-by:purview-cli]"
    );
}

#[tokio::test]
async fn a_template_that_cannot_render_fails_before_any_request() {
    let harness = signed_in().await;
    set_naming(&harness, json!({"case_name": "Case {query_summary}"}));
    let run = harness.run(&case_create(&["--json", "--yes"])).await;
    assert_eq!(run.outcome.exit_code, 1);
    let message = run.json()["error"]["message"].as_str().unwrap().to_owned();
    assert!(message.contains("naming.case_name"), "{message}");
    assert!(graph_requests(&harness).await.is_empty());
}

#[tokio::test]
async fn an_answer_that_differs_from_the_observed_one_is_a_warning() {
    let harness = signed_in().await;
    mount_get(&harness, CASES, page(vec![])).await;
    mount_post(
        &harness,
        CASES,
        json_response(200, case(NEW_CASE, CASE_NAME, "closing")),
    )
    .await;
    let run = harness.run(&case_create(&["--json", "--yes"])).await;
    assert_eq!(run.outcome.exit_code, 0, "{}", run.stderr());
    let stderr = run.stderr();
    assert!(
        stderr.contains("HTTP 200, where 201 was observed"),
        "{stderr}"
    );
    assert!(stderr.contains("status is closing"), "{stderr}");
}

// Flow 2: search create.

#[tokio::test]
async fn a_guard_refusal_sends_no_request() {
    let harness = signed_in().await;
    let run = harness
        .run(&[
            "--json",
            "--yes",
            "search",
            "create",
            CASE,
            "--name",
            "n",
            "--term",
            "retention",
        ])
        .await;
    assert_eq!(run.outcome.exit_code, 1);
    assert_eq!(run.json()["error"]["code"], "GenericQuery");
    assert!(graph_requests(&harness).await.is_empty());
    assert!(harness
        .identity
        .received_requests()
        .await
        .unwrap_or_default()
        .is_empty());
}

async fn ready_for_search(post: ResponseTemplate) -> Harness {
    let harness = signed_in().await;
    mount_get(
        &harness,
        &format!("{CASES}/{CASE}"),
        graph_fixture("case-get.json", &harness.graph.uri()),
    )
    .await;
    mount_get(
        &harness,
        &searches_path(),
        page(vec![search(
            "00000000-0000-4000-8000-000000000051",
            "Other",
        )]),
    )
    .await;
    mount_post(&harness, &searches_path(), post).await;
    harness
}

#[tokio::test]
async fn search_create_sends_one_post_to_the_searches_path_only() {
    let harness = ready_for_search(created_search(QUERY)).await;
    let run = harness.run(&search_create(&["--json", "--yes"])).await;
    assert_eq!(run.outcome.exit_code, 0, "{}", run.stderr());
    assert!(run.stderr().is_empty(), "{}", run.stderr());
    let requests = graph_requests(&harness).await;
    let writes: Vec<&Request> = requests
        .iter()
        .filter(|request| request.method.as_str() != "GET")
        .collect();
    assert_eq!(writes.len(), 1);
    assert_eq!(writes[0].method.as_str(), "POST");
    assert_eq!(writes[0].url.path(), searches_path());
    for request in &requests {
        let at = request.url.path().to_ascii_lowercase();
        for part in ["custodian", "noncustodial", "legalhold", "sources"] {
            assert!(!at.contains(part), "{} {at}", request.method);
        }
    }
    let expected = format!(
        "{{\"contentQuery\":{},\"dataSourceScopes\":\"allTenantMailboxes\",\"description\":{},\
         \"displayName\":\"orders-api-mail\"}}",
        serde_json::to_string(QUERY).unwrap(),
        serde_json::to_string(&format!("{QUERY} [created-by:purview-cli]")).unwrap(),
    );
    assert_eq!(String::from_utf8_lossy(&writes[0].body), expected);
    let results = &run.json()["results"];
    assert_eq!(results["applied"], true);
    assert_eq!(results["result"]["id"], NEW_SEARCH);
    let preflight = &results["plan"]["preflight"];
    assert_eq!(preflight[0], format!("case {CASE}: active"));
    assert_eq!(preflight[2], "guard: the query is narrowed");
}

#[tokio::test]
async fn search_create_without_yes_exits_3_and_sends_nothing() {
    let harness = ready_for_search(created_search(QUERY)).await;
    let run = harness.run(&search_create(&["--json"])).await;
    assert_eq!(run.outcome.exit_code, 3);
    assert_eq!(run.json()["plan"]["body"]["contentQuery"], QUERY);
    assert!(writes(&harness).await.is_empty());
}

#[tokio::test]
async fn a_search_name_in_use_is_refused() {
    let harness = signed_in().await;
    mount_get(
        &harness,
        &format!("{CASES}/{CASE}"),
        graph_fixture("case-get.json", &harness.graph.uri()),
    )
    .await;
    mount_get(
        &harness,
        &searches_path(),
        page(vec![search(
            "00000000-0000-4000-8000-000000000051",
            "orders-api-mail",
        )]),
    )
    .await;
    let run = harness.run(&search_create(&["--json", "--yes"])).await;
    assert_eq!(run.outcome.exit_code, 1);
    let error = &run.json()["error"];
    assert_eq!(error["code"], "SearchNameInUse");
    let message = error["message"].as_str().unwrap();
    assert!(
        message.contains("00000000-0000-4000-8000-000000000051"),
        "{message}"
    );
    assert!(!message.contains("orders-api-mail"), "{message}");
    assert!(writes(&harness).await.is_empty());
}

#[tokio::test]
async fn a_case_that_is_not_active_is_refused() {
    let harness = signed_in().await;
    mount_get(
        &harness,
        &format!("{CASES}/{CASE}"),
        case(CASE, "Closed case", "closed"),
    )
    .await;
    mount_get(&harness, &searches_path(), page(vec![])).await;
    let run = harness.run(&search_create(&["--json", "--yes"])).await;
    assert_eq!(run.outcome.exit_code, 1);
    assert_eq!(run.json()["error"]["code"], "CaseNotActive");
    assert!(writes(&harness).await.is_empty());
}

#[tokio::test]
async fn a_case_named_by_its_display_name_is_resolved() {
    let harness = ready_for_search(created_search(QUERY)).await;
    mount_get(
        &harness,
        CASES,
        graph_fixture("cases-list.json", &harness.graph.uri()),
    )
    .await;
    let mut args = search_create(&["--json"]);
    args[2] = "Records research - Orders review";
    let run = harness.run(&args).await;
    assert_eq!(run.outcome.exit_code, 3, "{}", run.stdout());
    assert_eq!(
        run.json()["plan"]["path"],
        format!("/security/cases/ediscoveryCases/{CASE}/searches")
    );
    assert_eq!(
        run.stderr(),
        format!("notice: matched case {CASE} by its display name\n")
    );
}

#[tokio::test]
async fn an_override_records_its_reason_and_warns() {
    let harness = ready_for_search(created_search("retention")).await;
    let run = harness
        .run(&[
            "--json",
            "search",
            "create",
            CASE,
            "--name",
            "orders-api-mail",
            "--term",
            "retention",
            "--allow-generic",
            "--reason",
            "Legal asked for every mention",
        ])
        .await;
    assert_eq!(run.outcome.exit_code, 3, "{}", run.stdout());
    let plan = &run.json()["plan"];
    assert_eq!(
        plan["body"]["description"],
        "\"retention\" [created-by:purview-cli] Guard overridden with --allow-generic: Legal \
         asked for every mention"
    );
    assert!(plan["warnings"][0]
        .as_str()
        .unwrap()
        .contains("--allow-generic overrides it"));
    assert_eq!(
        plan["preflight"][2],
        "guard: the query is not narrowed; overridden with --allow-generic"
    );
}

#[tokio::test]
async fn an_echoed_query_that_differs_is_a_warning() {
    let harness = ready_for_search(created_search("\"orders-api\"")).await;
    let run = harness.run(&search_create(&["--json", "--yes"])).await;
    assert_eq!(run.outcome.exit_code, 0, "{}", run.stderr());
    let stderr = run.stderr();
    assert!(
        stderr.contains("has a contentQuery that differs from the one sent"),
        "{stderr}"
    );
    assert!(!stderr.contains("orders-api"), "{stderr}");
    assert!(!stderr.contains("dataSourceScopes"), "{stderr}");
}

// Flow 7: unclear outcomes.

fn unclear_answers() -> Vec<(&'static str, ResponseTemplate, &'static [&'static str])> {
    vec![
        (
            "timeout",
            created_case().set_delay(Duration::from_secs(3)),
            &["--timeout", "1"],
        ),
        (
            "503",
            json_response(503, fixture("../graph/error-503-retry-after-date.json"))
                .insert_header("Retry-After", "1"),
            &[],
        ),
        (
            "429",
            json_response(429, json!({"error": {"code": "TooManyRequests"}}))
                .insert_header("Retry-After", "1"),
            &[],
        ),
    ]
}

#[tokio::test]
async fn an_unclear_case_create_is_sent_once_and_lists_candidates() {
    for (label, answer, extra) in unclear_answers() {
        let harness = signed_in().await;
        mount_get_then(
            &harness,
            CASES,
            page(vec![]),
            page(vec![
                case(NEW_CASE, CASE_NAME, "active"),
                case(CASE, "Another case", "active"),
            ]),
        )
        .await;
        mount_post(&harness, CASES, answer).await;
        let mut args = vec!["--json", "--yes"];
        args.extend_from_slice(extra);
        args.extend(case_create(&[]));
        let run = harness.run(&args).await;
        assert_eq!(run.outcome.exit_code, 1, "{label}");
        let error = &run.json()["error"];
        assert_eq!(error["code"], "WriteOutcomeUnknown", "{label}");
        let message = error["message"].as_str().unwrap();
        assert!(
            message.contains(&format!("case {NEW_CASE} (active")),
            "{label}: {message}"
        );
        assert!(!message.contains(CASE), "{label}: {message}");
        assert!(!message.contains("Orders review"), "{label}: {message}");
        assert_eq!(writes(&harness).await.len(), 1, "{label}");
        // The preflight list, then the reconciliation list.
        let gets = graph_requests(&harness)
            .await
            .iter()
            .filter(|request| request.method.as_str() == "GET")
            .count();
        assert_eq!(gets, 2, "{label}");
    }
}

#[tokio::test]
async fn an_unclear_search_create_is_sent_once_and_lists_candidates() {
    for (label, answer, extra) in unclear_answers() {
        let harness = signed_in().await;
        mount_get(
            &harness,
            &format!("{CASES}/{CASE}"),
            graph_fixture("case-get.json", &harness.graph.uri()),
        )
        .await;
        mount_get_then(
            &harness,
            &searches_path(),
            page(vec![]),
            page(vec![search(NEW_SEARCH, "orders-api-mail")]),
        )
        .await;
        mount_post(&harness, &searches_path(), answer).await;
        let mut args = vec!["--json", "--yes"];
        args.extend_from_slice(extra);
        args.extend(search_create(&[]));
        let run = harness.run(&args).await;
        assert_eq!(run.outcome.exit_code, 1, "{label}");
        let error = &run.json()["error"];
        assert_eq!(error["code"], "WriteOutcomeUnknown", "{label}");
        let message = error["message"].as_str().unwrap();
        assert!(
            message.contains(&format!(
                "search {NEW_SEARCH} (created 2026-01-02) in case {CASE}"
            )),
            "{label}: {message}"
        );
        assert!(!message.contains("orders-api-mail"), "{label}: {message}");
        assert_eq!(writes(&harness).await.len(), 1, "{label}");
    }
}

#[tokio::test]
async fn an_unclear_outcome_with_nothing_listed_says_so() {
    let harness = signed_in().await;
    mount_get(&harness, CASES, page(vec![])).await;
    mount_post(
        &harness,
        CASES,
        json_response(503, json!({"error": {"code": "ServiceUnavailable"}})),
    )
    .await;
    let run = harness.run(&case_create(&["--json", "--yes"])).await;
    assert_eq!(run.outcome.exit_code, 1);
    let message = run.json()["error"]["message"].as_str().unwrap().to_owned();
    assert!(
        message.contains("no case with the name was listed"),
        "{message}"
    );
    assert_eq!(writes(&harness).await.len(), 1);
}

#[tokio::test]
async fn an_answer_without_an_id_or_with_another_scope_is_a_warning() {
    let harness = ready_for_search(json_response(
        201,
        json!({
            "displayName": "orders-api-mail",
            "contentQuery": QUERY,
            "dataSourceScopes": "allTenantMailboxes,allTenantSites",
        }),
    ))
    .await;
    let run = harness.run(&search_create(&["--json", "--yes"])).await;
    assert_eq!(run.outcome.exit_code, 0, "{}", run.stderr());
    let stderr = run.stderr();
    assert!(
        stderr.contains("has a dataSourceScopes that differs from the one sent"),
        "{stderr}"
    );
    assert!(stderr.contains("no valid search id"), "{stderr}");
    assert!(!stderr.contains("contentQuery"), "{stderr}");
}

#[tokio::test]
async fn a_case_answer_without_an_id_is_a_warning() {
    let harness = signed_in().await;
    mount_get(&harness, CASES, page(vec![])).await;
    mount_post(
        &harness,
        CASES,
        json_response(201, json!({"displayName": CASE_NAME, "status": "active"})),
    )
    .await;
    let run = harness.run(&case_create(&["--json", "--yes"])).await;
    assert_eq!(run.outcome.exit_code, 0, "{}", run.stderr());
    assert!(
        run.stderr().contains("no valid case id"),
        "{}",
        run.stderr()
    );
}

/// A list whose paging link repeats stops before its last page; the name
/// check cannot rely on it, so nothing is sent.
#[tokio::test]
async fn a_list_whose_paging_repeats_refuses_both_creates() {
    let harness = signed_in().await;
    let again = format!("{}{CASES}", harness.graph.uri());
    mount_get(
        &harness,
        CASES,
        json!({"value": [], "@odata.nextLink": again}),
    )
    .await;
    mount_post(&harness, CASES, created_case()).await;
    let run = harness.run(&case_create(&["--json", "--yes"])).await;
    assert_eq!(run.outcome.exit_code, 1, "{}", run.stdout());
    assert!(writes(&harness).await.is_empty());

    let harness = signed_in().await;
    mount_get(
        &harness,
        &format!("{CASES}/{CASE}"),
        graph_fixture("case-get.json", &harness.graph.uri()),
    )
    .await;
    let again = format!("{}{}", harness.graph.uri(), searches_path());
    mount_get(
        &harness,
        &searches_path(),
        json!({"value": [], "@odata.nextLink": again}),
    )
    .await;
    mount_post(&harness, &searches_path(), created_search(QUERY)).await;
    let run = harness.run(&search_create(&["--json", "--yes"])).await;
    assert_eq!(run.outcome.exit_code, 1, "{}", run.stdout());
    assert!(writes(&harness).await.is_empty());
}
