//! The safety framework of `docs/SPEC.md` section 6.2, through the write
//! runner, with a write command that exists only in this test: its
//! preflight reads a case, and its plan creates a search in it. No release
//! has a write command yet, so `cli::execute_write_with` runs this one with
//! the global options as a write subcommand would get them.
//!
//! Every request to the mock Graph and identity platform is recorded, so
//! each test can say exactly what was sent: no POST before approval, one
//! after it, and none at all when the write is refused before sign-in.

mod support;

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use ms_purview_cli::commands::Session;
use ms_purview_cli::env::{Env, ScriptedInput};
use ms_purview_cli::error::{PurviewError, Result};
use ms_purview_cli::graph::WriteResponse;
use ms_purview_cli::routes::{CaseId, Query, ReadRoute, WriteRoute};
use ms_purview_cli::safety::{self, PlanInput, WriteCommand, WritePlan};
use ms_purview_cli::secrets::store_value;
use serde_json::{json, Value};
use support::*;
use wiremock::matchers::{method, path};
use wiremock::{Mock, Request, ResponseTemplate};

const CASE: &str = "00000000-0000-4000-8000-000000000031";
const SEARCHES: &str =
    "/v1.0/security/cases/ediscoveryCases/00000000-0000-4000-8000-000000000031/searches";

/// A write that exists only here.
struct StubWrite {
    refuse_check: bool,
    /// An account or tenant for the plan other than the signed-in one, set
    /// on the session too, as a command that changed it would.
    plan_account: Option<&'static str>,
    plan_tenant: Option<&'static str>,
}

#[async_trait]
impl WriteCommand for StubWrite {
    fn check(&self) -> Result<()> {
        if self.refuse_check {
            return Err(PurviewError::message("the stub's own check refused"));
        }
        Ok(())
    }

    async fn plan(&mut self, session: &mut Session<'_>) -> Result<WritePlan> {
        if let Some(account) = self.plan_account {
            session.account.email = account.to_owned();
        }
        if let Some(tenant) = self.plan_tenant {
            session.account.tenant_id = tenant.to_owned();
        }
        let case = CaseId::parse(CASE).unwrap();
        let record = session
            .graph
            .get(
                &ReadRoute::Case(case),
                &Query::new(),
                &mut session.env.stderr,
            )
            .await?;
        WritePlan::new(PlanInput {
            command: "stub create",
            account: self
                .plan_account
                .map_or_else(|| session.account.email.clone(), str::to_owned),
            tenant: session.account.tenant_id.clone(),
            route: WriteRoute::CreateSearch(case),
            body: json!({
                "displayName": "Stub search",
                "contentQuery": "\"orders-api\"",
                "dataSourceScopes": "allTenantMailboxes",
            }),
            effects: vec!["Creates a search over all tenant mailboxes. Places no hold.".into()],
            warnings: Vec::new(),
            preflight: vec![json!({"case": record["status"]})],
        })
    }

    async fn applied(
        &mut self,
        _session: &mut Session<'_>,
        response: WriteResponse,
    ) -> Result<Value> {
        Ok(json!({
            "status": response.status,
            "id": response.body.as_ref().map(|body| body["id"].clone()),
        }))
    }

    async fn reconcile(&mut self, _session: &mut Session<'_>) -> Result<Vec<String>> {
        Ok(vec!["a search named Stub search".into()])
    }
}

fn stub() -> Box<dyn WriteCommand> {
    Box::new(StubWrite {
        refuse_check: false,
        plan_account: None,
        plan_tenant: None,
    })
}

async fn run(harness: &Harness, args: &[&str]) -> Run {
    run_with(harness, args, stub(), |_| {}).await
}

async fn run_with(
    harness: &Harness,
    args: &[&str],
    command: Box<dyn WriteCommand>,
    configure: impl FnOnce(&mut Env),
) -> Run {
    let (mut env, captured) = harness.env();
    configure(&mut env);
    let mut argv = vec!["purview"];
    argv.extend_from_slice(args);
    let outcome = tokio::time::timeout(
        Duration::from_secs(60),
        ms_purview_cli::cli::execute_write_with(env, argv, command),
    )
    .await
    .expect("the command finished within 60 seconds");
    Run { outcome, captured }
}

/// A signed-in harness whose Graph answers the preflight read and the
/// POST with `post`.
async fn ready(post: ResponseTemplate) -> Harness {
    let harness = Harness::new().await;
    sign_in_alex(&harness).await;
    Mock::given(method("GET"))
        .and(path(format!("/v1.0/security/cases/ediscoveryCases/{CASE}")))
        .respond_with(json_response(
            200,
            graph_fixture("case-get.json", &harness.graph.uri()),
        ))
        .mount(&harness.graph)
        .await;
    Mock::given(method("POST"))
        .and(path(SEARCHES))
        .respond_with(post)
        .mount(&harness.graph)
        .await;
    harness
}

fn created() -> ResponseTemplate {
    json_response(
        201,
        json!({"id": "00000000-0000-4000-8000-000000000051", "displayName": "Stub search"}),
    )
}

async fn requests(server: &wiremock::MockServer) -> Vec<Request> {
    server.received_requests().await.unwrap_or_default()
}

/// The Graph requests that were not GETs.
async fn writes(harness: &Harness) -> Vec<Request> {
    requests(&harness.graph)
        .await
        .into_iter()
        .filter(|request| request.method.as_str() != "GET")
        .collect()
}

async fn gets(harness: &Harness) -> usize {
    requests(&harness.graph)
        .await
        .iter()
        .filter(|request| request.method.as_str() == "GET")
        .count()
}

#[tokio::test]
async fn without_yes_and_without_a_terminal_nothing_is_sent_and_the_exit_is_3() {
    let harness = ready(created()).await;
    let run = run(&harness, &["--json"]).await;
    assert_eq!(run.outcome.exit_code, 3, "{}", run.stdout());
    let document = run.json();
    assert_eq!(document["applied"], false);
    assert_eq!(document["error"]["code"], "ConfirmationRequired");
    assert_eq!(document["error"]["status"], 0);
    assert_eq!(document["plan"]["command"], "stub create");
    assert_eq!(document["plan"]["method"], "POST");
    assert_eq!(document["plan"]["account"], ALEX);
    assert_eq!(document["plan"]["preflight"][0]["case"], "active");
    assert!(run.stderr().is_empty(), "{}", run.stderr());
    assert_eq!(gets(&harness).await, 1);
    assert!(writes(&harness).await.is_empty());
}

#[tokio::test]
async fn exit_3_prints_the_whole_document_even_with_results_only() {
    let harness = ready(created()).await;
    let run = run(&harness, &["--json", "--results-only", "--no-input"]).await;
    assert_eq!(run.outcome.exit_code, 3);
    let document = run.json();
    assert_eq!(document["error"]["code"], "ConfirmationRequired");
    assert!(document.get("plan").is_some());
    assert!(writes(&harness).await.is_empty());
}

#[tokio::test]
async fn exit_3_in_a_table_puts_the_plan_and_reason_on_stderr() {
    let harness = ready(created()).await;
    let run = run(&harness, &[]).await;
    assert_eq!(run.outcome.exit_code, 3);
    assert!(run.stdout().is_empty(), "{}", run.stdout());
    let stderr = run.stderr();
    assert!(
        stderr.starts_with("Plan: purview stub create\n"),
        "{stderr}"
    );
    assert!(stderr.contains("pass --yes"), "{stderr}");
    assert!(writes(&harness).await.is_empty());
}

#[tokio::test]
async fn a_dry_run_reads_plans_and_sends_no_write() {
    for args in [
        &["--json", "--dry-run"][..],
        &["--json", "--dry-run", "--yes"],
    ] {
        let harness = ready(created()).await;
        let run = run(&harness, args).await;
        assert_eq!(run.outcome.exit_code, 0, "{args:?}: {}", run.stdout());
        let results = &run.json()["results"];
        assert_eq!(results["applied"], false);
        assert_eq!(results["result"], Value::Null);
        assert_eq!(results["plan"]["command"], "stub create");
        assert_eq!(run.json()["count"], 1);
        assert_eq!(gets(&harness).await, 1, "{args:?}");
        assert!(writes(&harness).await.is_empty(), "{args:?}");
    }
}

#[tokio::test]
async fn a_dry_run_in_a_table_prints_the_plan_on_stdout() {
    let harness = ready(created()).await;
    let run = run(&harness, &["--dry-run"]).await;
    assert_eq!(run.outcome.exit_code, 0);
    let stdout = run.stdout();
    assert!(
        stdout.starts_with("Plan: purview stub create\n"),
        "{stdout}"
    );
    assert!(
        stdout.contains(&format!("request: POST {}", &SEARCHES[5..])),
        "{stdout}"
    );
    assert!(stdout.ends_with("Dry run: nothing was sent.\n"), "{stdout}");
    assert!(writes(&harness).await.is_empty());
}

#[tokio::test]
async fn yes_sends_exactly_the_planned_bytes_once() {
    let harness = ready(created()).await;
    let run = run(&harness, &["--json", "--yes"]).await;
    assert_eq!(run.outcome.exit_code, 0, "{}", run.stdout());
    let results = &run.json()["results"];
    assert_eq!(results["applied"], true);
    assert_eq!(results["result"]["status"], 201);
    assert_eq!(
        results["result"]["id"],
        "00000000-0000-4000-8000-000000000051"
    );
    let sent = writes(&harness).await;
    assert_eq!(sent.len(), 1);
    let request = &sent[0];
    assert_eq!(request.method.as_str(), "POST");
    assert_eq!(request.url.path(), SEARCHES);
    assert_eq!(
        request.headers.get("content-type").unwrap(),
        "application/json"
    );
    let plan = &results["plan"];
    assert_eq!(
        serde_json::from_slice::<Value>(&request.body).unwrap(),
        plan["body"]
    );
    // The digest in the plan is the digest of what arrived.
    assert_eq!(
        plan["digest"],
        safety::digest("POST", plan["path"].as_str().unwrap(), &request.body)
    );
    assert!(run.stderr().is_empty(), "{}", run.stderr());
    // The preflight GET came first.
    let all = requests(&harness.graph).await;
    assert_eq!(all.len(), 2);
    assert_eq!(all[0].method.as_str(), "GET");
}

#[tokio::test]
async fn results_only_prints_the_inner_object_after_a_write() {
    let harness = ready(created()).await;
    let run = run(&harness, &["--json", "--yes", "--results-only"]).await;
    assert_eq!(run.outcome.exit_code, 0);
    let document = run.json();
    assert_eq!(document["applied"], true);
    assert!(document.get("results").is_none());
}

#[tokio::test]
async fn yes_in_a_table_shows_the_plan_and_what_was_applied() {
    let harness = ready(created()).await;
    let run = run(&harness, &["--yes"]).await;
    assert_eq!(run.outcome.exit_code, 0, "{}", run.stderr());
    assert!(run.stderr().starts_with("Plan: purview stub create\n"));
    assert!(run.stdout().starts_with("Applied: purview stub create\n"));
    assert_eq!(writes(&harness).await.len(), 1);
}

#[tokio::test]
async fn purview_yes_approves_like_the_flag() {
    let harness = ready(created()).await;
    let run = run_with(&harness, &["--json"], stub(), |env| {
        env.vars.insert("PURVIEW_YES".into(), "true".into());
    })
    .await;
    assert_eq!(run.outcome.exit_code, 0, "{}", run.stdout());
    assert_eq!(writes(&harness).await.len(), 1);
}

#[tokio::test]
async fn no_write_refuses_before_sign_in_whatever_else_is_given() {
    for (args, variable) in [
        (&["--json", "--yes", "--no-write"][..], None),
        (&["--json", "--yes"], Some(("PURVIEW_NO_WRITE", "true"))),
        (&["--json", "--dry-run", "--no-write"], None),
    ] {
        let harness = ready(created()).await;
        let identity_before = requests(&harness.identity).await.len();
        let run = run_with(&harness, args, stub(), |env| {
            if let Some((name, value)) = variable {
                env.vars.insert(name.into(), value.into());
            }
        })
        .await;
        assert_eq!(run.outcome.exit_code, 1, "{args:?}");
        assert_eq!(run.json()["error"]["code"], "WriteRefused", "{args:?}");
        assert!(requests(&harness.graph).await.is_empty(), "{args:?}");
        assert_eq!(requests(&harness.identity).await.len(), identity_before);
    }
}

#[tokio::test]
async fn the_commands_own_check_runs_before_sign_in() {
    let harness = Harness::new().await;
    let run = run_with(
        &harness,
        &["--json", "--yes"],
        Box::new(StubWrite {
            refuse_check: true,
            plan_account: None,
            plan_tenant: None,
        }),
        |_| {},
    )
    .await;
    assert_eq!(run.outcome.exit_code, 1);
    assert!(run.json()["error"]["message"]
        .as_str()
        .unwrap()
        .contains("the stub's own check refused"));
    assert!(requests(&harness.graph).await.is_empty());
    assert!(requests(&harness.identity).await.is_empty());
}

#[tokio::test]
async fn a_naming_template_with_an_unknown_variable_is_refused_before_sign_in() {
    let harness = ready(created()).await;
    let path = harness.config_dir().join("config.json");
    let mut config = harness.config();
    config["naming"] = json!({"case_name": "{nope}"});
    std::fs::write(&path, config.to_string()).unwrap();
    let run = run(&harness, &["--json", "--yes"]).await;
    assert_eq!(run.outcome.exit_code, 1);
    assert!(run.json()["error"]["message"]
        .as_str()
        .unwrap()
        .contains("naming.case_name"));
    assert!(requests(&harness.graph).await.is_empty());
}

/// Rewrites Alex's stored credential with `change`.
fn change_credential(harness: &Harness, change: impl FnOnce(&mut Value)) {
    let mut stored = harness.stored(ALEX).unwrap();
    change(&mut stored);
    store_value(
        harness.store.as_ref(),
        &format!("purview:token:{ALEX}"),
        &stored.to_string(),
    )
    .unwrap();
}

#[tokio::test]
async fn a_sign_in_records_whether_it_may_write() {
    let harness = Harness::new().await;
    sign_in_alex(&harness).await;
    let first = harness.stored(ALEX).unwrap();
    assert_eq!(first["access"], "read-write");
    let id = first["sign_in"].as_str().unwrap().to_owned();
    assert!(id.len() >= 16, "{id}");
    // Each sign-in gets its own id.
    sign_in_alex(&harness).await;
    assert_ne!(harness.stored(ALEX).unwrap()["sign_in"], id.as_str());
}

#[tokio::test]
async fn a_read_only_or_unrecorded_session_is_refused_before_any_request() {
    for access in [json!("read-only"), Value::Null, json!("admin"), json!(1)] {
        let harness = ready(created()).await;
        change_credential(&harness, |stored| {
            match &access {
                Value::Null => {
                    stored.as_object_mut().unwrap().remove("access");
                }
                value => stored["access"] = value.clone(),
            };
        });
        let identity_before = requests(&harness.identity).await.len();
        let refused = run(&harness, &["--json", "--yes"]).await;
        assert_eq!(refused.outcome.exit_code, 1, "{access}");
        assert_eq!(
            refused.json()["error"]["code"],
            "ReadOnlySession",
            "{access}"
        );
        assert!(requests(&harness.graph).await.is_empty(), "{access}");
        assert_eq!(requests(&harness.identity).await.len(), identity_before);
        // A dry run is a write command too.
        let dry = run(&harness, &["--json", "--dry-run"]).await;
        assert_eq!(dry.json()["error"]["code"], "ReadOnlySession", "{access}");
        // Reading still works.
        let read = harness.run(&["--json", "case", "get", CASE]).await;
        assert_eq!(read.outcome.exit_code, 0, "{access}: {}", read.stdout());
    }
}

#[tokio::test]
async fn a_read_write_record_without_the_read_write_permission_is_refused() {
    let harness = ready(created()).await;
    change_credential(&harness, |stored| {
        stored["graph"]["scope"] =
            "https://graph.microsoft.com/eDiscovery.Read.All openid profile".into();
    });
    let run = run(&harness, &["--json", "--yes"]).await;
    assert_eq!(run.json()["error"]["code"], "ReadOnlySession");
    assert!(run.json()["error"]["message"]
        .as_str()
        .unwrap()
        .contains("eDiscovery.ReadWrite.All"));
    assert!(requests(&harness.graph).await.is_empty());
}

#[tokio::test]
async fn a_read_only_sign_in_is_recorded_and_refused() {
    let harness = Harness::new().await;
    mount_login(
        &harness,
        "id-claims-preferred.json",
        json_response(200, fixture("token-download.json")),
    )
    .await;
    let login = harness
        .run(&[
            "auth",
            "login",
            "--read-only",
            "--client-id",
            CLIENT_ID,
            "--tenant-id",
            TENANT_ID,
        ])
        .await;
    assert_eq!(login.outcome.exit_code, 0, "{}", login.stderr());
    assert_eq!(harness.stored(ALEX).unwrap()["access"], "read-only");
    let run = run(&harness, &["--json", "--yes"]).await;
    assert_eq!(run.json()["error"]["code"], "ReadOnlySession");
    assert!(run.json()["error"]["message"]
        .as_str()
        .unwrap()
        .contains("--read-only"));
    assert!(requests(&harness.graph).await.is_empty());
}

#[tokio::test]
async fn a_dry_run_with_an_expired_token_refreshes_once_and_sends_no_write() {
    let harness = ready(created()).await;
    let scope = harness.stored(ALEX).unwrap()["graph"]["scope"]
        .as_str()
        .unwrap()
        .to_owned();
    Mock::given(method("POST"))
        .and(path(token_path("token")))
        .respond_with(json_response(
            200,
            token("canary-graph-access-0002", "canary-refresh-0002", &scope),
        ))
        .mount(&harness.identity)
        .await;
    harness.clock.advance(Duration::from_secs(5 * 3600));
    let run = run(&harness, &["--json", "--dry-run"]).await;
    assert_eq!(run.outcome.exit_code, 0, "{}", run.stdout());
    let refreshes = requests(&harness.identity).await;
    assert_eq!(refreshes.len(), 1);
    assert_eq!(refreshes[0].method.as_str(), "POST");
    assert!(refreshes[0].url.path().ends_with("/oauth2/v2.0/token"));
    // The refreshed credential still says it may write.
    let stored = harness.stored(ALEX).unwrap();
    assert_eq!(stored["graph"]["access_token"], "canary-graph-access-0002");
    assert_eq!(stored["access"], "read-write");
    assert!(writes(&harness).await.is_empty());
    assert_eq!(gets(&harness).await, 1);
}

async fn at_a_terminal(harness: &Harness, args: &[&str], answers: &[&str]) -> (Run, usize) {
    let input = Arc::new(ScriptedInput::new(answers));
    let reads = input.clone();
    let run = run_with(harness, args, stub(), move |env| {
        env.stdin_is_terminal = true;
        env.stderr_is_terminal = true;
        env.input = input;
    })
    .await;
    (run, reads.reads())
}

#[tokio::test]
async fn at_a_terminal_yes_sends_and_anything_else_declines() {
    let harness = ready(created()).await;
    let (run, reads) = at_a_terminal(&harness, &["--json"], &["y"]).await;
    assert_eq!(run.outcome.exit_code, 0, "{}", run.stdout());
    assert_eq!(reads, 1);
    assert!(run.stderr().ends_with("Apply? [y/N] "), "{}", run.stderr());
    assert_eq!(writes(&harness).await.len(), 1);

    for answers in [&["n"][..], &[""], &[]] {
        let harness = ready(created()).await;
        let (run, reads) = at_a_terminal(&harness, &["--json"], answers).await;
        assert_eq!(run.outcome.exit_code, 3, "{answers:?}");
        assert_eq!(run.json()["error"]["code"], "Declined");
        assert_eq!(reads, 1);
        assert!(writes(&harness).await.is_empty(), "{answers:?}");
    }
}

#[tokio::test]
async fn at_a_terminal_no_input_and_dry_run_never_ask() {
    for (args, code, exit) in [
        (
            &["--json", "--no-input"][..],
            Some("ConfirmationRequired"),
            3,
        ),
        (&["--json", "--dry-run"], None, 0),
        (&["--json", "--yes"], None, 0),
    ] {
        let harness = ready(created()).await;
        let (run, reads) = at_a_terminal(&harness, args, &["y"]).await;
        assert_eq!(run.outcome.exit_code, exit, "{args:?}");
        assert_eq!(reads, 0, "{args:?}");
        if let Some(code) = code {
            assert_eq!(run.json()["error"]["code"], code);
            assert!(writes(&harness).await.is_empty());
        }
    }
}

#[tokio::test]
async fn an_unclear_outcome_is_never_retried_and_lists_candidates() {
    for response in [
        json_response(503, fixture("../graph/error-503-retry-after-date.json"))
            .insert_header("Retry-After", "1"),
        json_response(429, json!({"error": {"code": "TooManyRequests"}}))
            .insert_header("Retry-After", "1"),
        json_response(500, json!({})),
        ResponseTemplate::new(201).set_body_string("not json"),
        // A create answered with no object.
        ResponseTemplate::new(201),
        ResponseTemplate::new(200).set_body_string("  "),
        // A redirect is not followed, and the POST may have been processed.
        ResponseTemplate::new(303).insert_header("Location", "/v1.0/security/cases"),
        ResponseTemplate::new(307).insert_header("Location", "/v1.0/security/cases"),
        ResponseTemplate::new(408),
    ] {
        let harness = ready(response).await;
        let run = run(&harness, &["--json", "--yes"]).await;
        assert_eq!(run.outcome.exit_code, 1, "{}", run.stdout());
        let error = &run.json()["error"];
        assert_eq!(error["code"], "WriteOutcomeUnknown");
        let message = error["message"].as_str().unwrap();
        assert!(message.contains("a search named Stub search"), "{message}");
        assert!(message.contains("not sent again"), "{message}");
        assert_eq!(writes(&harness).await.len(), 1);
        // Nothing was read after the POST: a redirect is not followed.
        assert_eq!(gets(&harness).await, 1);
    }
}

#[tokio::test]
async fn a_timeout_on_the_post_is_an_unclear_outcome() {
    let harness = ready(created().set_delay(Duration::from_secs(3))).await;
    let run = run(&harness, &["--json", "--yes", "--timeout", "1"]).await;
    assert_eq!(run.outcome.exit_code, 1);
    assert_eq!(run.json()["error"]["code"], "WriteOutcomeUnknown");
    assert_eq!(writes(&harness).await.len(), 1);
}

#[tokio::test]
async fn a_refusal_from_graph_is_its_error_and_not_retried() {
    for (status, code) in [
        (400, "BadRequest"),
        (401, "InvalidAuthenticationToken"),
        (403, "Forbidden"),
    ] {
        let harness = ready(json_response(
            status,
            json!({"error": {"code": code, "message": "refused"}}),
        ))
        .await;
        let run = run(&harness, &["--json", "--yes"]).await;
        assert_eq!(run.outcome.exit_code, 1);
        assert_eq!(run.json()["error"]["code"], code);
        assert_eq!(run.json()["error"]["status"], status);
        assert_eq!(writes(&harness).await.len(), 1, "{status}");
    }
}

#[tokio::test]
async fn a_post_with_less_than_five_minutes_of_token_left_refreshes_first() {
    let harness = ready(created()).await;
    let scope = harness.stored(ALEX).unwrap()["graph"]["scope"]
        .as_str()
        .unwrap()
        .to_owned();
    Mock::given(method("POST"))
        .and(path(token_path("token")))
        .respond_with(json_response(
            200,
            token("canary-graph-access-0002", "canary-refresh-0002", &scope),
        ))
        .mount(&harness.identity)
        .await;
    // token-graph.json lasts 4271 s: two minutes are left, enough for the
    // preflight GET but not for the POST.
    harness.clock.advance(Duration::from_secs(4271 - 120));
    let run = run(&harness, &["--json", "--yes"]).await;
    assert_eq!(run.outcome.exit_code, 0, "{}", run.stdout());
    assert_eq!(requests(&harness.identity).await.len(), 1);
    let sent = writes(&harness).await;
    assert_eq!(sent.len(), 1);
    assert_eq!(
        sent[0].headers.get("authorization").unwrap(),
        "Bearer canary-graph-access-0002"
    );
    // The preflight GET still used the first token.
    let get = &requests(&harness.graph).await[0];
    assert_eq!(
        get.headers.get("authorization").unwrap(),
        "Bearer canary-graph-access-0001"
    );
}

#[tokio::test]
async fn wrap_untrusted_wraps_the_plan_body_in_every_shape() {
    let harness = ready(created()).await;
    let refused = run(&harness, &["--json", "--wrap-untrusted"]).await;
    assert_eq!(refused.outcome.exit_code, 3);
    let document = refused.json();
    assert!(document["untrustedNotice"].is_string(), "{document}");
    let name = document["plan"]["body"]["displayName"].as_str().unwrap();
    assert!(name.starts_with("[UNTRUSTED:"), "{name}");

    let dry = run(&harness, &["--json", "--wrap-untrusted", "--dry-run"]).await;
    assert_eq!(dry.outcome.exit_code, 0);
    let document = dry.json();
    assert!(document["untrustedNotice"].is_string(), "{document}");
    let name = document["results"]["plan"]["body"]["displayName"]
        .as_str()
        .unwrap();
    assert!(name.starts_with("[UNTRUSTED:"), "{name}");
}

#[tokio::test]
async fn select_is_refused_for_a_write_before_sign_in() {
    for (args, variable) in [
        (&["--json", "--yes", "--select", "id"][..], None),
        (&["--json", "--yes"], Some(("PURVIEW_SELECT", "id"))),
    ] {
        let harness = ready(created()).await;
        let identity_before = requests(&harness.identity).await.len();
        let run = run_with(&harness, args, stub(), |env| {
            if let Some((name, value)) = variable {
                env.vars.insert(name.into(), value.into());
            }
        })
        .await;
        assert_eq!(run.outcome.exit_code, 1, "{args:?}");
        assert!(run.json()["error"]["message"]
            .as_str()
            .unwrap()
            .contains("--select"));
        assert!(requests(&harness.graph).await.is_empty());
        assert_eq!(requests(&harness.identity).await.len(), identity_before);
    }
}

#[tokio::test]
async fn a_plan_for_another_account_is_refused_before_approval() {
    for (account, tenant) in [
        (Some("sam.taylor@contoso.example"), None),
        (None, Some("00000000-0000-4000-8000-000000000099")),
    ] {
        let harness = ready(created()).await;
        let run = run_with(
            &harness,
            &["--json", "--yes"],
            Box::new(StubWrite {
                refuse_check: false,
                plan_account: account,
                plan_tenant: tenant,
            }),
            |_| {},
        )
        .await;
        assert_eq!(run.outcome.exit_code, 1, "{account:?} {tenant:?}");
        assert!(run.json()["error"]["message"]
            .as_str()
            .unwrap()
            .contains("another account or tenant"));
        assert!(writes(&harness).await.is_empty());
    }
}

#[tokio::test]
async fn the_question_comes_after_the_preflight_results() {
    let harness = ready(created()).await;
    let (run, _) = at_a_terminal(&harness, &[], &["n"]).await;
    assert_eq!(run.outcome.exit_code, 3);
    let stderr = run.stderr();
    let preflight = stderr
        .find("  preflight:\n")
        .expect("the preflight is shown");
    let question = stderr.find("Apply? [y/N] ").unwrap();
    assert!(preflight < question, "{stderr}");
    assert!(stderr.contains("\"case\":\"active\""), "{stderr}");
    // A declined plan is shown once.
    assert_eq!(stderr.matches("Plan: purview stub create").count(), 1);
}
