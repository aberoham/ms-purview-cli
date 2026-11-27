//! In-process flows through `cli::execute_with`, against a wiremock
//! identity platform, an in-memory credential store and a manual clock.
//! Nothing here reaches the network or the operating-system keychain.

mod support;

use std::time::Duration;

use ms_purview_cli::env::{Captured, Env, LoginWrite};
use ms_purview_cli::secrets::{CredentialStore, MemoryStore};
use serde_json::Value;
use support::*;
use wiremock::matchers::{method, path};
use wiremock::{Mock, ResponseTemplate};

#[tokio::test]
async fn login_stores_both_tokens_and_the_newest_refresh_token() {
    let harness = Harness::new().await;
    mount_login(
        &harness,
        "id-claims-preferred.json",
        json_response(200, fixture("token-download.json")),
    )
    .await;
    let run = harness
        .run(&[
            "--json",
            "auth",
            "login",
            "--client-id",
            CLIENT_ID,
            "--tenant-id",
            TENANT_ID,
        ])
        .await;
    assert_eq!(run.outcome.exit_code, 0, "{}", run.stderr());
    assert_eq!(
        run.json(),
        serde_json::json!({
            "results": {
                "account": ALEX,
                "upn": "alex.w@contoso.example",
                "tenantId": TENANT_ID,
                "clientId": CLIENT_ID,
                "graphScope": "https://graph.microsoft.com/eDiscovery.ReadWrite.All openid profile",
                "downloadReady": true,
            },
            "count": 1,
        })
    );
    let stderr = run.stderr();
    assert!(stderr.contains("enter the code CNTSO0001"), "{stderr}");
    assert!(!stderr.contains("warning"), "{stderr}");

    // The device code asked for the read-write Graph set.
    let requests = harness.identity.received_requests().await.unwrap();
    let device = form_of(&requests[0]);
    assert!(device.contains(&(
        "scope".into(),
        "https://graph.microsoft.com/eDiscovery.ReadWrite.All offline_access openid profile".into()
    )));
    assert!(device.contains(&("client_id".into(), CLIENT_ID.into())));
    // One pending poll and one success, each after the 5-second interval.
    assert_eq!(harness.clock.sleeps(), [Duration::from_secs(5); 2]);

    let stored = harness.stored(ALEX).expect("a stored credential");
    assert_eq!(stored["version"], 1);
    assert_eq!(stored["email"], ALEX);
    assert_eq!(stored["refresh_token"], "canary-refresh-0002");
    assert_eq!(stored["graph"]["access_token"], "canary-graph-access-0001");
    assert_eq!(stored["graph"]["expires_at"], "2026-01-05T10:11:21Z");
    assert_eq!(
        stored["download"]["access_token"],
        "canary-download-access-0001"
    );
    assert_eq!(
        stored["download"]["scope"],
        "b26e684c-5068-4120-a679-64a5d2c909d9/eDiscovery.Download.Read"
    );
    assert_eq!(harness.credentials(), [ALEX]);

    let account: Value =
        serde_json::from_slice(&std::fs::read(harness.account_file(ALEX)).unwrap()).unwrap();
    assert_eq!(
        account,
        serde_json::json!({
            "email": ALEX,
            "upn": "alex.w@contoso.example",
            "oid": "00000000-0000-4000-8000-000000000011",
            "display_name": "Alex Wilber",
            "tenant_id": TENANT_ID,
            "client_id": CLIENT_ID,
            "login_time": "2026-01-05T09:00:10Z",
        })
    );
    let config = harness.config();
    assert_eq!(config["default_account"], ALEX);
    assert_eq!(
        config["clients"][ALEX],
        serde_json::json!({"client_id": CLIENT_ID, "tenant_id": TENANT_ID})
    );
    harness.assert_no_canaries(&run);
}

#[tokio::test]
async fn login_without_download_consent_succeeds_with_a_warning() {
    let harness = Harness::new().await;
    mount_login(
        &harness,
        "id-claims-preferred.json",
        json_response(400, fixture("aadsts65001.json")),
    )
    .await;
    let run = harness
        .run(&[
            "auth",
            "login",
            "--client-id",
            CLIENT_ID,
            "--tenant-id",
            TENANT_ID,
        ])
        .await;
    assert_eq!(run.outcome.exit_code, 0, "{}", run.stderr());
    let stdout = run.stdout();
    assert!(
        stdout.starts_with(&format!("Signed in as Alex Wilber ({ALEX})")),
        "{stdout}"
    );
    assert!(stdout.contains("Download token: not issued"), "{stdout}");
    let stderr = run.stderr();
    assert!(stderr.contains("warning: no download token"), "{stderr}");
    assert!(stderr.contains("eDiscovery.Download.Read"), "{stderr}");
    assert!(stderr.contains("AADSTS65001"), "{stderr}");
    assert!(stderr.contains("DownloadNotConsented"), "{stderr}");

    let stored = harness.stored(ALEX).unwrap();
    assert!(stored.get("download").is_none(), "{stored}");
    // No rotation came back, so the first refresh token is kept.
    assert_eq!(stored["refresh_token"], "canary-refresh-0001");
    harness.assert_no_canaries(&run);
}

#[tokio::test]
async fn login_without_download_consent_reports_download_ready_false() {
    let harness = Harness::new().await;
    mount_login(
        &harness,
        "id-claims-preferred.json",
        json_response(400, fixture("aadsts65001.json")),
    )
    .await;
    let run = harness
        .run(&[
            "--json",
            "auth",
            "login",
            "--client-id",
            CLIENT_ID,
            "--tenant-id",
            TENANT_ID,
        ])
        .await;
    assert_eq!(run.outcome.exit_code, 0);
    assert_eq!(run.json()["results"]["downloadReady"], false);
}

#[tokio::test]
async fn any_other_download_refusal_fails_login_and_stores_nothing() {
    let harness = Harness::new().await;
    mount_login(
        &harness,
        "id-claims-preferred.json",
        json_response(400, fixture("aadsts65002.json")),
    )
    .await;
    let run = harness
        .run(&[
            "--json",
            "auth",
            "login",
            "--client-id",
            CLIENT_ID,
            "--tenant-id",
            TENANT_ID,
        ])
        .await;
    assert_eq!(run.outcome.exit_code, 1);
    let error = &run.json()["error"];
    assert_eq!(error["code"], "invalid_grant");
    assert_eq!(error["status"], 400);
    let message = error["message"].as_str().unwrap();
    assert!(message.contains("AADSTS65002"), "{message}");
    assert!(message.contains("error codes 65002"), "{message}");
    harness.assert_store_empty();
    assert!(!harness.config_dir().join("accounts").exists());
    harness.assert_no_canaries(&run);
}

#[tokio::test]
async fn read_only_login_asks_for_the_read_scope() {
    let harness = Harness::new().await;
    mount_login(
        &harness,
        "id-claims-preferred.json",
        json_response(200, fixture("token-download.json")),
    )
    .await;
    let run = harness
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
    assert_eq!(run.outcome.exit_code, 0, "{}", run.stderr());
    let requests = harness.identity.received_requests().await.unwrap();
    assert!(form_of(&requests[0]).contains(&(
        "scope".into(),
        "https://graph.microsoft.com/eDiscovery.Read.All offline_access openid profile".into()
    )));
}

#[tokio::test]
async fn the_account_falls_back_to_the_upn_claim() {
    let harness = Harness::new().await;
    mount_login(
        &harness,
        "id-claims-upn-only.json",
        json_response(200, fixture("token-download.json")),
    )
    .await;
    let run = harness
        .run(&[
            "--json",
            "auth",
            "login",
            "--client-id",
            CLIENT_ID,
            "--tenant-id",
            TENANT_ID,
        ])
        .await;
    assert_eq!(run.outcome.exit_code, 0, "{}", run.stderr());
    let results = &run.json()["results"];
    assert_eq!(results["account"], "sam.taylor@contoso.example");
    assert_eq!(results["upn"], "Sam.Taylor@contoso.example");
    assert!(harness.stored("sam.taylor@contoso.example").is_some());
}

#[tokio::test]
async fn an_id_token_with_no_account_claim_stores_nothing() {
    let harness = Harness::new().await;
    mount_login(
        &harness,
        "id-claims-none.json",
        json_response(200, fixture("token-download.json")),
    )
    .await;
    // The download redemption is never reached.
    harness.identity.reset().await;
    Mock::given(method("POST"))
        .and(path(token_path("devicecode")))
        .respond_with(json_response(200, fixture("device-code.json")))
        .mount(&harness.identity)
        .await;
    Mock::given(method("POST"))
        .and(path(token_path("token")))
        .respond_with(json_response(200, graph_token("id-claims-none.json")))
        .expect(1)
        .mount(&harness.identity)
        .await;
    let run = harness
        .run(&[
            "--json",
            "auth",
            "login",
            "--client-id",
            CLIENT_ID,
            "--tenant-id",
            TENANT_ID,
        ])
        .await;
    assert_eq!(run.outcome.exit_code, 1);
    assert_eq!(run.json()["error"]["code"], "NoAccountClaim");
    harness.assert_store_empty();
    harness.assert_no_canaries(&run);
}

#[tokio::test]
async fn slow_down_lengthens_the_interval_and_an_expired_code_stops() {
    let harness = Harness::new().await;
    Mock::given(method("POST"))
        .and(path(token_path("devicecode")))
        .respond_with(json_response(200, fixture("device-code.json")))
        .mount(&harness.identity)
        .await;
    Mock::given(method("POST"))
        .and(path(token_path("token")))
        .respond_with(json_response(
            400,
            serde_json::json!({"error": "slow_down"}),
        ))
        .up_to_n_times(1)
        .with_priority(1)
        .mount(&harness.identity)
        .await;
    Mock::given(method("POST"))
        .and(path(token_path("token")))
        .respond_with(json_response(
            400,
            serde_json::json!({"error": "expired_token", "error_description": "AADSTS70019"}),
        ))
        .with_priority(2)
        .mount(&harness.identity)
        .await;
    let run = harness
        .run(&[
            "auth",
            "login",
            "--client-id",
            CLIENT_ID,
            "--tenant-id",
            TENANT_ID,
        ])
        .await;
    assert_eq!(run.outcome.exit_code, 1);
    assert_eq!(
        harness.clock.sleeps(),
        [Duration::from_secs(5), Duration::from_secs(10)]
    );
    let stderr = run.stderr();
    assert!(stderr.contains("the device code expired"), "{stderr}");
    harness.assert_store_empty();
    harness.assert_no_canaries(&run);
}

#[tokio::test]
async fn a_declined_sign_in_keeps_only_the_allow_listed_error_fields() {
    let harness = Harness::new().await;
    Mock::given(method("POST"))
        .and(path(token_path("devicecode")))
        .respond_with(json_response(200, fixture("device-code.json")))
        .mount(&harness.identity)
        .await;
    Mock::given(method("POST"))
        .and(path(token_path("token")))
        .respond_with(json_response(
            400,
            serde_json::json!({
                "error": "authorization_declined",
                "error_description": "AADSTS70000: declined canary-device-code-0001",
                "error_codes": [70000],
                "trace_id": "00000000-0000-4000-8000-000000000031",
                "claims": "canary-graph-access-0001",
                "error_uri": "https://login.microsoftonline.com/error?code=70000",
            }),
        ))
        .mount(&harness.identity)
        .await;
    let run = harness
        .run(&[
            "--json",
            "auth",
            "login",
            "--client-id",
            CLIENT_ID,
            "--tenant-id",
            TENANT_ID,
        ])
        .await;
    assert_eq!(run.outcome.exit_code, 1);
    let message = run.json()["error"]["message"].as_str().unwrap().to_owned();
    assert!(message.contains("authorization_declined"), "{message}");
    assert!(message.contains("declined [redacted]"), "{message}");
    assert!(
        message.contains("trace id 00000000-0000-4000-8000-000000000031"),
        "{message}"
    );
    assert!(
        !message.contains("error_uri") && !message.contains("claims"),
        "{message}"
    );
    harness.assert_no_canaries(&run);
}

#[tokio::test]
async fn login_reuses_the_saved_registration_without_flags() {
    let harness = Harness::new().await;
    sign_in_alex(&harness).await;
    mount_login(
        &harness,
        "id-claims-preferred.json",
        json_response(200, fixture("token-download.json")),
    )
    .await;
    let run = harness.run(&["auth", "login"]).await;
    assert_eq!(run.outcome.exit_code, 0, "{}", run.stderr());
    assert!(
        run.stderr()
            .contains(&format!("in tenant {TENANT_ID}, as saved with {ALEX}")),
        "{}",
        run.stderr()
    );
}

#[tokio::test]
async fn login_without_any_registration_fails_before_the_network() {
    let harness = Harness::new().await;
    let run = harness.run(&["auth", "login"]).await;
    assert_eq!(run.outcome.exit_code, 1);
    assert!(run.stderr().contains("--client-id"), "{}", run.stderr());
    let run = harness
        .run(&["auth", "login", "--client-id", CLIENT_ID])
        .await;
    assert_eq!(run.outcome.exit_code, 1);
    assert!(run.stderr().contains("--tenant-id"), "{}", run.stderr());
    assert!(harness
        .identity
        .received_requests()
        .await
        .unwrap()
        .is_empty());
}

#[tokio::test]
async fn environment_variables_give_the_registration() {
    let harness = Harness::new().await;
    mount_login(
        &harness,
        "id-claims-preferred.json",
        json_response(200, fixture("token-download.json")),
    )
    .await;
    let (mut env, captured) = harness.env();
    env.vars
        .insert("PURVIEW_CLIENT_ID".into(), CLIENT_ID.into());
    env.vars
        .insert("PURVIEW_TENANT_ID".into(), TENANT_ID.into());
    let outcome = ms_purview_cli::cli::execute_with(env, ["purview", "auth", "login"]).await;
    assert_eq!(outcome.exit_code, 0, "{}", captured.stderr.text());
    assert!(harness.stored(ALEX).is_some());
}

/// Mounts one `auth refresh` round: the Graph redemption with `refresh`,
/// answered by `graph`, then the download redemption with whatever
/// refresh token the Graph answer rotated to, answered by `download`.
async fn mount_refresh(
    harness: &Harness,
    refresh: &str,
    graph: ResponseTemplate,
    rotated: &str,
    download: ResponseTemplate,
) {
    Mock::given(method("POST"))
        .and(path(token_path("token")))
        .and(Form(vec![
            ("grant_type", "refresh_token".into()),
            ("refresh_token", refresh.into()),
            (
                "scope",
                "https://graph.microsoft.com/eDiscovery.ReadWrite.All openid profile \
                 offline_access"
                    .into(),
            ),
        ]))
        .respond_with(graph)
        .expect(1)
        .mount(&harness.identity)
        .await;
    Mock::given(method("POST"))
        .and(path(token_path("token")))
        .and(Form(vec![
            ("grant_type", "refresh_token".into()),
            ("refresh_token", rotated.into()),
            (
                "scope",
                "b26e684c-5068-4120-a679-64a5d2c909d9/.default offline_access".into(),
            ),
        ]))
        .respond_with(download)
        .mount(&harness.identity)
        .await;
}

#[tokio::test]
async fn refresh_redeems_both_resources_and_stores_each_rotation() {
    let harness = Harness::new().await;
    sign_in_alex(&harness).await;
    harness.clock.advance(Duration::from_secs(600));
    mount_refresh(
        &harness,
        "canary-refresh-0002",
        json_response(
            200,
            token(
                "canary-graph-access-0002",
                "canary-refresh-0003",
                "https://graph.microsoft.com/eDiscovery.ReadWrite.All openid profile",
            ),
        ),
        "canary-refresh-0003",
        json_response(
            200,
            token(
                "canary-download-access-0002",
                "canary-refresh-0004",
                "b26e684c-5068-4120-a679-64a5d2c909d9/eDiscovery.Download.Read",
            ),
        ),
    )
    .await;
    let run = harness.run(&["--json", "auth", "refresh"]).await;
    assert_eq!(run.outcome.exit_code, 0, "{}", run.stderr());
    assert_eq!(
        run.json(),
        serde_json::json!({
            "results": {
                "account": ALEX,
                "graphExpiresAt": "2026-01-05T10:10:09Z",
                "downloadExpiresAt": "2026-01-05T10:10:09Z",
                "graphScope": "https://graph.microsoft.com/eDiscovery.ReadWrite.All openid profile",
            },
            "count": 1,
        })
    );
    let stored = harness.stored(ALEX).unwrap();
    assert_eq!(stored["refresh_token"], "canary-refresh-0004");
    assert_eq!(stored["graph"]["access_token"], "canary-graph-access-0002");
    assert_eq!(
        stored["download"]["access_token"],
        "canary-download-access-0002"
    );
    harness.assert_no_canaries(&run);
}

/// The download redemption fails after the Graph rotation, and its error
/// body reflects the refresh token and access token that the rotation
/// superseded in this process, as well as the new ones.
async fn refresh_reflecting_old_tokens(json: bool) {
    let harness = Harness::new().await;
    sign_in_alex(&harness).await;
    let reflected = serde_json::json!({
        "error": "invalid_grant",
        "error_description": "AADSTS70000: canary-refresh-0002 canary-graph-access-0001 \
                              canary-refresh-0003 canary-graph-access-0002 \
                              canary-download-access-0001",
        "error_codes": [70000],
        "trace_id": "canary-refresh-0002",
        "correlation_id": "canary-graph-access-0001",
    });
    mount_refresh(
        &harness,
        "canary-refresh-0002",
        json_response(
            200,
            token(
                "canary-graph-access-0002",
                "canary-refresh-0003",
                "https://graph.microsoft.com/eDiscovery.ReadWrite.All openid profile",
            ),
        ),
        "canary-refresh-0003",
        json_response(400, reflected),
    )
    .await;
    let args: &[&str] = if json {
        &["--json", "auth", "refresh"]
    } else {
        &["auth", "refresh"]
    };
    let run = harness.run(args).await;
    assert_eq!(run.outcome.exit_code, 1);
    let text = format!("{}{}", run.stdout(), run.stderr());
    assert!(text.contains("AADSTS70000"), "{text}");
    assert!(text.contains("[redacted]"), "{text}");
    if json {
        assert_eq!(run.json()["error"]["code"], "invalid_grant");
    }
    harness.assert_no_canaries(&run);
    // The Graph rotation was stored before the download step failed.
    assert_eq!(
        harness.stored(ALEX).unwrap()["refresh_token"],
        "canary-refresh-0003"
    );
}

#[tokio::test]
async fn a_failure_after_rotation_that_reflects_old_tokens_is_redacted() {
    refresh_reflecting_old_tokens(false).await;
}

#[tokio::test]
async fn a_json_failure_after_rotation_that_reflects_old_tokens_is_redacted() {
    refresh_reflecting_old_tokens(true).await;
}

#[tokio::test]
async fn refresh_without_download_consent_fails_and_keeps_the_graph_rotation() {
    let harness = Harness::new().await;
    sign_in_alex(&harness).await;
    mount_refresh(
        &harness,
        "canary-refresh-0002",
        json_response(
            200,
            token(
                "canary-graph-access-0002",
                "canary-refresh-0003",
                "https://graph.microsoft.com/eDiscovery.ReadWrite.All openid profile",
            ),
        ),
        "canary-refresh-0003",
        json_response(400, fixture("aadsts65001.json")),
    )
    .await;
    let run = harness.run(&["--json", "auth", "refresh"]).await;
    assert_eq!(run.outcome.exit_code, 1);
    assert_eq!(run.json()["error"]["code"], "DownloadNotConsented");
    assert!(run.stderr().is_empty(), "{}", run.stderr());
    // The Graph rotation and the removal of the refused download token
    // were both stored.
    let stored = harness.stored(ALEX).unwrap();
    assert!(stored.get("download").is_none(), "{stored}");
    assert_eq!(stored["refresh_token"], "canary-refresh-0003");
    harness.assert_no_canaries(&run);
}

#[tokio::test]
async fn refresh_fails_when_the_store_refuses_the_write() {
    let harness = Harness::new().await;
    sign_in_alex(&harness).await;
    mount_refresh(
        &harness,
        "canary-refresh-0002",
        json_response(
            200,
            token(
                "canary-graph-access-0002",
                "canary-refresh-0003",
                "eDiscovery.ReadWrite.All",
            ),
        ),
        "canary-refresh-0003",
        json_response(200, fixture("token-download.json")),
    )
    .await;
    harness.store.fail_writes(true);
    let run = harness.run(&["--json", "auth", "refresh"]).await;
    assert_eq!(run.outcome.exit_code, 1);
    let message = run.json()["error"]["message"].as_str().unwrap().to_owned();
    assert!(message.contains("storing the credential"), "{message}");
    harness.store.fail_writes(false);
    assert_eq!(
        harness.stored(ALEX).unwrap()["refresh_token"],
        "canary-refresh-0002"
    );
    harness.assert_no_canaries(&run);
}

#[tokio::test]
async fn refresh_with_no_credential_or_no_account_fails_before_the_network() {
    let harness = Harness::new().await;
    let run = harness.run(&["auth", "refresh"]).await;
    assert_eq!(run.outcome.exit_code, 1);
    assert!(run.stderr().contains("no account is signed in"));

    sign_in_alex(&harness).await;
    harness.store.remove(&format!("purview:token:{ALEX}"));
    let run = harness.run(&["auth", "refresh"]).await;
    assert_eq!(run.outcome.exit_code, 1);
    assert!(
        run.stderr().contains("no stored credential"),
        "{}",
        run.stderr()
    );
    assert!(harness
        .identity
        .received_requests()
        .await
        .unwrap()
        .is_empty());
}

async fn sign_in_sam_too(harness: &Harness) {
    mount_login(
        harness,
        "id-claims-upn-only.json",
        json_response(200, fixture("token-download.json")),
    )
    .await;
    let run = harness.run(&["auth", "login"]).await;
    assert_eq!(run.outcome.exit_code, 0, "{}", run.stderr());
    harness.identity.reset().await;
}

#[tokio::test]
async fn list_marks_the_default_and_logout_moves_it() {
    let harness = Harness::new().await;
    sign_in_alex(&harness).await;
    sign_in_sam_too(&harness).await;

    let run = harness.run(&["auth", "list"]).await;
    assert_eq!(run.outcome.exit_code, 0);
    let rows: Vec<Vec<String>> = run
        .stdout()
        .lines()
        .map(|line| {
            line.split("  ")
                .map(str::trim)
                .filter(|f| !f.is_empty())
                .map(str::to_owned)
                .collect()
        })
        .collect();
    assert_eq!(
        rows,
        [
            vec!["EMAIL", "NAME", "DEFAULT"],
            vec![ALEX, "Alex Wilber", "*"],
            vec!["sam.taylor@contoso.example"],
        ]
    );
    let run = harness.run(&["--json", "auth", "list"]).await;
    let listed = run.json();
    assert_eq!(listed["count"], 2);
    assert_eq!(listed["results"][1]["email"], "sam.taylor@contoso.example");

    let run = harness.run(&["--json", "auth", "logout"]).await;
    assert_eq!(run.outcome.exit_code, 0, "{}", run.stderr());
    assert_eq!(
        run.json(),
        serde_json::json!({"results": {"account": ALEX, "signedOut": true}, "count": 1})
    );
    assert!(harness.stored(ALEX).is_none());
    assert!(!harness.account_file(ALEX).exists());
    let config = harness.config();
    assert_eq!(config["default_account"], "sam.taylor@contoso.example");
    // The registration stays, so signing in again needs no flags.
    assert_eq!(config["clients"][ALEX]["client_id"], CLIENT_ID);
    harness.assert_no_canaries(&run);
}

#[tokio::test]
async fn account_is_chosen_by_key_or_upn_with_no_fallback() {
    let harness = Harness::new().await;
    sign_in_alex(&harness).await;
    sign_in_sam_too(&harness).await;

    let run = harness
        .run(&["auth", "logout", "--account", "ALEX.W@contoso.example"])
        .await;
    assert_eq!(run.outcome.exit_code, 0, "{}", run.stderr());
    assert!(harness.stored(ALEX).is_none());
    assert!(harness.stored("sam.taylor@contoso.example").is_some());

    let (mut env, captured) = harness.env();
    env.vars
        .insert("PURVIEW_ACCOUNT".into(), "nobody@contoso.example".into());
    let outcome = ms_purview_cli::cli::execute_with(env, ["purview", "auth", "logout"]).await;
    assert_eq!(outcome.exit_code, 1);
    assert!(
        captured
            .stderr
            .text()
            .contains("no signed-in account matches"),
        "{}",
        captured.stderr.text()
    );
    assert!(harness.stored("sam.taylor@contoso.example").is_some());
}

#[tokio::test]
async fn a_stale_default_is_not_replaced_by_a_guess() {
    let harness = Harness::new().await;
    sign_in_alex(&harness).await;
    let path = harness.config_dir().join("config.json");
    let mut config = harness.config();
    config["default_account"] = "gone@contoso.example".into();
    std::fs::write(&path, config.to_string()).unwrap();
    let run = harness.run(&["auth", "refresh"]).await;
    assert_eq!(run.outcome.exit_code, 1);
    assert!(
        run.stderr().contains("no default account is set"),
        "{}",
        run.stderr()
    );
}

#[tokio::test]
async fn blank_explicit_flags_are_errors_and_never_fall_back() {
    let harness = Harness::new().await;
    sign_in_alex(&harness).await;
    for args in [
        &["auth", "logout", "--account", ""][..],
        &["auth", "logout", "--account", "  "][..],
        &["auth", "refresh", "--account", ""][..],
    ] {
        let run = harness.run(args).await;
        assert_eq!(run.outcome.exit_code, 1, "{args:?}");
        assert!(
            run.stderr()
                .starts_with("Error: --account was given an empty value"),
            "{args:?}: {}",
            run.stderr()
        );
    }
    assert!(harness.stored(ALEX).is_some());

    // A blank id is refused before the configuration is read: this
    // config.json cannot be parsed, and the error does not mention it.
    std::fs::write(harness.config_dir().join("config.json"), b"{not json").unwrap();
    for flag in ["--client-id", "--tenant-id"] {
        let (mut env, captured) = harness.env();
        env.vars
            .insert("PURVIEW_CLIENT_ID".into(), CLIENT_ID.into());
        env.vars
            .insert("PURVIEW_TENANT_ID".into(), TENANT_ID.into());
        let outcome =
            ms_purview_cli::cli::execute_with(env, ["purview", "auth", "login", flag, " "]).await;
        assert_eq!(outcome.exit_code, 1);
        let stderr = captured.stderr.text();
        assert!(
            stderr.starts_with(&format!("Error: {flag} was given an empty value")),
            "{stderr}"
        );
    }
    assert!(harness
        .identity
        .received_requests()
        .await
        .unwrap()
        .is_empty());
}

#[tokio::test]
async fn empty_environment_variables_count_as_unset() {
    let harness = Harness::new().await;
    sign_in_alex(&harness).await;
    let (mut env, captured) = harness.env();
    env.vars.insert("PURVIEW_ACCOUNT".into(), "".into());
    let outcome = ms_purview_cli::cli::execute_with(env, ["purview", "auth", "logout"]).await;
    assert_eq!(outcome.exit_code, 0, "{}", captured.stderr.text());
    assert!(harness.stored(ALEX).is_none());
}

#[tokio::test]
async fn login_with_account_resolves_a_recorded_upn_and_reuses_its_registration() {
    let harness = Harness::new().await;
    sign_in_alex(&harness).await;
    mount_login(
        &harness,
        "id-claims-preferred.json",
        json_response(200, fixture("token-download.json")),
    )
    .await;
    let run = harness
        .run(&["auth", "login", "--account", "Alex.W@contoso.example"])
        .await;
    assert_eq!(run.outcome.exit_code, 0, "{}", run.stderr());
    assert!(
        run.stderr().contains(&format!("as saved with {ALEX}")),
        "{}",
        run.stderr()
    );
}

#[tokio::test]
async fn login_refuses_an_identity_other_than_the_account_asked_for() {
    let harness = Harness::new().await;
    sign_in_alex(&harness).await;
    let before = harness.stored(ALEX).unwrap();
    let config_before = harness.config();
    // The browser signs in as a different person.
    mount_login(
        &harness,
        "id-claims-upn-only.json",
        json_response(200, fixture("token-download.json")),
    )
    .await;
    let run = harness
        .run(&["--json", "auth", "login", "--account", ALEX])
        .await;
    assert_eq!(run.outcome.exit_code, 1);
    let message = run.json()["error"]["message"].as_str().unwrap().to_owned();
    assert!(
        message.contains("signed in as sam.taylor@contoso.example"),
        "{message}"
    );
    assert!(message.contains("nothing was stored"), "{message}");
    assert!(!message.contains(ALEX), "{message}");
    assert_eq!(harness.credentials(), [ALEX]);
    assert_eq!(harness.stored(ALEX).unwrap(), before);
    assert_eq!(harness.config(), config_before);
    assert!(!harness.account_file("sam.taylor@contoso.example").exists());
    harness.assert_no_canaries(&run);
}

#[tokio::test]
async fn an_account_that_matches_several_upns_is_refused() {
    let harness = Harness::new().await;
    sign_in_alex(&harness).await;
    sign_in_sam_too(&harness).await;
    // Give both account files the same upn.
    for email in [ALEX, "sam.taylor@contoso.example"] {
        let path = harness.account_file(email);
        let mut record: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        record["upn"] = "shared@contoso.example".into();
        std::fs::write(&path, record.to_string()).unwrap();
    }
    for args in [
        &["auth", "logout", "--account", "shared@contoso.example"][..],
        &["auth", "login", "--account", "shared@contoso.example"][..],
    ] {
        let run = harness.run(args).await;
        assert_eq!(run.outcome.exit_code, 1, "{args:?}");
        assert!(
            run.stderr().contains("matches several signed-in accounts"),
            "{args:?}: {}",
            run.stderr()
        );
        assert!(
            !run.stderr().contains("shared@"),
            "{args:?}: {}",
            run.stderr()
        );
    }
    assert_eq!(harness.credentials().len(), 2);
}

/// Runs `auth login` for Alex with one of its writes made to fail.
async fn login_with_fault(harness: &Harness, write: LoginWrite, client: &str) -> Run {
    mount_login(
        harness,
        "id-claims-preferred.json",
        json_response(200, fixture("token-download.json")),
    )
    .await;
    let (mut env, captured) = harness.env();
    env.login_write_fault = Some(write);
    let outcome = ms_purview_cli::cli::execute_with(
        env,
        [
            "purview",
            "auth",
            "login",
            "--client-id",
            client,
            "--tenant-id",
            TENANT_ID,
        ],
    )
    .await;
    harness.identity.reset().await;
    Run { outcome, captured }
}

#[tokio::test]
async fn a_first_sign_in_that_fails_at_the_credential_or_account_file_keeps_nothing() {
    for write in [LoginWrite::Credential, LoginWrite::AccountFile] {
        let harness = Harness::new().await;
        let run = login_with_fault(&harness, write, CLIENT_ID).await;
        assert_eq!(run.outcome.exit_code, 1, "{write:?}");
        assert!(
            run.stderr().contains("injected failure"),
            "{}",
            run.stderr()
        );
        harness.assert_store_empty();
        assert!(!harness.account_file(ALEX).exists(), "{write:?}");
        assert!(
            !harness.config_dir().join("config.json").exists(),
            "{write:?}"
        );
        harness.assert_no_canaries(&run);
        let list = harness.run(&["--json", "auth", "list"]).await;
        assert_eq!(list.json()["count"], 0, "{write:?}");
    }
}

#[tokio::test]
async fn a_first_sign_in_that_fails_at_config_json_leaves_a_working_account() {
    let harness = Harness::new().await;
    let run = login_with_fault(&harness, LoginWrite::Config, CLIENT_ID).await;
    assert_eq!(run.outcome.exit_code, 1);
    assert!(
        run.stderr().contains("saving config.json"),
        "{}",
        run.stderr()
    );
    assert_eq!(harness.credentials(), [ALEX]);
    assert!(harness.account_file(ALEX).exists());
    harness.assert_no_canaries(&run);

    let list = harness.run(&["--json", "auth", "list"]).await;
    assert_eq!(list.json()["results"][0]["email"], ALEX);
    // No default was saved, so the account is named; it refreshes through
    // the registration its credential records.
    let refresh = harness.run(&["auth", "refresh"]).await;
    assert!(refresh.stderr().contains("no default account is set"));
    mount_any_refresh(&harness).await;
    let refresh = harness.run(&["auth", "refresh", "--account", ALEX]).await;
    assert_eq!(refresh.outcome.exit_code, 0, "{}", refresh.stderr());
    let logout = harness.run(&["auth", "logout", "--account", ALEX]).await;
    assert_eq!(logout.outcome.exit_code, 0, "{}", logout.stderr());
    harness.assert_store_empty();
}

/// Answers every refresh-token redemption, for any registration.
async fn mount_any_refresh(harness: &Harness) {
    Mock::given(method("POST"))
        .and(path(token_path("token")))
        .and(Form::new(&[("grant_type", "refresh_token")]))
        .respond_with(json_response(
            200,
            token(
                "canary-graph-access-0002",
                "canary-refresh-0003",
                "https://graph.microsoft.com/eDiscovery.ReadWrite.All openid profile",
            ),
        ))
        .mount(&harness.identity)
        .await;
}

const OTHER_CLIENT: &str = "00000000-0000-4000-8000-000000000003";

/// The client id every refresh-token redemption since the last reset used.
async fn refresh_clients(harness: &Harness) -> Vec<String> {
    harness
        .identity
        .received_requests()
        .await
        .unwrap()
        .iter()
        .map(form_of)
        .filter(|form| form.contains(&("grant_type".into(), "refresh_token".into())))
        .filter_map(|form| {
            form.into_iter()
                .find(|(name, _)| name == "client_id")
                .map(|(_, value)| value)
        })
        .collect()
}

#[tokio::test]
async fn a_re_sign_in_through_a_new_registration_that_fails_at_the_credential_keeps_the_old() {
    // The store refuses the write outright: the first sign-in is intact,
    // and refresh uses its registration.
    let harness = Harness::new().await;
    sign_in_alex(&harness).await;
    mount_login(
        &harness,
        "id-claims-preferred.json",
        json_response(200, fixture("token-download.json")),
    )
    .await;
    harness.store.fail_writes(true);
    let run = harness
        .run(&[
            "auth",
            "login",
            "--client-id",
            OTHER_CLIENT,
            "--tenant-id",
            TENANT_ID,
        ])
        .await;
    harness.store.fail_writes(false);
    harness.identity.reset().await;
    assert_eq!(run.outcome.exit_code, 1);
    assert_eq!(harness.stored(ALEX).unwrap()["client_id"], CLIENT_ID);
    mount_any_refresh(&harness).await;
    let refresh = harness.run(&["auth", "refresh"]).await;
    assert_eq!(refresh.outcome.exit_code, 0, "{}", refresh.stderr());
    assert_eq!(refresh_clients(&harness).await, [CLIENT_ID, CLIENT_ID]);

    // The write takes effect and then reports a failure: the new tokens
    // are in place, the account file still names the old registration, and
    // refresh refuses rather than mixing them.
    let harness = Harness::new().await;
    sign_in_alex(&harness).await;
    let run = login_with_fault(&harness, LoginWrite::Credential, OTHER_CLIENT).await;
    assert_eq!(run.outcome.exit_code, 1);
    assert!(
        run.stderr().contains("may or may not have been replaced"),
        "{}",
        run.stderr()
    );
    assert_eq!(harness.stored(ALEX).unwrap()["client_id"], OTHER_CLIENT);
    mount_any_refresh(&harness).await;
    let refresh = harness.run(&["auth", "refresh"]).await;
    assert_eq!(refresh.outcome.exit_code, 1);
    assert!(
        refresh.stderr().contains("its account file"),
        "{}",
        refresh.stderr()
    );
    assert!(refresh_clients(&harness).await.is_empty());
}

#[tokio::test]
async fn a_re_sign_in_through_a_new_registration_that_stops_later_makes_refresh_refuse() {
    for (write, named_by) in [
        (LoginWrite::AccountFile, "its account file"),
        (LoginWrite::Config, "config.json"),
    ] {
        let harness = Harness::new().await;
        sign_in_alex(&harness).await;
        let run = login_with_fault(&harness, write, OTHER_CLIENT).await;
        assert_eq!(run.outcome.exit_code, 1, "{write:?}");
        // The new tokens replaced the old ones in place, stamped with the
        // registration that issued them.
        assert_eq!(harness.credentials(), [ALEX], "{write:?}");
        assert_eq!(harness.stored(ALEX).unwrap()["client_id"], OTHER_CLIENT);
        harness.assert_no_canaries(&run);

        mount_any_refresh(&harness).await;
        let refresh = harness.run(&["--json", "auth", "refresh"]).await;
        assert_eq!(refresh.outcome.exit_code, 1, "{write:?}");
        let message = refresh.json()["error"]["message"]
            .as_str()
            .unwrap()
            .to_owned();
        assert!(
            message.contains("issued through another app registration than"),
            "{message}"
        );
        assert!(message.contains(named_by), "{write:?}: {message}");
        assert!(message.contains("purview auth login"), "{message}");
        assert!(refresh_clients(&harness).await.is_empty(), "{write:?}");

        // Signing in again through the new registration repairs it.
        harness.identity.reset().await;
        mount_login(
            &harness,
            "id-claims-preferred.json",
            json_response(200, fixture("token-download.json")),
        )
        .await;
        let again = harness
            .run(&[
                "auth",
                "login",
                "--client-id",
                OTHER_CLIENT,
                "--tenant-id",
                TENANT_ID,
            ])
            .await;
        assert_eq!(again.outcome.exit_code, 0, "{}", again.stderr());
        harness.identity.reset().await;
        mount_any_refresh(&harness).await;
        let refresh = harness.run(&["auth", "refresh"]).await;
        assert_eq!(refresh.outcome.exit_code, 0, "{}", refresh.stderr());
        assert_eq!(
            refresh_clients(&harness).await,
            [OTHER_CLIENT, OTHER_CLIENT]
        );
    }
}

#[tokio::test]
async fn a_credential_store_refusal_on_first_sign_in_stores_nothing() {
    let harness = Harness::new().await;
    mount_login(
        &harness,
        "id-claims-preferred.json",
        json_response(200, fixture("token-download.json")),
    )
    .await;
    harness.store.fail_writes(true);
    let run = harness
        .run(&[
            "auth",
            "login",
            "--client-id",
            CLIENT_ID,
            "--tenant-id",
            TENANT_ID,
        ])
        .await;
    harness.store.fail_writes(false);
    assert_eq!(run.outcome.exit_code, 1);
    assert!(
        run.stderr().contains("nothing from this sign-in was kept"),
        "{}",
        run.stderr()
    );
    harness.assert_store_empty();
    assert!(!harness.account_file(ALEX).exists());
    harness.assert_no_canaries(&run);
}

#[tokio::test]
async fn a_mixed_case_registration_key_is_replaced_on_sign_in() {
    let harness = Harness::new().await;
    sign_in_alex(&harness).await;
    let path = harness.config_dir().join("config.json");
    let mut config = harness.config();
    let stale = serde_json::json!({
        "client_id": "00000000-0000-4000-8000-000000000009",
        "tenant_id": TENANT_ID,
        "note": "kept",
    });
    config["clients"]["Alex.Wilber@Contoso.Example"] = stale;
    std::fs::write(&path, config.to_string()).unwrap();
    mount_login(
        &harness,
        "id-claims-preferred.json",
        json_response(200, fixture("token-download.json")),
    )
    .await;
    let run = harness
        .run(&[
            "auth",
            "login",
            "--client-id",
            CLIENT_ID,
            "--tenant-id",
            TENANT_ID,
        ])
        .await;
    assert_eq!(run.outcome.exit_code, 0, "{}", run.stderr());
    let clients = harness.config()["clients"].clone();
    assert_eq!(
        clients,
        serde_json::json!({ALEX: {"client_id": CLIENT_ID, "tenant_id": TENANT_ID, "note": "kept"}})
    );
}

#[tokio::test]
async fn under_json_the_sign_in_text_goes_to_stderr_and_stdout_is_one_document() {
    let harness = Harness::new().await;
    mount_login(
        &harness,
        "id-claims-preferred.json",
        json_response(200, fixture("token-download.json")),
    )
    .await;
    let run = harness
        .run(&[
            "--json",
            "auth",
            "login",
            "--client-id",
            CLIENT_ID,
            "--tenant-id",
            TENANT_ID,
        ])
        .await;
    assert_eq!(run.outcome.exit_code, 0);
    let stderr = run.stderr();
    assert!(
        stderr.starts_with(&format!("Signing in through app registration {CLIENT_ID}")),
        "{stderr}"
    );
    assert!(stderr.contains("enter the code CNTSO0001"), "{stderr}");
    assert_eq!(run.json()["results"]["account"], ALEX);
    assert_eq!(
        serde_json::Deserializer::from_str(&run.stdout())
            .into_iter::<Value>()
            .count(),
        1
    );
}

#[tokio::test]
async fn list_honours_select_from_the_flag_or_the_variable() {
    let harness = Harness::new().await;
    sign_in_alex(&harness).await;
    let run = harness
        .run(&["--plain", "--select", "EMAIL,DEFAULT", "auth", "list"])
        .await;
    assert_eq!(run.outcome.exit_code, 0, "{}", run.stderr());
    assert_eq!(run.stdout(), format!("{ALEX}\t*\n"));

    let (mut env, captured) = harness.env();
    env.vars.insert("PURVIEW_SELECT".into(), "NAME".into());
    env.vars.insert("PURVIEW_PLAIN".into(), "true".into());
    let outcome = ms_purview_cli::cli::execute_with(env, ["purview", "auth", "list"]).await;
    assert_eq!(outcome.exit_code, 0);
    assert_eq!(captured.stdout.text(), "Alex Wilber\n");

    let run = harness.run(&["--select", "BOGUS", "auth", "list"]).await;
    assert_eq!(run.outcome.exit_code, 1);
    assert!(run.stdout().is_empty());
}

#[tokio::test]
async fn the_device_code_expires_locally_while_the_server_keeps_saying_pending() {
    let harness = Harness::new().await;
    let mut code = fixture("device-code.json");
    code["expires_in"] = 12.into();
    Mock::given(method("POST"))
        .and(path(token_path("devicecode")))
        .respond_with(json_response(200, code))
        .mount(&harness.identity)
        .await;
    Mock::given(method("POST"))
        .and(path(token_path("token")))
        .respond_with(json_response(400, fixture("authorization-pending.json")))
        .expect(2)
        .mount(&harness.identity)
        .await;
    let run = harness
        .run(&[
            "auth",
            "login",
            "--client-id",
            CLIENT_ID,
            "--tenant-id",
            TENANT_ID,
        ])
        .await;
    assert_eq!(run.outcome.exit_code, 1);
    assert!(
        run.stderr().contains("the device code expired"),
        "{}",
        run.stderr()
    );
    // Two full intervals, then only what was left of the code's lifetime.
    assert_eq!(
        harness.clock.sleeps(),
        [
            Duration::from_secs(5),
            Duration::from_secs(5),
            Duration::from_secs(2)
        ]
    );
}

#[tokio::test]
async fn a_token_in_an_error_body_is_redacted_where_the_body_quotes_it() {
    let harness = Harness::new().await;
    Mock::given(method("POST"))
        .and(path(token_path("devicecode")))
        .respond_with(json_response(200, fixture("device-code.json")))
        .mount(&harness.identity)
        .await;
    Mock::given(method("POST"))
        .and(path(token_path("token")))
        .respond_with(json_response(
            400,
            serde_json::json!({
                "error": "invalid_request",
                "error_description": "AADSTS90000: canary-graph-access-0003",
                "access_token": "canary-graph-access-0003",
            }),
        ))
        .mount(&harness.identity)
        .await;
    let run = harness
        .run(&[
            "--json",
            "auth",
            "login",
            "--client-id",
            CLIENT_ID,
            "--tenant-id",
            TENANT_ID,
        ])
        .await;
    assert_eq!(run.outcome.exit_code, 1);
    let message = run.json()["error"]["message"].as_str().unwrap().to_owned();
    assert!(message.contains("AADSTS90000: [redacted]"), "{message}");
    harness.assert_no_canaries(&run);
}

#[tokio::test]
async fn an_account_bound_by_its_ids_refuses_an_identity_that_shares_its_upn() {
    let harness = Harness::new().await;
    sign_in_alex(&harness).await;
    sign_in_sam_too(&harness).await;
    // Alex's recorded upn is Sam's address: a name collision.
    let path = harness.account_file(ALEX);
    let mut record: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    record["upn"] = "sam.taylor@contoso.example".into();
    std::fs::write(&path, record.to_string()).unwrap();
    let alex_before = harness.stored(ALEX).unwrap();
    let sam_before = harness.stored("sam.taylor@contoso.example").unwrap();
    // Alex is asked for by key; the browser signs in as Sam.
    mount_login(
        &harness,
        "id-claims-upn-only.json",
        json_response(200, fixture("token-download.json")),
    )
    .await;
    let run = harness
        .run(&["--json", "auth", "login", "--account", ALEX])
        .await;
    assert_eq!(run.outcome.exit_code, 1, "{}", run.stdout());
    let message = run.json()["error"]["message"].as_str().unwrap().to_owned();
    assert!(message.contains("nothing was stored"), "{message}");
    assert_eq!(harness.stored(ALEX).unwrap(), alex_before);
    assert_eq!(
        harness.stored("sam.taylor@contoso.example").unwrap(),
        sam_before
    );
}

#[tokio::test]
async fn a_name_that_matches_no_stored_account_needs_the_same_key_or_upn() {
    let harness = Harness::new().await;
    for (requested, accepted) in [
        ("alex.w@contoso.example", true),
        ("ALEX.WILBER@contoso.example", true),
        ("alex@contoso.example", false),
    ] {
        harness.identity.reset().await;
        mount_login(
            &harness,
            "id-claims-preferred.json",
            json_response(200, fixture("token-download.json")),
        )
        .await;
        let run = harness
            .run(&[
                "auth",
                "login",
                "--account",
                requested,
                "--client-id",
                CLIENT_ID,
                "--tenant-id",
                TENANT_ID,
            ])
            .await;
        assert_eq!(
            run.outcome.exit_code == 0,
            accepted,
            "{requested}: {}",
            run.stderr()
        );
        harness.run(&["auth", "logout", "--account", ALEX]).await;
        harness.assert_store_empty();
    }
}

#[tokio::test]
async fn a_permission_change_error_names_no_scope_even_with_an_escaped_canary() {
    // A rotated refresh token with a backslash, which JSON escapes, also
    // reflected in the scope the response claims.
    let escaped = "canary\\escaped-0001";
    for json in [false, true] {
        let harness = Harness::new().await;
        sign_in_alex(&harness).await;
        Mock::given(method("POST"))
            .and(path(token_path("token")))
            .respond_with(json_response(
                200,
                serde_json::json!({
                    "access_token": "canary-graph-access-0002",
                    "refresh_token": escaped,
                    "expires_in": 3599,
                    "scope": format!("eDiscovery.Read.All {escaped}"),
                }),
            ))
            .mount(&harness.identity)
            .await;
        let mut args = vec!["auth", "refresh"];
        if json {
            args.insert(0, "--json");
        }
        let run = harness.run(&args).await;
        assert_eq!(run.outcome.exit_code, 1);
        let text = format!("{}{}", run.stdout(), run.stderr());
        assert!(text.contains("different set of permissions"), "{text}");
        assert!(text.contains("purview auth login"), "{text}");
        for fragment in ["escaped-0001", "Read.All", "ReadWrite.All"] {
            assert!(!text.contains(fragment), "{fragment} in {text}");
        }
        // Nothing was stored.
        assert_eq!(
            harness.stored(ALEX).unwrap()["refresh_token"],
            "canary-refresh-0002"
        );
    }
}

#[tokio::test]
async fn an_explicit_blank_select_is_an_error_and_an_empty_variable_is_unset() {
    let harness = Harness::new().await;
    sign_in_alex(&harness).await;
    let run = harness.run(&["--select", "", "auth", "list"]).await;
    assert_eq!(run.outcome.exit_code, 1);
    assert!(
        run.stderr()
            .starts_with("Error: --select was given an empty value"),
        "{}",
        run.stderr()
    );
    let (mut env, captured) = harness.env();
    env.vars.insert("PURVIEW_SELECT".into(), "".into());
    env.vars.insert("PURVIEW_PLAIN".into(), "true".into());
    let outcome = ms_purview_cli::cli::execute_with(env, ["purview", "auth", "list"]).await;
    assert_eq!(outcome.exit_code, 0);
    assert_eq!(captured.stdout.text(), format!("{ALEX}\tAlex Wilber\t*\n"));
}

/// Signs in with the given claims, replacing `tid` and `oid` as asked.
async fn mount_login_as(harness: &Harness, claims_fixture: &str, edit: impl Fn(&mut Value)) {
    let mut claims = fixture(claims_fixture);
    edit(&mut claims);
    let encode = |value: &Value| {
        use base64::Engine;
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(value.to_string())
    };
    let mut body = fixture("token-graph.json");
    body["id_token"] = Value::from(format!(
        "{}.{}.",
        encode(&serde_json::json!({"alg": "none"})),
        encode(&claims)
    ));
    Mock::given(method("POST"))
        .and(path(token_path("devicecode")))
        .respond_with(json_response(200, fixture("device-code.json")))
        .mount(&harness.identity)
        .await;
    Mock::given(method("POST"))
        .and(path(token_path("token")))
        .and(Form::new(&[(
            "grant_type",
            "urn:ietf:params:oauth:grant-type:device_code",
        )]))
        .respond_with(json_response(200, body))
        .mount(&harness.identity)
        .await;
    Mock::given(method("POST"))
        .and(path(token_path("token")))
        .and(Form::new(&[("grant_type", "refresh_token")]))
        .respond_with(json_response(200, fixture("token-download.json")))
        .mount(&harness.identity)
        .await;
}

/// What a refused sign-in must leave: every account's file and credential
/// exactly as before.
struct Snapshot(Vec<(String, Vec<u8>, Value)>);

impl Snapshot {
    fn take(harness: &Harness, emails: &[&str]) -> Self {
        Self(
            emails
                .iter()
                .map(|email| {
                    (
                        (*email).to_owned(),
                        std::fs::read(harness.account_file(email)).unwrap(),
                        harness.stored(email).unwrap(),
                    )
                })
                .collect(),
        )
    }

    fn assert_unchanged(&self, harness: &Harness) {
        for (email, file, credential) in &self.0 {
            assert_eq!(
                &std::fs::read(harness.account_file(email)).unwrap(),
                file,
                "{email}"
            );
            assert_eq!(&harness.stored(email).unwrap(), credential, "{email}");
        }
    }
}

#[tokio::test]
async fn a_key_owned_by_another_object_id_is_refused_before_any_write() {
    let harness = Harness::new().await;
    sign_in_alex(&harness).await;
    let before = Snapshot::take(&harness, &[ALEX]);
    // The address was reassigned: same key, same registration, another oid.
    mount_login_as(&harness, "id-claims-preferred.json", |claims| {
        claims["oid"] = "00000000-0000-4000-8000-000000000099".into();
    })
    .await;
    let run = harness.run(&["--json", "auth", "login"]).await;
    assert_eq!(run.outcome.exit_code, 1);
    let message = run.json()["error"]["message"].as_str().unwrap().to_owned();
    assert!(message.contains("belongs to another identity"), "{message}");
    assert!(
        message.contains(&format!("purview auth logout --account {ALEX}")),
        "{message}"
    );
    before.assert_unchanged(&harness);
    // Even with the account-file write set to fail, as in the sequence that
    // once left the other identity's tokens under this key, nothing changes.
    let run = login_with_fault_as(&harness, LoginWrite::AccountFile, |claims| {
        claims["oid"] = "00000000-0000-4000-8000-000000000099".into();
    })
    .await;
    assert_eq!(run.outcome.exit_code, 1);
    before.assert_unchanged(&harness);
    // The first identity's tokens still refresh, through its own token.
    harness.identity.reset().await;
    mount_refresh(
        &harness,
        "canary-refresh-0002",
        json_response(
            200,
            token(
                "canary-graph-access-0002",
                "canary-refresh-0003",
                "https://graph.microsoft.com/eDiscovery.ReadWrite.All openid profile",
            ),
        ),
        "canary-refresh-0003",
        json_response(200, fixture("token-download.json")),
    )
    .await;
    let refresh = harness.run(&["auth", "refresh"]).await;
    assert_eq!(refresh.outcome.exit_code, 0, "{}", refresh.stderr());
    harness.identity.reset().await;
    mount_login_as(&harness, "id-claims-preferred.json", |claims| {
        claims["oid"] = "00000000-0000-4000-8000-000000000099".into();
    })
    .await;
    // Logging out frees the key, and the new identity can then sign in.
    harness.run(&["auth", "logout", "--account", ALEX]).await;
    let run = harness.run(&["auth", "login"]).await;
    assert_eq!(run.outcome.exit_code, 0, "{}", run.stderr());
    assert_eq!(
        harness.stored(ALEX).unwrap()["oid"],
        "00000000-0000-4000-8000-000000000099"
    );
}

#[tokio::test]
async fn a_key_owned_by_the_same_object_id_in_another_tenant_is_refused() {
    let harness = Harness::new().await;
    sign_in_alex(&harness).await;
    let before = Snapshot::take(&harness, &[ALEX]);
    mount_login_as(&harness, "id-claims-preferred.json", |claims| {
        claims["tid"] = "00000000-0000-4000-8000-000000000098".into();
    })
    .await;
    // The id token names another tenant; the sign-in endpoint is the same.
    let run = harness.run(&["auth", "login"]).await;
    assert_eq!(run.outcome.exit_code, 1);
    assert!(
        run.stderr().contains("belongs to another identity"),
        "{}",
        run.stderr()
    );
    before.assert_unchanged(&harness);
}

#[tokio::test]
async fn a_rename_onto_a_key_another_account_holds_is_refused_and_keeps_both() {
    let harness = Harness::new().await;
    sign_in_alex(&harness).await;
    sign_in_sam_too(&harness).await;
    let before = Snapshot::take(&harness, &[ALEX, "sam.taylor@contoso.example"]);
    // Alex, asked for by key and recognised by tid and oid, now has Sam's
    // address as preferred_username.
    mount_login_as(&harness, "id-claims-preferred.json", |claims| {
        claims["preferred_username"] = "sam.taylor@contoso.example".into();
        claims["upn"] = "sam.taylor@contoso.example".into();
    })
    .await;
    let run = harness.run(&["auth", "login", "--account", ALEX]).await;
    assert_eq!(run.outcome.exit_code, 1);
    assert!(
        run.stderr()
            .contains("the account key sam.taylor@contoso.example belongs to another identity"),
        "{}",
        run.stderr()
    );
    before.assert_unchanged(&harness);
}

#[tokio::test]
async fn a_rename_onto_a_free_key_signs_in_under_the_new_key() {
    let harness = Harness::new().await;
    sign_in_alex(&harness).await;
    mount_login_as(&harness, "id-claims-preferred.json", |claims| {
        claims["preferred_username"] = "alex.renamed@contoso.example".into();
    })
    .await;
    let run = harness
        .run(&["--json", "auth", "login", "--account", ALEX])
        .await;
    assert_eq!(run.outcome.exit_code, 0, "{}", run.stderr());
    assert_eq!(
        run.json()["results"]["account"],
        "alex.renamed@contoso.example"
    );
    let renamed = harness.stored("alex.renamed@contoso.example").unwrap();
    assert_eq!(renamed["oid"], "00000000-0000-4000-8000-000000000011");
    assert!(harness
        .account_file("alex.renamed@contoso.example")
        .exists());
}

#[tokio::test]
async fn refresh_refuses_tokens_of_another_object_id_than_the_account_file() {
    let harness = Harness::new().await;
    sign_in_alex(&harness).await;
    // A re-login under the same key and registration by another identity,
    // as an older release could have stored it: the credential's principal
    // differs from the account file's.
    let key = format!("purview:token:{ALEX}");
    let mut credential = harness.stored(ALEX).unwrap();
    credential["oid"] = "00000000-0000-4000-8000-000000000099".into();
    ms_purview_cli::secrets::store_value(harness.store.as_ref(), &key, &credential.to_string())
        .unwrap();
    mount_any_refresh(&harness).await;
    let run = harness
        .run(&["--json", "auth", "refresh", "--account", ALEX])
        .await;
    assert_eq!(run.outcome.exit_code, 1);
    let message = run.json()["error"]["message"].as_str().unwrap().to_owned();
    assert!(message.contains("belong to another identity"), "{message}");
    assert!(refresh_clients(&harness).await.is_empty());
    harness.assert_no_canaries(&run);
}

#[tokio::test]
async fn a_first_sign_in_whose_credential_write_commits_then_fails_keeps_nothing() {
    let harness = Harness::new().await;
    let run = login_with_fault(&harness, LoginWrite::Credential, CLIENT_ID).await;
    assert_eq!(run.outcome.exit_code, 1);
    assert!(
        run.stderr().contains("nothing from this sign-in was kept"),
        "{}",
        run.stderr()
    );
    harness.assert_store_empty();
}

#[tokio::test]
async fn a_credential_that_cannot_be_removed_after_a_failed_sign_in_is_named_for_logout() {
    for write in [LoginWrite::Credential, LoginWrite::AccountFile] {
        let harness = Harness::new().await;
        harness.store.fail_deletes(true);
        let run = login_with_fault(&harness, write, CLIENT_ID).await;
        harness.store.fail_deletes(false);
        assert_eq!(run.outcome.exit_code, 1, "{write:?}");
        let stderr = run.stderr();
        assert!(
            stderr.contains("removing them failed"),
            "{write:?}: {stderr}"
        );
        assert!(
            stderr.contains(&format!("purview auth logout --account {ALEX}")),
            "{stderr}"
        );
        assert_eq!(harness.credentials(), [ALEX], "{write:?}");
        assert!(!harness.account_file(ALEX).exists());
        // Logout removes a credential that has no account file.
        let logout = harness.run(&["auth", "logout", "--account", ALEX]).await;
        assert_eq!(logout.outcome.exit_code, 0, "{}", logout.stderr());
        harness.assert_store_empty();
    }
}

#[tokio::test]
async fn the_device_code_and_client_timers_are_told_apart() {
    // The client's own timeout is shorter than the time the code has left:
    // the poll endpoint is reached and the failure is a transport one.
    let harness = Harness::new().await;
    Mock::given(method("POST"))
        .and(path(token_path("devicecode")))
        .respond_with(json_response(200, fixture("device-code.json")))
        .mount(&harness.identity)
        .await;
    Mock::given(method("POST"))
        .and(path(token_path("token")))
        .respond_with(
            json_response(400, fixture("authorization-pending.json"))
                .set_delay(Duration::from_secs(3)),
        )
        .expect(1)
        .mount(&harness.identity)
        .await;
    let (mut env, captured) = harness.env();
    env.identity_timeout = Duration::from_millis(300);
    let outcome = ms_purview_cli::cli::execute_with(
        env,
        [
            "purview",
            "auth",
            "login",
            "--client-id",
            CLIENT_ID,
            "--tenant-id",
            TENANT_ID,
        ],
    )
    .await;
    assert_eq!(outcome.exit_code, 1);
    let stderr = captured.stderr.text();
    assert!(stderr.contains("enter the code CNTSO0001"), "{stderr}");
    assert!(
        stderr.contains("could not reach the identity platform: the request timed out"),
        "{stderr}"
    );
    assert!(!stderr.contains("expired"), "{stderr}");
    drop(harness);

    // The code has one second left and the client would wait ten: only the
    // device-code deadline can end the stalled poll.
    let harness = Harness::new().await;
    let mut code = fixture("device-code.json");
    code["expires_in"] = 6.into();
    Mock::given(method("POST"))
        .and(path(token_path("devicecode")))
        .respond_with(json_response(200, code))
        .mount(&harness.identity)
        .await;
    Mock::given(method("POST"))
        .and(path(token_path("token")))
        .respond_with(
            json_response(400, fixture("authorization-pending.json"))
                .set_delay(Duration::from_secs(3)),
        )
        .expect(1)
        .mount(&harness.identity)
        .await;
    let (mut env, captured) = harness.env();
    env.identity_timeout = Duration::from_secs(10);
    let started = std::time::Instant::now();
    let outcome = ms_purview_cli::cli::execute_with(
        env,
        [
            "purview",
            "auth",
            "login",
            "--client-id",
            CLIENT_ID,
            "--tenant-id",
            TENANT_ID,
        ],
    )
    .await;
    assert_eq!(outcome.exit_code, 1);
    let stderr = captured.stderr.text();
    assert!(stderr.contains("the device code expired"), "{stderr}");
    assert!(!stderr.contains("could not reach"), "{stderr}");
    assert!(
        started.elapsed() < Duration::from_secs(3),
        "{:?}",
        started.elapsed()
    );
}

/// `auth login` with the given claim edits and one write made to fail.
async fn login_with_fault_as(
    harness: &Harness,
    write: LoginWrite,
    edit: impl Fn(&mut Value),
) -> Run {
    mount_login_as(harness, "id-claims-preferred.json", edit).await;
    let (mut env, captured) = harness.env();
    env.login_write_fault = Some(write);
    let outcome = ms_purview_cli::cli::execute_with(env, ["purview", "auth", "login"]).await;
    Run { outcome, captured }
}

const OTHER_OID: &str = "00000000-0000-4000-8000-000000000099";

/// Waits until the mock identity platform has received `count` requests.
async fn wait_for_requests(harness: &Harness, count: usize) {
    for _ in 0..200 {
        if harness.identity.received_requests().await.unwrap().len() >= count {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("the identity platform never received {count} requests");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn overlapping_sign_ins_under_one_key_never_both_succeed() {
    let harness = Harness::new().await;
    // Another login holds Alex's account lock while it writes.
    std::fs::create_dir_all(harness.account_locks().dir).unwrap();
    let held =
        ms_purview_cli::secrets::CredentialLock::acquire(&harness.lock_path(ALEX), Duration::ZERO)
            .unwrap();
    // A second identity signs in under the same key; it finishes in the
    // browser, then waits for the lock.
    mount_login_as(&harness, "id-claims-preferred.json", |claims| {
        claims["oid"] = OTHER_OID.into();
    })
    .await;
    let second_done = std::sync::atomic::AtomicBool::new(false);
    let second = async {
        let run = harness
            .run(&[
                "auth",
                "login",
                "--client-id",
                CLIENT_ID,
                "--tenant-id",
                TENANT_ID,
            ])
            .await;
        second_done.store(true, std::sync::atomic::Ordering::SeqCst);
        run
    };
    let holder = async {
        // device code, one poll, the download redemption
        wait_for_requests(&harness, 3).await;
        tokio::time::sleep(Duration::from_millis(200)).await;
        let waited = !second_done.load(std::sync::atomic::Ordering::SeqCst);
        // The lock holder completes the first identity's sign-in.
        harness.identity.reset().await;
        mount_login(
            &harness,
            "id-claims-preferred.json",
            json_response(200, fixture("token-download.json")),
        )
        .await;
        let (mut env, captured) = harness.env();
        env.account_locks = None; // it is the holder
        let first = ms_purview_cli::cli::execute_with(
            env,
            [
                "purview",
                "auth",
                "login",
                "--client-id",
                CLIENT_ID,
                "--tenant-id",
                TENANT_ID,
            ],
        )
        .await;
        drop(held);
        (waited, first, captured)
    };
    let (second, (waited, first, captured)) = tokio::join!(second, holder);
    assert!(waited, "the second login did not wait for the lock");
    assert_eq!(first.exit_code, 0, "{}", captured.stderr.text());
    assert_eq!(second.outcome.exit_code, 1);
    assert!(
        second.stderr().contains("belongs to another identity"),
        "{}",
        second.stderr()
    );
    assert_eq!(
        harness.stored(ALEX).unwrap()["oid"],
        "00000000-0000-4000-8000-000000000011"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_sign_in_that_cannot_get_the_lock_stores_nothing() {
    let harness = Harness::new().await;
    std::fs::create_dir_all(harness.account_locks().dir).unwrap();
    let _held =
        ms_purview_cli::secrets::CredentialLock::acquire(&harness.lock_path(ALEX), Duration::ZERO)
            .unwrap();
    mount_login(
        &harness,
        "id-claims-preferred.json",
        json_response(200, fixture("token-download.json")),
    )
    .await;
    let (mut env, captured) = harness.env();
    env.account_locks = Some(ms_purview_cli::secrets::AccountLocks {
        wait: Duration::from_millis(300),
        ..harness.account_locks()
    });
    let outcome = ms_purview_cli::cli::execute_with(
        env,
        [
            "purview",
            "--json",
            "auth",
            "login",
            "--client-id",
            CLIENT_ID,
            "--tenant-id",
            TENANT_ID,
        ],
    )
    .await;
    assert_eq!(outcome.exit_code, 1);
    let printed: Value = serde_json::from_str(&captured.stdout.text()).unwrap();
    assert_eq!(printed["error"]["code"], "CredentialLockBusy");
    harness.assert_store_empty();
    assert!(!harness.account_file(ALEX).exists());
}

#[tokio::test]
async fn logout_names_an_exact_key_before_matching_a_upn() {
    let harness = Harness::new().await;
    sign_in_alex(&harness).await;
    // An orphan credential whose key is Alex's recorded upn.
    let orphan = "purview:token:alex.w@contoso.example";
    harness.store.set_password(orphan, "{damaged").unwrap();
    let run = harness
        .run(&["auth", "logout", "--account", "alex.w@contoso.example"])
        .await;
    assert_eq!(run.outcome.exit_code, 0, "{}", run.stderr());
    assert!(!harness.store.keys().contains(&orphan.to_owned()));
    // Alex, whose upn that is, is untouched.
    assert_eq!(harness.credentials(), [ALEX]);
    assert!(harness.account_file(ALEX).exists());
}

#[tokio::test]
async fn logout_sweeps_headerless_chunks_and_damaged_entries_in_the_windows_layout() {
    let harness = Harness::with_store(MemoryStore::chunked(64)).await;
    let key = format!("purview:token:{ALEX}");
    // Chunks a failed first write left without a header, in both slots.
    harness
        .store
        .set_secret(&format!("{key}:0"), b"canary-refresh-0001")
        .unwrap();
    harness
        .store
        .set_secret(&format!("{key}:s1:3"), b"canary-refresh-0002")
        .unwrap();
    let run = harness.run(&["auth", "logout", "--account", ALEX]).await;
    assert_eq!(run.outcome.exit_code, 0, "{}", run.stderr());
    harness.assert_store_empty();

    // A primary entry that is not UTF-8 and not a credential.
    harness.store.set_secret(&key, &[0xff, 0xfe, 0x00]).unwrap();
    let run = harness.run(&["auth", "logout", "--account", ALEX]).await;
    assert_eq!(run.outcome.exit_code, 0, "{}", run.stderr());
    harness.assert_store_empty();
}

#[tokio::test]
async fn a_first_sign_in_whose_header_write_fails_sweeps_its_chunks() {
    let harness = Harness::with_store(MemoryStore::chunked(64)).await;
    mount_login(
        &harness,
        "id-claims-preferred.json",
        json_response(200, fixture("token-download.json")),
    )
    .await;
    harness.store.fail_headers(true);
    let run = harness
        .run(&[
            "auth",
            "login",
            "--client-id",
            CLIENT_ID,
            "--tenant-id",
            TENANT_ID,
        ])
        .await;
    harness.store.fail_headers(false);
    assert_eq!(run.outcome.exit_code, 1);
    assert!(
        run.stderr().contains("nothing from this sign-in was kept"),
        "{}",
        run.stderr()
    );
    harness.assert_store_empty();
    harness.assert_no_canaries(&run);
}

/// Signs Alex in and returns the run, with the store already holding
/// `entry` under Alex's key and an account file as `file` says.
async fn sign_in_over(harness: &Harness, entry: Option<&str>, file: Option<Value>) -> Run {
    if let Some(entry) = entry {
        harness
            .store
            .set_password(&format!("purview:token:{ALEX}"), entry)
            .unwrap();
    }
    if let Some(file) = file {
        std::fs::create_dir_all(harness.config_dir().join("accounts")).unwrap();
        std::fs::write(harness.account_file(ALEX), file.to_string()).unwrap();
    }
    mount_login(
        harness,
        "id-claims-preferred.json",
        json_response(200, fixture("token-download.json")),
    )
    .await;
    harness
        .run(&[
            "auth",
            "login",
            "--client-id",
            CLIENT_ID,
            "--tenant-id",
            TENANT_ID,
        ])
        .await
}

fn alex_file() -> Value {
    serde_json::json!({
        "email": ALEX,
        "upn": "alex.w@contoso.example",
        "oid": "00000000-0000-4000-8000-000000000011",
        "display_name": "Alex Wilber",
        "tenant_id": TENANT_ID,
        "client_id": CLIENT_ID,
        "login_time": "2026-01-05T09:00:10Z",
    })
}

#[tokio::test]
async fn a_key_held_only_by_a_differently_stamped_credential_is_refused() {
    let harness = Harness::new().await;
    let entry = serde_json::json!({
        "version": 1, "email": ALEX, "tid": TENANT_ID, "oid": OTHER_OID,
        "client_id": CLIENT_ID, "tenant_id": TENANT_ID, "refresh_token": "canary-other-refresh-0001",
        "graph": {"access_token": "canary-other-access-0001", "scope": "eDiscovery.ReadWrite.All"},
    })
    .to_string();
    let run = sign_in_over(&harness, Some(&entry), None).await;
    assert_eq!(run.outcome.exit_code, 1);
    assert!(
        run.stderr().contains("belongs to another identity"),
        "{}",
        run.stderr()
    );
    assert!(
        run.stderr()
            .contains(&format!("purview auth logout --account {ALEX}")),
        "{}",
        run.stderr()
    );
    assert_eq!(harness.stored(ALEX).unwrap()["oid"], OTHER_OID);
    assert!(!harness.account_file(ALEX).exists());
}

#[tokio::test]
async fn a_partly_recorded_or_unreadable_destination_counts_as_owned() {
    // A credential that keeps a different oid but lacks its tid.
    let harness = Harness::new().await;
    let partial = serde_json::json!({"version": 1, "email": ALEX, "oid": OTHER_OID}).to_string();
    let run = sign_in_over(&harness, Some(&partial), None).await;
    assert_eq!(run.outcome.exit_code, 1, "partial credential");
    assert!(!harness.account_file(ALEX).exists());

    // A damaged credential and no account file to vouch for the key.
    let harness = Harness::new().await;
    let run = sign_in_over(&harness, Some("{damaged"), None).await;
    assert_eq!(run.outcome.exit_code, 1, "damaged credential");
    assert!(
        run.stderr().contains("purview auth logout --account"),
        "{}",
        run.stderr()
    );

    // An account file with both ids but a malformed field, and no credential.
    let harness = Harness::new().await;
    let mut malformed = alex_file();
    malformed["display_name"] = 5.into();
    let run = sign_in_over(&harness, None, Some(malformed.clone())).await;
    assert_eq!(run.outcome.exit_code, 1, "malformed account file");
    harness.assert_store_empty();
    assert_eq!(
        serde_json::from_slice::<Value>(&std::fs::read(harness.account_file(ALEX)).unwrap())
            .unwrap(),
        malformed
    );

    // An account file that records the oid but not the tid.
    let harness = Harness::new().await;
    let mut partial_file = alex_file();
    partial_file["tenant_id"] = "".into();
    let run = sign_in_over(&harness, None, Some(partial_file)).await;
    assert_eq!(run.outcome.exit_code, 1, "partly recorded account file");
    harness.assert_store_empty();
}

#[tokio::test]
async fn a_damaged_credential_is_repaired_when_the_account_file_vouches_for_the_identity() {
    let harness = Harness::new().await;
    let run = sign_in_over(&harness, Some("{damaged"), Some(alex_file())).await;
    assert_eq!(run.outcome.exit_code, 0, "{}", run.stderr());
    let stored = harness.stored(ALEX).unwrap();
    assert_eq!(stored["oid"], "00000000-0000-4000-8000-000000000011");
    assert_eq!(stored["refresh_token"], "canary-refresh-0002");
}

#[tokio::test]
async fn a_lock_file_name_never_carries_an_account_claim() {
    // An account name holding a value the sign-in registers as a secret:
    // the account file is refused, the sign-in is rolled back, and the lock
    // file taken for that key must not carry the value in its name.
    let harness = Harness::new().await;
    mount_login_as(&harness, "id-claims-preferred.json", |claims| {
        claims["preferred_username"] = "canary-refresh-0001@contoso.example".into();
    })
    .await;
    let run = harness
        .run(&[
            "auth",
            "login",
            "--client-id",
            CLIENT_ID,
            "--tenant-id",
            TENANT_ID,
        ])
        .await;
    assert_eq!(run.outcome.exit_code, 1);
    harness.assert_store_empty();
    let locks: Vec<_> = std::fs::read_dir(harness.account_locks().dir)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    assert_eq!(locks.len(), 1, "{locks:?}");
    assert_eq!(locks[0].len(), 64 + ".lock".len(), "{locks:?}");
    harness.assert_no_canaries(&run);
}

/// Holds Alex's account lock, and gives commands a short wait for it.
fn hold_alex_lock(harness: &Harness) -> (ms_purview_cli::secrets::CredentialLock, Env, Captured) {
    std::fs::create_dir_all(harness.account_locks().dir).unwrap();
    let held =
        ms_purview_cli::secrets::CredentialLock::acquire(&harness.lock_path(ALEX), Duration::ZERO)
            .unwrap();
    let (mut env, captured) = harness.env();
    env.account_locks = Some(ms_purview_cli::secrets::AccountLocks {
        wait: Duration::from_millis(300),
        ..harness.account_locks()
    });
    (held, env, captured)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn logout_cannot_delete_while_the_account_lock_is_held() {
    let harness = Harness::new().await;
    sign_in_alex(&harness).await;
    let before = Snapshot::take(&harness, &[ALEX]);
    let (_held, env, captured) = hold_alex_lock(&harness);
    let outcome =
        ms_purview_cli::cli::execute_with(env, ["purview", "--json", "auth", "logout"]).await;
    assert_eq!(outcome.exit_code, 1);
    let printed: Value = serde_json::from_str(&captured.stdout.text()).unwrap();
    assert_eq!(printed["error"]["code"], "CredentialLockBusy");
    before.assert_unchanged(&harness);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn refresh_cannot_commit_while_the_account_lock_is_held() {
    let harness = Harness::new().await;
    sign_in_alex(&harness).await;
    let before = Snapshot::take(&harness, &[ALEX]);
    mount_any_refresh(&harness).await;
    let (_held, env, captured) = hold_alex_lock(&harness);
    let outcome =
        ms_purview_cli::cli::execute_with(env, ["purview", "--json", "auth", "refresh"]).await;
    assert_eq!(outcome.exit_code, 1);
    let printed: Value = serde_json::from_str(&captured.stdout.text()).unwrap();
    assert_eq!(printed["error"]["code"], "CredentialLockBusy");
    before.assert_unchanged(&harness);
}

#[cfg(unix)]
#[tokio::test]
async fn exact_key_logout_refuses_a_linked_account_file_before_deleting() {
    let harness = Harness::new().await;
    sign_in_alex(&harness).await;
    let path = harness.account_file(ALEX);
    let elsewhere = harness.root.path().join("elsewhere.json");
    std::fs::rename(&path, &elsewhere).unwrap();
    std::os::unix::fs::symlink(&elsewhere, &path).unwrap();
    let run = harness
        .run(&["--json", "auth", "logout", "--account", ALEX])
        .await;
    assert_eq!(run.outcome.exit_code, 1);
    let message = run.json()["error"]["message"].as_str().unwrap().to_owned();
    assert!(message.contains("is a link"), "{message}");
    assert!(!message.contains(ALEX), "{message}");
    assert_eq!(harness.credentials(), [ALEX]);
    assert!(elsewhere.exists());
}

#[tokio::test]
async fn an_undecodable_primary_is_repaired_when_the_account_file_vouches() {
    for store in [MemoryStore::chunked(64), MemoryStore::windows(64)] {
        repair_an_undecodable_primary(store).await;
    }
}

async fn repair_an_undecodable_primary(store: MemoryStore) {
    let harness = Harness::with_store(store).await;
    harness
        .store
        .set_secret(&format!("purview:token:{ALEX}"), &[0xff, 0xfe, 0x00])
        .unwrap();
    let run = sign_in_over(&harness, None, Some(alex_file())).await;
    assert_eq!(run.outcome.exit_code, 0, "{}", run.stderr());
    assert_eq!(harness.credentials(), [ALEX]);
    assert_eq!(
        harness.stored(ALEX).unwrap()["refresh_token"],
        "canary-refresh-0002"
    );
}

// Browser sign-in (`auth login --browser`).

const AUTH_CODE: &str = "canary-auth-code-0001";

/// Mounts the code exchange, answered with `exchange`, and the download
/// redemption.
async fn mount_browser_login(harness: &Harness, exchange: impl wiremock::Respond + 'static) {
    Mock::given(method("POST"))
        .and(path(token_path("token")))
        .and(Form::new(&[
            ("grant_type", "authorization_code"),
            ("code", AUTH_CODE),
            ("client_id", CLIENT_ID),
        ]))
        .respond_with(exchange)
        .expect(1)
        .mount(&harness.identity)
        .await;
    Mock::given(method("POST"))
        .and(path(token_path("token")))
        .and(Form::new(&[
            ("grant_type", "refresh_token"),
            ("refresh_token", "canary-refresh-0001"),
        ]))
        .respond_with(json_response(200, fixture("token-download.json")))
        .mount(&harness.identity)
        .await;
}

fn browser_login_args(extra: &[&'static str]) -> Vec<&'static str> {
    let mut args = vec![
        "auth",
        "login",
        "--browser",
        "--client-id",
        CLIENT_ID,
        "--tenant-id",
        TENANT_ID,
    ];
    args.extend_from_slice(extra);
    args
}

/// Sets the browser, and a sign-in timeout short enough for a test.
fn with_browser(browser: &std::sync::Arc<ScriptedBrowser>) -> impl FnOnce(&mut Env, &Captured) {
    let browser = browser.clone();
    move |env: &mut Env, captured: &Captured| {
        *browser.stderr.lock().unwrap() = Some(captured.stderr.clone());
        env.browser = browser;
        env.browser_timeout = Duration::from_secs(20);
    }
}

/// The value of a form field, or a failure that names only the field.
fn form_field(form: &[(String, String)], name: &str) -> String {
    form.iter()
        .find(|(key, _)| key == name)
        .map(|(_, value)| value.clone())
        .unwrap_or_else(|| panic!("no {name} field in the request"))
}

/// A token endpoint that refuses the code exchange and quotes the code and
/// the verifier it was sent in its description, as a careless service
/// might.
struct RefusalQuotingTheExchange;

impl wiremock::Respond for RefusalQuotingTheExchange {
    fn respond(&self, request: &wiremock::Request) -> ResponseTemplate {
        let form = form_of(request);
        json_response(
            400,
            serde_json::json!({
                "error": "invalid_grant",
                "error_description": format!(
                    "AADSTS70008: The provided authorization code has expired. code {} verifier {}",
                    form_field(&form, "code"),
                    form_field(&form, "code_verifier")
                ),
                "error_codes": [70008],
                "trace_id": "00000000-0000-4000-8000-000000000031",
            }),
        )
    }
}

#[tokio::test]
async fn browser_login_uses_pkce_on_the_loopback_redirect_and_stores_both_tokens() {
    let harness = Harness::new().await;
    mount_browser_login(
        &harness,
        json_response(200, graph_token("id-claims-preferred.json")),
    )
    .await;
    // A favicon request and an answer for another sign-in come first; the
    // listener answers both and keeps waiting.
    let browser = ScriptedBrowser::new(&[
        "/favicon.ico",
        "/callback?code=canary-auth-code-0001&state=another-sign-in",
        "/callback?code=canary-auth-code-0001&state={state}&session_state=x",
    ]);
    let mut args = vec!["--json"];
    args.extend(browser_login_args(&[]));
    let run = harness.run_with(&args, with_browser(&browser)).await;
    assert_eq!(run.outcome.exit_code, 0, "{}", run.stderr());
    assert_eq!(
        browser.answers(3),
        [
            "HTTP/1.1 404 Not Found",
            "HTTP/1.1 400 Bad Request",
            "HTTP/1.1 200 OK"
        ]
    );
    assert_eq!(run.json()["results"]["account"], ALEX);
    assert_eq!(run.json()["results"]["downloadReady"], true);

    // The authorization request.
    let opened = browser.opened();
    assert_eq!(
        opened.path(),
        format!("/{TENANT_ID}/oauth2/v2.0/authorize").as_str()
    );
    let redirect_uri = query_value(&opened, "redirect_uri");
    let redirect = url::Url::parse(&redirect_uri).unwrap();
    assert_eq!(
        (redirect.scheme(), redirect.host_str(), redirect.path()),
        ("http", Some("localhost"), "/callback")
    );
    assert!(redirect.port().is_some_and(|port| port > 0));
    for (name, value) in [
        ("client_id", CLIENT_ID),
        ("response_type", "code"),
        ("response_mode", "query"),
        ("code_challenge_method", "S256"),
        ("prompt", "select_account"),
        (
            "scope",
            "https://graph.microsoft.com/eDiscovery.ReadWrite.All offline_access openid profile",
        ),
    ] {
        assert_eq!(query_value(&opened, name), value, "{name}");
    }
    assert!(query_value(&opened, "state").len() >= 32);
    // The address is printed too, for a browser that did not open.
    assert!(run.stderr().contains(opened.as_str()), "{}", run.stderr());

    // The exchange sends the verifier whose S256 hash is the challenge,
    // with the same redirect and scope; no device code was requested.
    let requests = harness.identity.received_requests().await.unwrap();
    assert!(requests
        .iter()
        .all(|request| !request.url.path().ends_with("/devicecode")));
    let exchange = form_of(&requests[0]);
    let field = |name: &str| form_field(&exchange, name);
    use base64::Engine;
    use sha2::Digest;
    let challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(sha2::Sha256::digest(field("code_verifier").as_bytes()));
    assert!(
        challenge == query_value(&opened, "code_challenge"),
        "the verifier does not match the challenge"
    );
    assert_eq!(field("redirect_uri"), redirect_uri);
    assert_eq!(field("scope"), query_value(&opened, "scope"));

    let stored = harness.stored(ALEX).expect("a stored credential");
    assert_eq!(stored["refresh_token"], "canary-refresh-0002");
    assert_eq!(
        stored["download"]["access_token"],
        "canary-download-access-0001"
    );
    harness.assert_no_canaries(&run);
}

#[tokio::test]
async fn an_idle_connection_does_not_hold_up_the_answer() {
    let harness = Harness::new().await;
    mount_browser_login(
        &harness,
        json_response(200, graph_token("id-claims-preferred.json")),
    )
    .await;
    let browser = ScriptedBrowser::new(&[
        "<idle>",
        "<idle>",
        "/callback?code=canary-auth-code-0001&state={state}",
    ]);
    let run = harness
        .run_with(&browser_login_args(&[]), with_browser(&browser))
        .await;
    assert_eq!(run.outcome.exit_code, 0, "{}", run.stderr());
    // Served one at a time, each idle connection would hold the answer
    // back for the 10-second read timeout: 20 seconds for the two, which
    // the 20-second sign-in timeout would cut off first. Only the answer
    // is timed, not the token exchange after it.
    let answers = browser.timed_answers(1);
    assert_eq!(answers.len(), 1, "{answers:?}");
    let (status, answered) = &answers[0];
    assert_eq!(status, "HTTP/1.1 200 OK");
    assert!(*answered < Duration::from_secs(9), "{answered:?}");
}

#[tokio::test]
async fn a_browser_that_does_not_open_leaves_the_printed_address_working() {
    let harness = Harness::new().await;
    mount_browser_login(
        &harness,
        json_response(200, graph_token("id-claims-preferred.json")),
    )
    .await;
    let browser = std::sync::Arc::new(ScriptedBrowser {
        visits: vec!["/callback?code=canary-auth-code-0001&state={state}".into()],
        fail_open: true,
        ..ScriptedBrowser::default()
    });
    let run = harness
        .run_with(
            &browser_login_args(&["--read-only"]),
            with_browser(&browser),
        )
        .await;
    assert_eq!(run.outcome.exit_code, 0, "{}", run.stderr());
    let stderr = run.stderr();
    assert!(
        stderr.contains("warning: could not open the browser (no browser found)"),
        "{stderr}"
    );
    assert!(
        query_value(&browser.opened(), "scope").contains("/eDiscovery.Read.All "),
        "{}",
        browser.opened()
    );
    assert_eq!(browser.answers(1), ["HTTP/1.1 200 OK"]);
    assert!(harness.stored(ALEX).is_some());
    harness.assert_no_canaries(&run);
}

#[tokio::test]
async fn a_refusal_in_the_browser_stores_nothing_and_redeems_nothing() {
    let harness = Harness::new().await;
    let browser = ScriptedBrowser::new(&[
        "/callback?state={state}&error=access_denied&error_description=AADSTS65004%3A+User+declined",
    ]);
    let run = harness
        .run_with(&browser_login_args(&[]), with_browser(&browser))
        .await;
    assert_eq!(run.outcome.exit_code, 1);
    let stderr = run.stderr();
    assert!(
        stderr.contains("sign-in failed: the browser sign-in was refused: access_denied: AADSTS65004: User declined"),
        "{stderr}"
    );
    assert_eq!(browser.answers(1), ["HTTP/1.1 400 Bad Request"]);
    assert!(harness
        .identity
        .received_requests()
        .await
        .unwrap()
        .is_empty());
    harness.assert_store_empty();
    assert!(!harness.account_file(ALEX).exists());
}

#[tokio::test]
async fn a_refused_code_exchange_keeps_the_code_and_verifier_out_of_output() {
    let harness = Harness::new().await;
    mount_browser_login(&harness, RefusalQuotingTheExchange).await;
    let browser = ScriptedBrowser::new(&["/callback?code=canary-auth-code-0001&state={state}"]);
    let mut args = vec!["--json"];
    args.extend(browser_login_args(&[]));
    let run = harness.run_with(&args, with_browser(&browser)).await;
    assert_eq!(run.outcome.exit_code, 1);
    // The scan comes first, so that no failure message below can show a
    // value the command failed to redact.
    let requests = harness.identity.received_requests().await.unwrap();
    let verifier = form_field(&form_of(&requests[0]), "code_verifier");
    harness.assert_absent(&run, &[AUTH_CODE, verifier.as_str()]);
    let message = run.json()["error"]["message"].as_str().unwrap().to_owned();
    assert!(
        message.contains(
            "redeeming the browser sign-in's authorization code failed with HTTP 400: \
             invalid_grant: AADSTS70008"
        ),
        "{message}"
    );
    harness.assert_store_empty();
    harness.assert_no_canaries(&run);
}

#[tokio::test]
async fn a_browser_that_never_comes_back_times_out_and_stores_nothing() {
    let harness = Harness::new().await;
    // A browser that opens but never follows the redirect.
    let browser = ScriptedBrowser::new(&[]);
    let configure = with_browser(&browser);
    let run = harness
        .run_with(&browser_login_args(&[]), |env, captured| {
            configure(env, captured);
            env.browser_timeout = Duration::from_millis(300);
        })
        .await;
    assert_eq!(run.outcome.exit_code, 1);
    let stderr = run.stderr();
    assert!(
        stderr.contains("the browser sign-in did not finish within 0 seconds"),
        "{stderr}"
    );
    assert!(stderr.contains("leave out --browser"), "{stderr}");
    assert!(harness
        .identity
        .received_requests()
        .await
        .unwrap()
        .is_empty());
    harness.assert_store_empty();
}

#[tokio::test]
async fn browser_login_under_no_input_is_refused_before_the_browser_opens() {
    let harness = Harness::new().await;
    let browser = ScriptedBrowser::new(&[]);
    let mut args = vec!["--no-input"];
    args.extend(browser_login_args(&[]));
    let run = harness.run_with(&args, with_browser(&browser)).await;
    assert_eq!(run.outcome.exit_code, 1);
    assert!(run.stderr().contains("--no-input"), "{}", run.stderr());
    assert!(browser.opened.lock().unwrap().is_empty());
    assert!(harness
        .identity
        .received_requests()
        .await
        .unwrap()
        .is_empty());
}

const CASES_PATH: &str = "/v1.0/security/cases/ediscoveryCases";
const GRAPH_SCOPE: &str = "https://graph.microsoft.com/eDiscovery.ReadWrite.All openid profile";

/// Mounts the `auth status` read for `token`, answered by `answer`.
async fn mount_probe(harness: &Harness, token: &str, answer: ResponseTemplate) {
    Mock::given(method("GET"))
        .and(path(CASES_PATH))
        .and(wiremock::matchers::query_param("$top", "1"))
        .and(wiremock::matchers::header(
            "authorization",
            format!("Bearer {token}").as_str(),
        ))
        .respond_with(answer)
        .mount(&harness.graph)
        .await;
}

async fn graph_requests(harness: &Harness) -> usize {
    harness.graph.received_requests().await.unwrap().len()
}

async fn identity_requests(harness: &Harness) -> usize {
    harness.identity.received_requests().await.unwrap().len()
}

#[tokio::test]
async fn status_reads_one_case_with_the_stored_token_and_never_sends_the_download_token() {
    let harness = Harness::new().await;
    sign_in_alex(&harness).await;
    mount_probe(
        &harness,
        "canary-graph-access-0001",
        json_response(
            200,
            graph_fixture("cases-list-top1.json", &harness.graph.uri()),
        ),
    )
    .await;
    let run = harness.run(&["--json", "auth", "status"]).await;
    assert_eq!(run.outcome.exit_code, 0, "{}", run.stderr());
    assert_eq!(
        run.json(),
        serde_json::json!({
            "results": {
                "account": ALEX,
                "upn": "alex.w@contoso.example",
                "tenantId": TENANT_ID,
                "clientId": CLIENT_ID,
                "graphScope": GRAPH_SCOPE,
                "graphExpiresAt": "2026-01-05T10:11:21Z",
                "downloadScope": "b26e684c-5068-4120-a679-64a5d2c909d9/eDiscovery.Download.Read",
                "downloadExpiresAt": "2026-01-05T10:00:09Z",
                "purviewRole": "ok",
                "purviewRoleDetail": null,
            },
            "count": 1,
        })
    );
    assert_eq!(graph_requests(&harness).await, 1);
    // No refresh and no download redemption.
    assert_eq!(identity_requests(&harness).await, 0);
    assert!(run.stderr().is_empty(), "{}", run.stderr());
    harness.assert_no_canaries(&run);
}

#[tokio::test]
async fn status_reports_denied_for_a_403_and_unknown_for_other_failures() {
    let harness = Harness::new().await;
    sign_in_alex(&harness).await;
    mount_probe(
        &harness,
        "canary-graph-access-0001",
        json_response(403, graph_fixture("error-403.json", &harness.graph.uri())),
    )
    .await;
    let run = harness.run(&["auth", "status"]).await;
    assert_eq!(run.outcome.exit_code, 0, "{}", run.stderr());
    let text = run.stdout();
    assert!(
        text.contains(
            "Purview role: denied (Microsoft Graph returned HTTP 403: Forbidden: Caller does not \
             have the required eDiscovery role."
        ),
        "{text}"
    );
    assert!(
        text.starts_with(&format!("Account: {ALEX}\nTenant: {TENANT_ID}\n")),
        "{text}"
    );
    assert!(
        text.contains(
            "Download scope: b26e684c-5068-4120-a679-64a5d2c909d9/eDiscovery.Download.Read\n\
             Download token expires: 2026-01-05T10:00:09Z"
        ),
        "{text}"
    );

    for (answer, attempts) in [
        (
            json_response(
                500,
                serde_json::json!({"error": {"code": "InternalServerError"}}),
            ),
            3,
        ),
        (
            json_response(404, serde_json::json!({"error": {"code": "NotFound"}})),
            1,
        ),
        (ResponseTemplate::new(200).set_body_string("not json"), 1),
    ] {
        harness.graph.reset().await;
        mount_probe(&harness, "canary-graph-access-0001", answer).await;
        let run = harness.run(&["--json", "auth", "status"]).await;
        assert_eq!(run.outcome.exit_code, 0, "{}", run.stderr());
        let results = &run.json()["results"];
        assert_eq!(results["purviewRole"], "unknown", "{results}");
        assert!(results["purviewRoleDetail"].is_string(), "{results}");
        assert_eq!(graph_requests(&harness).await, attempts);
    }
}

#[tokio::test]
async fn status_marks_an_expired_download_token_without_renewing_it() {
    let harness = Harness::new().await;
    sign_in_alex(&harness).await;
    // Past the download token's expiry, inside the Graph token's.
    harness.clock.advance(Duration::from_secs(3700));
    mount_probe(
        &harness,
        "canary-graph-access-0001",
        json_response(
            200,
            graph_fixture("cases-list-top1.json", &harness.graph.uri()),
        ),
    )
    .await;
    let run = harness.run(&["auth", "status"]).await;
    assert_eq!(run.outcome.exit_code, 0, "{}", run.stderr());
    assert!(
        run.stdout().contains(
            "Download token expires: 2026-01-05T10:00:09Z (expired; 'purview auth refresh' \
             renews it)"
        ),
        "{}",
        run.stdout()
    );
    assert_eq!(identity_requests(&harness).await, 0);
}

#[cfg(unix)]
#[tokio::test]
async fn a_trace_directory_that_cannot_be_written_stops_before_any_request() {
    use std::os::unix::fs::PermissionsExt;
    let harness = Harness::new().await;
    sign_in_alex(&harness).await;
    // Past the Graph token's expiry, so a request would start with a refresh.
    harness.clock.advance(Duration::from_secs(5000));
    let trace = harness.root.path().join("read-only");
    std::fs::create_dir(&trace).unwrap();
    std::fs::set_permissions(&trace, std::fs::Permissions::from_mode(0o500)).unwrap();
    // A privileged runner can write regardless of the mode; there is
    // nothing to test then.
    if std::fs::write(trace.join("probe"), b"").is_ok() {
        return;
    }
    let trace_arg = trace.display().to_string();
    let run = harness
        .run(&["--json", "--trace", &trace_arg, "auth", "status"])
        .await;
    std::fs::set_permissions(&trace, std::fs::Permissions::from_mode(0o700)).unwrap();
    assert_eq!(run.outcome.exit_code, 1);
    let message = run.json()["error"]["message"].as_str().unwrap().to_owned();
    assert!(message.contains("opening the trace directory"), "{message}");
    // Under --json a failure leaves stderr empty, warnings included.
    assert!(run.stderr().is_empty(), "{}", run.stderr());
    assert_eq!(graph_requests(&harness).await, 0);
    assert_eq!(identity_requests(&harness).await, 0);
}

#[tokio::test]
async fn a_signed_url_in_a_graph_error_reaches_no_output_or_trace_with_its_signature() {
    let harness = Harness::new().await;
    sign_in_alex(&harness).await;
    let signed = format!(
        "{}/v1.0/files/O'Brien.pdf?sig=canary-sig-0007&se=2026",
        harness.graph.uri()
    );
    mount_probe(
        &harness,
        "canary-graph-access-0001",
        json_response(
            403,
            serde_json::json!({"error": {
                "code": "Forbidden",
                "message": format!("no role; see '{signed}'."),
                "target": signed,
            }}),
        ),
    )
    .await;
    let trace = harness.root.path().join("trace");
    let trace_arg = trace.display().to_string();
    for args in [
        vec!["auth", "status"],
        vec!["--json", "--trace", &trace_arg, "auth", "status"],
    ] {
        let run = harness.run(&args).await;
        assert_eq!(run.outcome.exit_code, 0, "{}", run.stderr());
        if args[0] == "--json" {
            let detail = run.json()["results"]["purviewRoleDetail"]
                .as_str()
                .unwrap()
                .to_owned();
            assert!(detail.contains("O'Brien.pdf?REDACTED"), "{detail}");
        } else {
            assert!(
                run.stdout().contains("Purview role: denied"),
                "{}",
                run.stdout()
            );
        }
        harness.assert_absent(&run, &["canary-sig-0007"]);
    }
    assert_eq!(std::fs::read_dir(&trace).unwrap().count(), 1);
}

#[tokio::test]
async fn status_with_a_refresh_the_identity_platform_refuses_is_an_error() {
    let harness = Harness::new().await;
    sign_in_alex(&harness).await;
    // Past the Graph token's expiry, so the read needs a refresh.
    harness.clock.advance(Duration::from_secs(5000));
    Mock::given(method("POST"))
        .and(path(token_path("token")))
        .respond_with(json_response(
            400,
            serde_json::json!({
                "error": "invalid_grant",
                "error_description": "AADSTS70043: The refresh token has expired.",
                "error_codes": [70043],
            }),
        ))
        .expect(1)
        .mount(&harness.identity)
        .await;
    let run = harness.run(&["--json", "auth", "status"]).await;
    assert_eq!(run.outcome.exit_code, 1);
    let error = &run.json()["error"];
    assert_eq!(error["code"], "invalid_grant");
    assert_eq!(error["status"], 400);
    let message = error["message"].as_str().unwrap();
    assert!(message.contains("purview auth login"), "{message}");
    assert!(message.contains("AADSTS70043"), "{message}");
    assert_eq!(graph_requests(&harness).await, 0);
    harness.assert_no_canaries(&run);
}

#[tokio::test]
async fn graph_flags_are_checked_before_any_network_call() {
    let harness = Harness::new().await;
    sign_in_alex(&harness).await;
    for (args, vars, expected) in [
        (
            &["--timeout", "601"][..],
            &[][..],
            "--timeout must be a whole number",
        ),
        (
            &["--timeout", "x"][..],
            &[][..],
            "--timeout must be a whole number",
        ),
        (
            &["--timeout", " "][..],
            &[][..],
            "--timeout was given an empty value",
        ),
        (
            &["--trace", " "][..],
            &[][..],
            "--trace was given an empty value",
        ),
        (
            &["--trace", ""][..],
            &[][..],
            "a value is required for '--trace <DIR>'",
        ),
        (
            &[][..],
            &[("PURVIEW_TIMEOUT", "-1")][..],
            "PURVIEW_TIMEOUT must be a whole number",
        ),
        (
            &[][..],
            &[("PURVIEW_VERBOSE", "yes")][..],
            "PURVIEW_VERBOSE must be true or false",
        ),
    ] {
        let mut argv = vec!["--json"];
        argv.extend_from_slice(args);
        argv.extend_from_slice(&["auth", "status"]);
        let run = harness
            .run_with(&argv, |env, _| {
                for (name, value) in vars {
                    env.vars.insert((*name).to_owned(), (*value).into());
                }
            })
            .await;
        assert_eq!(run.outcome.exit_code, 1, "{args:?}");
        let message = run.json()["error"]["message"].as_str().unwrap().to_owned();
        assert!(message.contains(expected), "{args:?}: {message}");
    }
    assert_eq!(graph_requests(&harness).await, 0);
    assert_eq!(identity_requests(&harness).await, 0);
}

/// The first canary sweep (`docs/SPEC.md` section 8.5, item 10) for the
/// transport: a refresh rotation, a 401 whose body reflects the
/// superseded tokens, a second refresh, a 503 retry and a success whose
/// body carries a token, all under `--trace` and `--verbose`. Afterwards
/// no canary is in stdout, stderr, the trace directory or the
/// configuration directory.
#[tokio::test]
async fn the_canary_sweep_finds_no_token_in_output_trace_or_config() {
    let harness = Harness::new().await;
    sign_in_alex(&harness).await;
    harness.clock.advance(Duration::from_secs(5000));
    for (old_refresh, access, new_refresh) in [
        (
            "canary-refresh-0002",
            "canary-graph-access-0002",
            "canary-refresh-0003",
        ),
        (
            "canary-refresh-0003",
            "canary-graph-access-0003",
            "canary-refresh-0004",
        ),
    ] {
        Mock::given(method("POST"))
            .and(path(token_path("token")))
            .and(Form::new(&[
                ("grant_type", "refresh_token"),
                ("refresh_token", old_refresh),
            ]))
            .respond_with(json_response(200, token(access, new_refresh, GRAPH_SCOPE)))
            .expect(1)
            .mount(&harness.identity)
            .await;
    }
    // Each answer reflects every token the run holds by then, superseded
    // ones included. A token is reflected only after the process has
    // received it: a value it has not yet seen (or never sees, such as the
    // device code) it cannot know to remove.
    let held_at_401 = [
        "canary-graph-access-0001",
        "canary-graph-access-0002",
        "canary-download-access-0001",
        "canary-refresh-0002",
        "canary-refresh-0003",
    ]
    .join(" ");
    let reflected = format!("{held_at_401} canary-graph-access-0003 canary-refresh-0004");
    mount_probe(
        &harness,
        "canary-graph-access-0002",
        json_response(
            401,
            serde_json::json!({"error": {"code": "InvalidAuthenticationToken", "message": held_at_401}}),
        ),
    )
    .await;
    Mock::given(method("GET"))
        .and(path(CASES_PATH))
        .and(wiremock::matchers::header(
            "authorization",
            "Bearer canary-graph-access-0003",
        ))
        .respond_with(
            json_response(
                503,
                serde_json::json!({"error": {"code": "ServiceUnavailable", "message": reflected}}),
            )
            .insert_header("request-id", "canary-refresh-0002"),
        )
        .up_to_n_times(1)
        .with_priority(1)
        .mount(&harness.graph)
        .await;
    let mut body = graph_fixture("cases-list-top1.json", &harness.graph.uri());
    body["value"][0]["description"] = Value::from(reflected.clone());
    body["value"][0]["downloadUrl"] = Value::from(format!(
        "{}/v1.0/x?sig=canary-sig-0001&code=canary-auth-code-0001",
        harness.graph.uri()
    ));
    mount_probe(
        &harness,
        "canary-graph-access-0003",
        json_response(200, body),
    )
    .await;
    let trace = harness.root.path().join("trace");
    let trace_arg = trace.display().to_string();
    let run = harness
        .run(&[
            "--json",
            "--verbose",
            "--trace",
            &trace_arg,
            "auth",
            "status",
        ])
        .await;
    assert_eq!(run.outcome.exit_code, 0, "{}", run.stderr());
    assert_eq!(run.json()["results"]["purviewRole"], "ok");
    assert_eq!(graph_requests(&harness).await, 3);
    let stderr = run.stderr();
    assert!(
        stderr.starts_with("warning: trace files hold tenant data"),
        "{stderr}"
    );
    assert!(
        stderr.contains(&format!(
            "[verbose] refreshed the Graph token: returned scope {GRAPH_SCOPE}; refresh token \
             rotated: yes"
        )),
        "{stderr}"
    );
    assert!(
        stderr.contains("[verbose] refreshing the Graph token after HTTP 401"),
        "{stderr}"
    );
    assert_eq!(std::fs::read_dir(&trace).unwrap().count(), 3);
    let stored = harness.stored(ALEX).unwrap();
    assert_eq!(stored["refresh_token"], "canary-refresh-0004");
    let mut values: Vec<&str> = CANARIES.to_vec();
    values.extend(["canary-sig-0001"]);
    harness.assert_absent(&run, &values);
}

#[tokio::test]
async fn account_and_registration_errors_do_not_repeat_the_value() {
    let harness = Harness::new().await;
    sign_in_alex(&harness).await;
    sign_in_sam_too(&harness).await;
    let canary = "canary-7f3e";
    let address = format!("{canary}@contoso.example");
    let guid = "00000000-0000-4000-8000-000000000001";
    // Each case: arguments, a variable to set, and the message it must reach.
    type Case<'a> = (&'a [&'a str], Option<(&'a str, &'a str)>, &'a str);
    let cases: [Case; 10] = [
        (
            &["auth", "logout", "--account", &address],
            None,
            "no signed-in account matches",
        ),
        (
            &["auth", "refresh", "--account", &address],
            None,
            "no signed-in account matches",
        ),
        (
            &["case", "list", "--account", &address],
            None,
            "no signed-in account matches",
        ),
        (
            &["case", "list"],
            Some(("PURVIEW_ACCOUNT", &address)),
            "no signed-in account matches",
        ),
        (
            &["auth", "login", "--account", &address],
            None,
            "no app registration is saved",
        ),
        (
            &["auth", "login"],
            Some(("PURVIEW_ACCOUNT", &address)),
            "no app registration is saved",
        ),
        (
            &["auth", "login", "--no-input", "--client-id", canary],
            None,
            "--client-id: invalid client id",
        ),
        (
            &["auth", "login", "--no-input"],
            Some(("PURVIEW_CLIENT_ID", canary)),
            "PURVIEW_CLIENT_ID: invalid client id",
        ),
        (
            &[
                "auth",
                "login",
                "--no-input",
                "--client-id",
                guid,
                "--tenant-id",
                canary,
            ],
            None,
            "--tenant-id: invalid tenant id",
        ),
        (
            &["auth", "login", "--no-input", "--client-id", guid],
            Some(("PURVIEW_TENANT_ID", canary)),
            "PURVIEW_TENANT_ID: invalid tenant id",
        ),
    ];
    for (args, variable, expected) in cases {
        for json in [false, true] {
            let mut full: Vec<&str> = if json { vec!["--json"] } else { vec![] };
            full.extend_from_slice(args);
            let run = harness
                .run_with(&full, |env, _| {
                    if let Some((name, value)) = variable {
                        env.vars.insert(name.into(), value.into());
                    }
                })
                .await;
            assert_eq!(run.outcome.exit_code, 1, "{full:?} {variable:?}");
            let shown = format!("{}{}", run.stdout(), run.stderr());
            assert!(shown.contains(expected), "{full:?} {variable:?}: {shown}");
            assert!(!shown.contains(canary), "{full:?} {variable:?}: {shown}");
        }
    }
}

#[tokio::test]
async fn a_client_saved_against_several_tenants_is_refused_without_listing_them() {
    let harness = Harness::new().await;
    let canary = "canary-tenant-5b1d";
    let config = serde_json::json!({
        "clients": {
            "a@contoso.example": {"client_id": CLIENT_ID, "tenant_id": TENANT_ID},
            "b@contoso.example": {"client_id": CLIENT_ID, "tenant_id": canary},
        }
    });
    std::fs::create_dir_all(harness.config_dir()).unwrap();
    std::fs::write(harness.config_dir().join("config.json"), config.to_string()).unwrap();
    for json in [false, true] {
        let mut args = if json { vec!["--json"] } else { vec![] };
        args.extend(["auth", "login", "--client-id", CLIENT_ID]);
        let run = harness.run(&args).await;
        assert_eq!(run.outcome.exit_code, 1, "{args:?}");
        let shown = format!("{}{}", run.stdout(), run.stderr());
        assert!(shown.contains("saved against several tenants"), "{shown}");
        assert!(!shown.contains(canary), "{shown}");
        assert!(!shown.contains(TENANT_ID), "{shown}");
    }
}

#[tokio::test]
async fn a_malformed_saved_client_id_is_refused_without_naming_its_key() {
    let harness = Harness::new().await;
    let canary = "canary-key-3c9a@contoso.example";
    let config = serde_json::json!({
        "default_account": canary,
        "clients": {canary: {"client_id": "not-a-guid", "tenant_id": TENANT_ID}},
    });
    std::fs::create_dir_all(harness.config_dir()).unwrap();
    std::fs::write(harness.config_dir().join("config.json"), config.to_string()).unwrap();
    for json in [false, true] {
        let mut args = if json { vec!["--json"] } else { vec![] };
        args.extend(["auth", "login"]);
        let run = harness.run(&args).await;
        assert_eq!(run.outcome.exit_code, 1, "{args:?}");
        let shown = format!("{}{}", run.stdout(), run.stderr());
        assert!(shown.contains("invalid client id"), "{shown}");
        assert!(!shown.contains("canary-key"), "{shown}");
    }
}
