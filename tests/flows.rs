//! In-process flows through `cli::execute_with`, against a wiremock
//! identity platform, an in-memory credential store and a manual clock.
//! Nothing here reaches the network or the operating-system keychain.

mod support;

use std::time::Duration;

use serde_json::Value;
use support::*;
use wiremock::matchers::{method, path};
use wiremock::{Mock, ResponseTemplate};

fn json_response(status: u16, body: Value) -> ResponseTemplate {
    ResponseTemplate::new(status).set_body_json(body)
}

/// Mounts a device-code sign-in: the device code, one pending poll, the
/// Graph token with the given claims, then `download` for the download
/// redemption.
async fn mount_login(harness: &Harness, claims: &str, download: ResponseTemplate) {
    Mock::given(method("POST"))
        .and(path(token_path("devicecode")))
        .respond_with(json_response(200, fixture("device-code.json")))
        .expect(1)
        .mount(&harness.identity)
        .await;
    let device_grant = Form::new(&[
        ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
        ("device_code", "canary-device-code-0001"),
        ("client_id", CLIENT_ID),
    ]);
    Mock::given(method("POST"))
        .and(path(token_path("token")))
        .and(device_grant)
        .respond_with(json_response(400, fixture("authorization-pending.json")))
        .up_to_n_times(1)
        .with_priority(1)
        .mount(&harness.identity)
        .await;
    Mock::given(method("POST"))
        .and(path(token_path("token")))
        .and(Form::new(&[(
            "grant_type",
            "urn:ietf:params:oauth:grant-type:device_code",
        )]))
        .respond_with(json_response(200, graph_token(claims)))
        .with_priority(2)
        .mount(&harness.identity)
        .await;
    Mock::given(method("POST"))
        .and(path(token_path("token")))
        .and(Form::new(&[
            ("grant_type", "refresh_token"),
            ("refresh_token", "canary-refresh-0001"),
            (
                "scope",
                "b26e684c-5068-4120-a679-64a5d2c909d9/.default offline_access",
            ),
        ]))
        .respond_with(download)
        .expect(1)
        .mount(&harness.identity)
        .await;
}

async fn sign_in_alex(harness: &Harness) {
    mount_login(
        harness,
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
    harness.identity.reset().await;
}

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
    assert!(harness.credentials().is_empty());
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
    assert!(harness.credentials().is_empty());
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
    assert!(harness.credentials().is_empty());
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
    }
    assert_eq!(harness.credentials().len(), 2);
}

/// Signs in Alex with one write made to fail, then checks what the next
/// `auth list`, `auth refresh` and `auth logout` see.
#[tokio::test]
async fn a_failed_config_write_stores_nothing() {
    let harness = Harness::new().await;
    mount_login(
        &harness,
        "id-claims-preferred.json",
        json_response(200, fixture("token-download.json")),
    )
    .await;
    // A value in config.json that the sign-in's tokens make recognisable
    // as a secret: Config::save refuses it, so the first write fails.
    std::fs::create_dir_all(harness.config_dir()).unwrap();
    std::fs::write(
        harness.config_dir().join("config.json"),
        br#"{"note": "canary-refresh-0001"}"#,
    )
    .unwrap();
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
        run.stderr()
            .contains("saving config.json; nothing was stored"),
        "{}",
        run.stderr()
    );
    assert!(harness.credentials().is_empty());
    assert!(!harness.config_dir().join("accounts").exists());
    assert_eq!(
        harness.config(),
        serde_json::json!({"note": "canary-refresh-0001"})
    );
    // The canary planted in config.json is the only copy anywhere.
    for text in [run.stdout(), run.stderr()] {
        assert!(!text.contains("canary"), "{text}");
    }
}

#[tokio::test]
async fn a_failed_account_file_write_leaves_only_the_registration() {
    let harness = Harness::new().await;
    mount_login(
        &harness,
        "id-claims-preferred.json",
        json_response(200, fixture("token-download.json")),
    )
    .await;
    // A directory where the account file goes makes its write fail.
    std::fs::create_dir_all(harness.account_file(ALEX)).unwrap();
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
        run.stderr().contains("no token was stored"),
        "{}",
        run.stderr()
    );
    assert!(harness.credentials().is_empty());
    assert_eq!(harness.config()["clients"][ALEX]["client_id"], CLIENT_ID);
    harness.assert_no_canaries(&run);

    let list = harness.run(&["--json", "auth", "list"]).await;
    assert_eq!(list.json()["count"], 0);
    let refresh = harness.run(&["auth", "refresh"]).await;
    assert!(refresh.stderr().contains("no account is signed in"));
    // Once the obstacle is gone, a new sign-in reuses the registration.
    std::fs::remove_dir(harness.account_file(ALEX)).unwrap();
    harness.identity.reset().await;
    mount_login(
        &harness,
        "id-claims-preferred.json",
        json_response(200, fixture("token-download.json")),
    )
    .await;
    let again = harness.run(&["auth", "login"]).await;
    assert_eq!(again.outcome.exit_code, 0, "{}", again.stderr());
    assert_eq!(harness.credentials(), [ALEX]);
}

#[tokio::test]
async fn a_failed_credential_write_leaves_a_listed_account_logout_removes() {
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
        run.stderr().contains("the tokens were not"),
        "{}",
        run.stderr()
    );
    harness.assert_no_canaries(&run);
    assert!(harness.credentials().is_empty());

    let list = harness.run(&["--json", "auth", "list"]).await;
    assert_eq!(list.json()["results"][0]["email"], ALEX);
    let refresh = harness.run(&["auth", "refresh"]).await;
    assert_eq!(refresh.outcome.exit_code, 1);
    assert!(
        refresh.stderr().contains("no stored credential"),
        "{}",
        refresh.stderr()
    );
    let logout = harness.run(&["auth", "logout"]).await;
    assert_eq!(logout.outcome.exit_code, 0, "{}", logout.stderr());
    assert!(!harness.account_file(ALEX).exists());
}

#[tokio::test]
async fn signing_in_with_a_new_registration_drops_the_old_tokens_first() {
    let harness = Harness::new().await;
    sign_in_alex(&harness).await;
    let other_client = "00000000-0000-4000-8000-000000000003";
    // The mocks match any client id except where the form says otherwise.
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
        .respond_with(json_response(200, graph_token("id-claims-preferred.json")))
        .mount(&harness.identity)
        .await;
    Mock::given(method("POST"))
        .and(path(token_path("token")))
        .and(Form::new(&[("grant_type", "refresh_token")]))
        .respond_with(json_response(200, fixture("token-download.json")))
        .mount(&harness.identity)
        .await;
    harness.store.fail_writes(true);
    let run = harness
        .run(&[
            "auth",
            "login",
            "--client-id",
            other_client,
            "--tenant-id",
            TENANT_ID,
        ])
        .await;
    harness.store.fail_writes(false);
    assert_eq!(run.outcome.exit_code, 1);
    // The old tokens, issued to the old app, are gone with it.
    assert!(harness.credentials().is_empty());
    assert_eq!(harness.config()["clients"][ALEX]["client_id"], other_client);
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
