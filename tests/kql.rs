//! `purview kql` in-process: the guard's verdict, its output shapes, and
//! the configured term lists. The command is local, so every `Env` here
//! keeps the unreachable Graph and identity-platform hosts of
//! `Env::in_memory()`: a network call would fail the command.

use std::path::Path;

use ms_purview_cli::cli::execute_with;
use ms_purview_cli::env::{Captured, Env};
use ms_purview_cli::kql::classify::BUILT_IN_GENERIC;
use serde_json::Value;

const SMOKE: &[&str] = &[
    "kql",
    "--term",
    "orders-api",
    "--participant",
    "alex@contoso.example",
];

fn env_with_config(dir: &Path, config: Option<&str>) -> (Env, Captured) {
    let (mut env, captured) = Env::in_memory();
    // A configuration directory exists only when there is a config.json,
    // created private, as the tool keeps it.
    let dir = dir.join("config");
    if let Some(config) = config {
        std::fs::create_dir(&dir).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        std::fs::write(dir.join("config.json"), config).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(
                dir.join("config.json"),
                std::fs::Permissions::from_mode(0o600),
            )
            .unwrap();
        }
    }
    env.config_dir = Some(dir);
    (env, captured)
}

async fn run(config: Option<&str>, args: &[&str]) -> (i32, String, String, Option<Value>) {
    let dir = tempfile::tempdir().unwrap();
    let (env, captured) = env_with_config(dir.path(), config);
    let mut argv = vec!["purview"];
    argv.extend_from_slice(args);
    let outcome = execute_with(env, argv).await;
    (
        outcome.exit_code,
        captured.stdout.text(),
        captured.stderr.text(),
        outcome.stdout_value,
    )
}

#[tokio::test]
async fn the_release_smoke_test_is_narrowed() {
    let (code, stdout, stderr, _) = run(None, SMOKE).await;
    assert_eq!(code, 0, "{stderr}");
    assert!(stderr.is_empty(), "{stderr}");
    let lines: Vec<&str> = stdout.lines().collect();
    assert_eq!(
        lines.first(),
        Some(&"kql: \"orders-api\" AND participants:alex@contoso.example")
    );
    assert!(lines[1].starts_with("COLUMN  FIELD"), "{stdout}");
    assert!(lines[2].contains("specific"), "{stdout}");
    assert!(lines[3].contains("narrowing"), "{stdout}");
    assert_eq!(lines.last(), Some(&"verdict: narrowed"));
}

#[tokio::test]
async fn json_success_is_the_results_envelope() {
    let mut args = vec!["--json"];
    args.extend_from_slice(SMOKE);
    let (code, stdout, stderr, value) = run(None, &args).await;
    assert_eq!(code, 0, "{stderr}");
    let value = value.unwrap();
    assert_eq!(serde_json::from_str::<Value>(&stdout).unwrap(), value);
    assert_eq!(value["count"], 1);
    let results = &value["results"];
    assert_eq!(
        results["kql"],
        "\"orders-api\" AND participants:alex@contoso.example"
    );
    assert_eq!(results["narrowed"], true);
    assert!(results.get("unnarrowedAt").is_none());
    assert_eq!(results["leaves"][0]["field"], "term");
    assert_eq!(results["leaves"][0]["class"], "specific");
    assert_eq!(results["leaves"][0]["rule"], 6);
    assert_eq!(results["leaves"][1]["field"], "participants");
    assert_eq!(results["leaves"][1]["class"], "narrowing");
    assert_eq!(results["leaves"][1]["column"], 18);
}

#[tokio::test]
async fn a_generic_query_prints_its_report_then_fails() {
    let (code, stdout, stderr, value) = run(None, &["kql", "--term", "retention"]).await;
    assert_eq!(code, 1);
    assert!(value.is_none());
    assert!(stdout.contains("generic"), "{stdout}");
    assert!(stdout.ends_with("verdict: not narrowed\n"), "{stdout}");
    assert!(
        stderr.starts_with("Error: the query is not narrowed: the branch at column 1"),
        "{stderr}"
    );
    assert!(!stderr.contains("retention"), "{stderr}");
}

#[tokio::test]
async fn a_generic_query_under_json_is_one_document_with_the_analysis() {
    for args in [
        &["--json", "kql", "--term", "retention"][..],
        &["--json", "--results-only", "kql", "--term", "retention"][..],
    ] {
        let (code, stdout, stderr, value) = run(None, args).await;
        assert_eq!(code, 1);
        assert!(stderr.is_empty(), "{stderr}");
        let value = value.unwrap();
        assert_eq!(serde_json::from_str::<Value>(&stdout).unwrap(), value);
        assert_eq!(value["error"]["code"], "GenericQuery");
        assert_eq!(value["error"]["status"], 0);
        assert_eq!(value["analysis"]["narrowed"], false);
        assert_eq!(value["analysis"]["unnarrowedAt"], 1);
        assert_eq!(value["analysis"]["leaves"][0]["rule"], 8);
        assert!(value.get("results").is_none());
    }
}

#[tokio::test]
async fn a_query_outside_the_grammar_is_an_error_naming_only_the_column() {
    let (code, stdout, stderr, value) =
        run(None, &["--json", "kql", "--kql", "orders-api secretword"]).await;
    assert_eq!(code, 1);
    assert!(stderr.is_empty());
    let value = value.unwrap();
    assert_eq!(value["error"]["code"], "KqlNotUnderstood");
    let message = value["error"]["message"].as_str().unwrap();
    assert!(message.contains("column 12"), "{message}");
    assert!(!message.contains("secretword"), "{message}");
    assert!(value.get("analysis").is_none());
    assert!(!stdout.contains("secretword"));
}

#[tokio::test]
async fn the_configured_lists_change_the_verdict_and_generic_wins() {
    let config =
        r#"{"guard": {"specific_terms": ["Okta", "orders-api"], "generic_terms": ["orders-api"]}}"#;
    let (code, _, stderr, _) = run(Some(config), &["kql", "--term", "okta"]).await;
    assert_eq!(code, 0, "{stderr}");
    let (code, stdout, _, _) = run(Some(config), &["kql", "--term", "orders-api"]).await;
    assert_eq!(code, 1);
    assert!(stdout.contains("1: in guard.generic_terms"), "{stdout}");
    let (code, _, _, _) = run(None, &["kql", "--term", "okta"]).await;
    assert_eq!(code, 1);
    // Nulls are unset.
    let (code, _, stderr, _) = run(
        Some(r#"{"guard": {"specific_terms": null, "generic_terms": null}}"#),
        SMOKE,
    )
    .await;
    assert_eq!(code, 0, "{stderr}");
}

#[tokio::test]
async fn a_wrong_guard_setting_is_an_error() {
    let (code, stdout, stderr, _) =
        run(Some(r#"{"guard": {"specific_terms": "Okta"}}"#), SMOKE).await;
    assert_eq!(code, 1);
    assert!(stdout.is_empty());
    assert!(
        stderr.contains("guard.specific_terms must be a list of non-blank strings"),
        "{stderr}"
    );
}

#[tokio::test]
async fn arguments_are_checked_before_config_json_is_read() {
    for (args, expected) in [
        (&["kql"][..], "no query given"),
        (
            &["kql", "--participant", "contoso.example"][..],
            "--participant needs a full address",
        ),
        (&["kql", "--term", "a\"b"][..], "double quote"),
        (
            &["kql", "--select", "NOPE", "--term", "orders-api"][..],
            "--select names a column",
        ),
    ] {
        let (code, _, stderr, _) = run(Some("{not json"), args).await;
        assert_eq!(code, 1);
        assert!(stderr.contains(expected), "{args:?}: {stderr}");
    }
}

#[tokio::test]
async fn select_is_checked_under_json_too_and_plain_prints_rows_only() {
    let (code, _, _, value) = run(
        None,
        &["--json", "--select", "NOPE", "kql", "--term", "orders-api"],
    )
    .await;
    assert_eq!(code, 1);
    assert_eq!(value.unwrap()["error"]["code"], "CommandFailed");
    let (code, stdout, _, _) = run(
        None,
        &[
            "--plain",
            "--select",
            "field,class",
            "kql",
            "--term",
            "orders-api",
        ],
    )
    .await;
    assert_eq!(code, 0);
    assert_eq!(stdout, "term\tspecific\n");
}

#[tokio::test]
async fn kql_conflicts_with_every_query_flag() {
    for flag in [
        &["--term", "orders-api"][..],
        &["--participant", "alex@contoso.example"][..],
        &["--since", "2025-01-01"][..],
        &["--until", "2025-01-01"][..],
        &["--kind", "email"][..],
        &["--exclude-from", "alex@contoso.example"][..],
    ] {
        let mut args = vec!["--json", "kql", "--kql", "orders-api"];
        args.extend_from_slice(flag);
        let (code, _, _, value) = run(None, &args).await;
        assert_eq!(code, 1, "{flag:?}");
        assert_eq!(value.unwrap()["error"]["code"], "CommandFailed");
    }
}

#[tokio::test]
async fn negated_leaves_are_marked() {
    let (code, _, _, value) = run(
        None,
        &[
            "--json",
            "kql",
            "--term",
            "orders-api",
            "--exclude-from",
            "noreply@notify.example",
            "--kind",
            "teams",
            "--since",
            "2025-01-01",
        ],
    )
    .await;
    assert_eq!(code, 0);
    let leaves = value.unwrap()["results"]["leaves"].clone();
    let fields: Vec<(&str, bool)> = leaves
        .as_array()
        .unwrap()
        .iter()
        .map(|leaf| {
            (
                leaf["field"].as_str().unwrap(),
                leaf["negated"].as_bool().unwrap(),
            )
        })
        .collect();
    assert_eq!(
        fields,
        [
            ("term", false),
            ("sent", false),
            ("kind", false),
            ("from", true)
        ]
    );
}

/// The list between the markers in a document, one entry per word.
fn documented_list(path: &str) -> Vec<String> {
    let text = std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join(path)).unwrap();
    let start = text
        .find("<!-- built-in-generic-list:start -->")
        .unwrap_or_else(|| panic!("{path} has no start marker"));
    let end = text
        .find("<!-- built-in-generic-list:end -->")
        .unwrap_or_else(|| panic!("{path} has no end marker"));
    text[start..end]
        .lines()
        .skip(1)
        .filter(|line| !line.starts_with("```"))
        .flat_map(str::split_whitespace)
        .map(str::to_owned)
        .collect()
}

#[test]
fn the_built_in_generic_list_matches_the_documents() {
    let code: Vec<String> = BUILT_IN_GENERIC
        .iter()
        .map(|word| (*word).to_owned())
        .collect();
    assert_eq!(documented_list("docs/safety.md"), code);
    assert_eq!(documented_list("docs/SPEC.md"), code);
}
