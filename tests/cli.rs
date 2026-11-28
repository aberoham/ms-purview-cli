//! Offline process contracts, run against the built binary.

use assert_cmd::Command;
use predicates::prelude::*;
use serde_json::Value;

/// Every variable the binary reads, removed so the shell running the tests
/// cannot change the result.
const VARIABLES: &[&str] = &[
    "PURVIEW_JSON",
    "PURVIEW_RESULTS_ONLY",
    "PURVIEW_PLAIN",
    "PURVIEW_SELECT",
    "PURVIEW_ACCOUNT",
    "PURVIEW_NO_INPUT",
    "PURVIEW_VERBOSE",
    "PURVIEW_TIMEOUT",
    "PURVIEW_TRACE_DIR",
    "PURVIEW_WRAP_UNTRUSTED",
    "PURVIEW_YES",
    "PURVIEW_NO_WRITE",
    "PURVIEW_CLIENT_ID",
    "PURVIEW_TENANT_ID",
    "PURVIEW_CONFIG_DIR",
];

#[test]
fn the_scrubbed_variables_cover_every_flag_variable() {
    for name in ms_purview_cli::env::FLAG_VARIABLES {
        assert!(VARIABLES.contains(name), "{name}");
    }
}

fn purview() -> Command {
    let mut command = Command::new(assert_cmd::cargo::cargo_bin!("purview"));
    for name in VARIABLES {
        command.env_remove(name);
    }
    command
}

#[test]
fn version_prints_name_version_commit_and_target() {
    let temporary = tempfile::tempdir().unwrap();
    let output = purview()
        .env("PURVIEW_CONFIG_DIR", temporary.path())
        .arg("version")
        .assert()
        .success()
        .stderr(predicate::str::is_empty())
        .get_output()
        .stdout
        .clone();
    let text = String::from_utf8(output).unwrap();
    assert!(text.ends_with('\n'), "{text:?}");
    assert_eq!(text.lines().count(), 1, "{text:?}");
    let fields: Vec<&str> = text.trim_end().split(' ').collect();
    assert_eq!(fields.len(), 4, "{text:?}");
    assert_eq!(fields[0], "purview");
    assert_eq!(fields[1], env!("CARGO_PKG_VERSION"));
    assert!(!fields[2].is_empty() && !fields[3].is_empty(), "{text:?}");
    // The version command needs no configuration and writes none.
    assert_eq!(std::fs::read_dir(temporary.path()).unwrap().count(), 0);
}

#[test]
fn version_json_has_the_envelope_and_three_fields() {
    let output = purview()
        .args(["version", "--json"])
        .assert()
        .success()
        .stderr(predicate::str::is_empty())
        .get_output()
        .stdout
        .clone();
    let value: Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(value["count"], 1);
    let results = value["results"].as_object().unwrap();
    let mut keys: Vec<&str> = results.keys().map(String::as_str).collect();
    keys.sort_unstable();
    assert_eq!(keys, ["commit", "target", "version"]);
    assert_eq!(results["version"], env!("CARGO_PKG_VERSION"));
    assert!(results["commit"].is_null() || results["commit"].is_string());
    assert!(results["target"].as_str().is_some_and(|t| !t.is_empty()));
}

#[test]
fn version_results_only_drops_the_envelope() {
    for (args, env) in [
        (&["--json", "--results-only", "version"][..], None),
        (&["version"][..], Some(("true", "true"))),
    ] {
        let mut command = purview();
        if let Some((json, results_only)) = env {
            command
                .env("PURVIEW_JSON", json)
                .env("PURVIEW_RESULTS_ONLY", results_only);
        }
        let output = command.args(args).assert().success().get_output().clone();
        let value: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(value["version"], env!("CARGO_PKG_VERSION"), "{args:?}");
        assert!(value.get("results").is_none(), "{args:?}");
    }
}

/// The commit is recorded only at build time, through
/// `PURVIEW_BUILD_COMMIT`; without it the text form says `unknown`.
#[test]
fn the_commit_field_is_the_recorded_commit_or_unknown() {
    let output = purview()
        .arg("version")
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let text = String::from_utf8(output).unwrap();
    let expected = option_env!("PURVIEW_BUILD_COMMIT")
        .filter(|commit| !commit.is_empty())
        .unwrap_or("unknown");
    assert_eq!(text.split(' ').nth(2), Some(expected), "{text:?}");
}

#[test]
fn argument_errors_are_one_json_document_when_json_was_asked_for() {
    for (args, env) in [
        (&["version", "--bogus", "--json"][..], None),
        (&["--json", "nonsense"][..], None),
        (&["--json"][..], None),
        (&["version", "extra"][..], Some("true")),
    ] {
        let mut command = purview();
        if let Some(value) = env {
            command.env("PURVIEW_JSON", value);
        }
        let output = command.args(args).assert().code(1).get_output().clone();
        let value: Value = serde_json::from_slice(&output.stdout)
            .unwrap_or_else(|error| panic!("{args:?}: {error}"));
        let object = value.as_object().unwrap();
        assert_eq!(object.len(), 1, "{args:?}: {value}");
        assert_eq!(value["error"]["code"], "CommandFailed", "{args:?}");
        assert_eq!(value["error"]["status"], 0, "{args:?}");
        assert!(value["error"]["message"].is_string(), "{args:?}");
        assert!(output.stderr.is_empty(), "{args:?}");
    }
}

#[test]
fn argument_errors_without_json_go_to_stderr_only() {
    purview()
        .args(["version", "--bogus"])
        .assert()
        .code(1)
        .stdout(predicate::str::is_empty())
        .stderr(predicate::str::starts_with(
            "Error: an argument that this command does not take (not repeated here); quote a value that holds spaces\n",
        ))
        .stderr(predicate::str::contains("Usage: purview version"));
    purview()
        .assert()
        .code(1)
        .stdout(predicate::str::is_empty())
        .stderr(predicate::str::starts_with(
            "Error: a command is required\n",
        ))
        .stderr(predicate::str::contains("Usage"));
}

#[test]
fn a_json_flag_after_a_double_dash_does_not_ask_for_json() {
    purview()
        .args(["version", "--", "--json"])
        .assert()
        .code(1)
        .stdout(predicate::str::is_empty());
}

#[test]
fn an_invalid_json_variable_is_refused_in_human_form() {
    purview()
        .env("PURVIEW_JSON", "yes")
        .arg("version")
        .assert()
        .code(1)
        .stdout(predicate::str::is_empty())
        .stderr(predicate::str::starts_with(
            "Error: PURVIEW_JSON must be true or false\n\nUsage: purview [OPTIONS] <COMMAND>",
        ));
}

#[test]
fn an_invalid_plain_variable_still_answers_in_json_when_json_is_set() {
    for args in [&["version"][..], &["version", "--bogus"][..]] {
        let output = purview()
            .env("PURVIEW_JSON", "true")
            .env("PURVIEW_PLAIN", "bad")
            .args(args)
            .assert()
            .code(1)
            .stderr(predicate::str::is_empty())
            .get_output()
            .stdout
            .clone();
        let value: Value = serde_json::from_slice(&output).unwrap();
        assert_eq!(value["error"]["code"], "CommandFailed", "{args:?}");
    }
}

#[test]
fn json_variables_are_read_by_the_binary() {
    let output = purview()
        .env("PURVIEW_JSON", "true")
        .env("PURVIEW_PLAIN", "false")
        .arg("version")
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let value: Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(value["count"], 1);
}

/// A pipe whose reading end is already closed makes every write fail with
/// a broken pipe, as when the reader of `purview ... | head` has exited.
#[test]
fn a_failed_stdout_write_exits_1() {
    for args in [
        &["version", "--json"][..],
        &["version"][..],
        &["--help"][..],
    ] {
        let (reader, writer) = std::io::pipe().unwrap();
        drop(reader);
        let mut command = std::process::Command::new(assert_cmd::cargo::cargo_bin!("purview"));
        for name in VARIABLES {
            command.env_remove(name);
        }
        let output = command.args(args).stdout(writer).output().unwrap();
        assert_eq!(output.status.code(), Some(1), "{args:?}");
        let stderr = String::from_utf8(output.stderr).unwrap();
        assert!(
            stderr.starts_with("Error: could not write to standard output: "),
            "{args:?}: {stderr}"
        );
        assert_eq!(stderr.lines().count(), 1, "{args:?}: {stderr}");
    }
}

#[test]
fn help_is_success_and_lists_exactly_the_shipped_commands() {
    let output = purview()
        .arg("--help")
        .assert()
        .success()
        .stderr(predicate::str::is_empty())
        .get_output()
        .stdout
        .clone();
    let text = String::from_utf8(output).unwrap();
    let commands: Vec<&str> = text
        .lines()
        .skip_while(|line| *line != "Commands:")
        .skip(1)
        .take_while(|line| !line.trim().is_empty())
        .filter_map(|line| line.split_whitespace().next())
        .collect();
    assert_eq!(
        commands,
        [
            "auth",
            "case",
            "search",
            "operation",
            "download",
            "estimate",
            "report",
            "export",
            "kql",
            "parse",
            "version",
            "help"
        ],
        "{text}"
    );
}

#[test]
fn command_groups_list_exactly_their_shipped_commands() {
    for group in ["case", "search", "operation"] {
        let output = purview()
            .args([group, "--help"])
            .assert()
            .success()
            .get_output()
            .stdout
            .clone();
        let text = String::from_utf8(output).unwrap();
        let commands: Vec<&str> = text
            .lines()
            .skip_while(|line| *line != "Commands:")
            .skip(1)
            .take_while(|line| !line.trim().is_empty())
            .filter_map(|line| line.split_whitespace().next())
            .collect();
        let expected: &[&str] = match group {
            "operation" => &["list", "get", "help"],
            "case" => &["list", "get", "create", "close", "help"],
            _ => &["list", "get", "create", "help"],
        };
        assert_eq!(commands, expected, "{group}: {text}");
    }
}

#[test]
fn auth_help_lists_exactly_the_shipped_auth_commands() {
    let output = purview()
        .args(["auth", "--help"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let text = String::from_utf8(output).unwrap();
    let commands: Vec<&str> = text
        .lines()
        .skip_while(|line| *line != "Commands:")
        .skip(1)
        .take_while(|line| !line.trim().is_empty())
        .filter_map(|line| line.split_whitespace().next())
        .collect();
    assert_eq!(
        commands,
        ["login", "refresh", "status", "list", "logout", "help"],
        "{text}"
    );
}

/// `--no-input` refuses sign-in before any network call or credential
/// access, so this runs offline against an empty configuration directory
/// and leaves it empty.
#[test]
fn login_under_no_input_is_refused_before_any_work() {
    let temporary = tempfile::tempdir().unwrap();
    for (args, variable) in [
        (&["auth", "login", "--no-input", "--json"][..], None),
        (&["--json", "auth", "login"][..], Some("true")),
    ] {
        let mut command = purview();
        command.env("PURVIEW_CONFIG_DIR", temporary.path());
        if let Some(value) = variable {
            command.env("PURVIEW_NO_INPUT", value);
        }
        let output = command.args(args).assert().code(1).get_output().clone();
        let value: Value = serde_json::from_slice(&output.stdout).unwrap();
        let message = value["error"]["message"].as_str().unwrap();
        assert!(message.contains("--no-input"), "{message}");
        assert!(output.stderr.is_empty(), "{args:?}");
    }
    assert_eq!(std::fs::read_dir(temporary.path()).unwrap().count(), 0);
}

#[test]
fn a_malformed_client_id_is_refused_before_no_input_or_network() {
    purview()
        .env("PURVIEW_CONFIG_DIR", tempfile::tempdir().unwrap().path())
        .args(["auth", "login", "--no-input", "--client-id", "not-a-guid"])
        .assert()
        .code(1)
        .stdout(predicate::str::is_empty())
        .stderr(predicate::str::starts_with(
            "Error: --client-id: invalid client id",
        ));
}

#[test]
fn listing_with_no_accounts_is_empty_and_writes_nothing() {
    let temporary = tempfile::tempdir().unwrap();
    let output = purview()
        .env("PURVIEW_CONFIG_DIR", temporary.path().join("purview"))
        .args(["auth", "list", "--json"])
        .assert()
        .success()
        .stderr(predicate::str::is_empty())
        .get_output()
        .stdout
        .clone();
    let value: Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(value, serde_json::json!({"results": [], "count": 0}));
    assert!(!temporary.path().join("purview").exists());
}

#[test]
fn logout_with_no_accounts_fails_without_touching_the_store() {
    let temporary = tempfile::tempdir().unwrap();
    purview()
        .env("PURVIEW_CONFIG_DIR", temporary.path().join("purview"))
        .args(["auth", "logout"])
        .assert()
        .code(1)
        .stderr(predicate::str::starts_with(
            "Error: no account is signed in; run 'purview auth login' first",
        ));
}

/// The release smoke test: `purview kql` runs with no sign-in, no
/// configuration and no network.
#[test]
fn the_kql_smoke_test_is_narrowed_with_no_configuration() {
    let config = tempfile::tempdir().unwrap();
    purview()
        .env("PURVIEW_CONFIG_DIR", config.path().join("missing"))
        .args([
            "kql",
            "--term",
            "orders-api",
            "--participant",
            "alex@contoso.example",
        ])
        .assert()
        .success()
        .stderr(predicate::str::is_empty())
        .stdout(predicate::str::ends_with("verdict: narrowed\n"));
    assert!(!config.path().join("missing").exists());
}

/// A query that is not narrowed, and one outside the grammar, exit 1 from
/// the process, with the JSON error code.
#[test]
fn kql_refusals_exit_1_with_their_codes() {
    let config = tempfile::tempdir().unwrap();
    for (query, code) in [
        ("retention", "GenericQuery"),
        ("retention policy", "KqlNotUnderstood"),
    ] {
        let output = purview()
            .env("PURVIEW_CONFIG_DIR", config.path().join("missing"))
            .args(["--json", "kql", "--kql", query])
            .assert()
            .code(1)
            .stderr(predicate::str::is_empty())
            .get_output()
            .stdout
            .clone();
        let value: Value = serde_json::from_slice(&output).unwrap();
        assert_eq!(value["error"]["code"], code, "{query}");
    }
}

/// Runs a write command line that must fail before sign-in, with no
/// configuration directory, and returns its JSON error code. Nothing may
/// reach the credential store or the network, so the process ends before
/// sign-in; the configuration directory is never created.
fn refused_before_sign_in(args: &[&str]) -> String {
    let config = tempfile::tempdir().unwrap();
    let missing = config.path().join("missing");
    let output = purview()
        .env("PURVIEW_CONFIG_DIR", &missing)
        .arg("--json")
        .args(args)
        .assert()
        .code(1)
        .stderr(predicate::str::is_empty())
        .get_output()
        .stdout
        .clone();
    assert!(!missing.exists(), "{args:?}");
    let value: Value = serde_json::from_slice(&output).unwrap();
    value["error"]["code"]
        .as_str()
        .unwrap_or_default()
        .to_owned()
}

const SEARCH_CREATE: &[&str] = &[
    "search",
    "create",
    "00000000-0000-4000-8000-000000000031",
    "--name",
    "orders-api-mail",
];

/// The release smoke test of v0.2.0 (`docs/SPEC.md` section 11), and the
/// same for `search create`: --no-write refuses before anything else.
#[test]
fn no_write_refuses_both_create_commands_before_sign_in() {
    assert_eq!(
        refused_before_sign_in(&["--no-write", "case", "create", "--topic", "smoke"]),
        "WriteRefused"
    );
    let mut args = vec!["--no-write"];
    args.extend_from_slice(SEARCH_CREATE);
    args.extend_from_slice(&[
        "--term",
        "orders-api",
        "--participant",
        "alex@contoso.example",
    ]);
    assert_eq!(refused_before_sign_in(&args), "WriteRefused");
    // Before the guard, too.
    let mut args = vec!["--no-write"];
    args.extend_from_slice(SEARCH_CREATE);
    args.extend_from_slice(&["--term", "retention"]);
    assert_eq!(refused_before_sign_in(&args), "WriteRefused");
}

#[test]
fn create_argument_errors_need_no_network() {
    let canary = "canary-argument-0077";
    let tab = format!("Orders\treview {canary}");
    let cases: Vec<Vec<String>> = vec![
        vec!["case".into(), "create".into()],
        vec![
            "case".into(),
            "create".into(),
            "--topic".into(),
            "  ".into(),
        ],
        vec![
            "case".into(),
            "create".into(),
            "--topic".into(),
            tab.clone(),
        ],
        vec![
            "case".into(),
            "create".into(),
            "--topic".into(),
            format!("Orders review {canary}\n"),
        ],
        vec![
            "case".into(),
            "create".into(),
            "--topic".into(),
            format!("Orders\u{2028}review {canary}"),
        ],
        vec![
            "case".into(),
            "create".into(),
            "--topic".into(),
            "Orders".into(),
            "--name".into(),
            tab.clone(),
        ],
        vec![
            "case".into(),
            "create".into(),
            "--topic".into(),
            "Orders".into(),
            "--requester".into(),
            String::new(),
        ],
        vec![
            "--select".into(),
            "ID".into(),
            "case".into(),
            "create".into(),
            "--topic".into(),
            "Orders".into(),
        ],
    ];
    let search = |extra: &[&str]| -> Vec<String> {
        SEARCH_CREATE
            .iter()
            .chain(extra)
            .map(|arg| (*arg).to_owned())
            .collect()
    };
    let searches = vec![
        // No query at all.
        search(&[]),
        search(&["--term", "orders-api", "--reason", "needed"]),
        search(&["--term", "orders-api", "--allow-generic"]),
        search(&["--term", "orders-api", "--allow-generic", "--reason", " "]),
        search(&["--term", "orders-api", "--kql", "\"orders-api\""]),
        search(&["--term", "orders-api", "--description", &tab]),
        vec![
            "search".into(),
            "create".into(),
            "c".into(),
            "--term".into(),
            "x".into(),
        ],
        vec![
            "search".into(),
            "create".into(),
            " ".into(),
            "--name".into(),
            "n".into(),
            "--term".into(),
            "orders-api".into(),
        ],
    ];
    for args in cases.iter().chain(&searches) {
        let args: Vec<&str> = args.iter().map(String::as_str).collect();
        let config = tempfile::tempdir().unwrap();
        let output = purview()
            .env("PURVIEW_CONFIG_DIR", config.path().join("missing"))
            .arg("--json")
            .args(&args)
            .assert()
            .code(1)
            .stderr(predicate::str::is_empty())
            .get_output()
            .stdout
            .clone();
        let text = String::from_utf8(output).unwrap();
        assert!(!text.contains(canary), "{args:?}: {text}");
        let value: Value = serde_json::from_str(&text).unwrap();
        assert_eq!(value["error"]["code"], "CommandFailed", "{args:?}: {text}");
        // Refused as an argument, not by the sign-in that would follow.
        let message = value["error"]["message"].as_str().unwrap_or_default();
        assert!(!message.contains("auth login"), "{args:?}: {text}");
    }
}

/// The guard runs before sign-in, after --no-write: a query that is not
/// narrowed, and one outside the grammar, are refused with their codes.
#[test]
fn search_create_runs_the_guard_before_sign_in() {
    for (extra, code) in [
        (&["--term", "retention"][..], "GenericQuery"),
        (&["--kql", "retention policy"][..], "KqlNotUnderstood"),
        (
            &[
                "--kql",
                "retention policy",
                "--allow-generic",
                "--reason",
                "needed",
            ][..],
            "KqlNotUnderstood",
        ),
    ] {
        let mut args = SEARCH_CREATE.to_vec();
        args.extend_from_slice(extra);
        assert_eq!(refused_before_sign_in(&args), code, "{extra:?}");
    }
}

/// A small estimate zip on disk, built from CSV text.
fn estimate_zip_file(dir: &std::path::Path) -> std::path::PathBuf {
    use std::io::Write;
    let path = dir.join("estimate.zip");
    let mut writer = zip::ZipWriter::new(std::fs::File::create(&path).unwrap());
    let options = zip::write::SimpleFileOptions::default();
    for (name, body) in [
        (
            "Locations-2026-01-05_09-00-00.csv",
            "\u{feff}DataSourceName,DataSourceType,Location,LocationId,LocationType,LocationSubType,Count,Size,Status,ErrorWarning,Query\r\nExchange,Mailbox,alex@contoso.example,1,Mailbox,PrimaryMailBox,12,2048,Succeeded,,q\r\nExchange,Mailbox,sam@contoso.example,2,Mailbox,ArchiveMailBox,0,0,Failed,Timed out,q\r\n",
        ),
        (
            "Statistics-2026-01-05_09-00-00.csv",
            "\u{feff}DataSourceName,DataSourceType,Location,LocationType,LocationSubType,StatType,StatName,OriginalStatName,Value\r\n",
        ),
        ("Summary-2026-01-05_09-00-00.csv", "\u{feff}LocationCount,2,x\r\n"),
    ] {
        writer.start_file(name, options).unwrap();
        writer.write_all(body.as_bytes()).unwrap();
    }
    writer.finish().unwrap();
    path
}

/// `parse` runs with an empty configuration directory, signs nothing in,
/// and creates no configuration.
#[test]
fn parse_reads_a_generated_zip_with_no_configuration() {
    let dir = tempfile::tempdir().unwrap();
    let zip = estimate_zip_file(dir.path());
    let missing = dir.path().join("missing");
    for (subcommand, check) in [
        ("locations", "alex@contoso.example"),
        ("failures", "sam@contoso.example"),
        ("summary", "LocationCount"),
    ] {
        let output = purview()
            .env("PURVIEW_CONFIG_DIR", &missing)
            .args(["--json", "parse", subcommand])
            .arg(&zip)
            .assert()
            .success()
            .stderr(predicate::str::is_empty())
            .get_output()
            .stdout
            .clone();
        let text = String::from_utf8(output).unwrap();
        assert!(text.contains(check), "{subcommand}: {text}");
        serde_json::from_str::<Value>(&text).unwrap();
    }
    purview()
        .env("PURVIEW_CONFIG_DIR", &missing)
        .args(["parse", "locations", "--with-hits", "--plain"])
        .arg(&zip)
        .assert()
        .success()
        .stdout("alex@contoso.example\tPrimaryMailBox\t12\t2048\tSucceeded\n");
    assert!(!missing.exists());
    // A file that is not a zip is refused without naming its path.
    let not_zip = dir.path().join("plain.zip");
    std::fs::write(&not_zip, b"not a zip").unwrap();
    let output = purview()
        .env("PURVIEW_CONFIG_DIR", &missing)
        .args(["--json", "parse", "locations"])
        .arg(&not_zip)
        .assert()
        .code(1)
        .get_output()
        .stdout
        .clone();
    let value: Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(value["error"]["code"], "HostileZip");
    assert!(!value["error"]["message"]
        .as_str()
        .unwrap()
        .contains("plain.zip"));
}

#[test]
fn estimate_argument_errors_and_no_write_need_no_network() {
    let case = "00000000-0000-4000-8000-000000000031";
    let search = "00000000-0000-4000-8000-000000000051";
    for extra in [
        &["--strict", "--no-download"][..],
        &["--strict", "--no-wait"],
        &["--reason", "x"],
        &["--allow-generic"],
        &["--no-wait", "--wait-timeout", "1m"],
        &["--wait-timeout", "nonsense"],
        &["--poll-interval", "1s"],
    ] {
        let mut args = vec!["estimate", case, search];
        args.extend_from_slice(extra);
        assert_eq!(refused_before_sign_in(&args), "CommandFailed", "{extra:?}");
    }
    assert_eq!(
        refused_before_sign_in(&["--no-write", "estimate", case, search]),
        "WriteRefused"
    );
}

/// `--no-teams-context` was observed for `report` (PR 2.5), not for
/// `export create` (PR 4.1): only the second is labelled experimental.
#[test]
fn only_export_create_calls_no_teams_context_experimental() {
    let help = |args: &[&str]| {
        let output = purview()
            .args(args)
            .assert()
            .success()
            .get_output()
            .stdout
            .clone();
        String::from_utf8(output).unwrap()
    };
    let report = help(&["report", "--help"]);
    assert!(report.contains("--no-teams-context"), "{report}");
    assert!(!report.contains("experimental"), "{report}");
    let export = help(&["export", "create", "--help"]);
    assert!(export.contains("--no-teams-context"), "{export}");
    assert!(
        export.contains("experimental: not yet observed"),
        "{export}"
    );
    assert!(export.contains("and is experimental"), "{export}");
}
