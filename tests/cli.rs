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
            "Error: unexpected argument '--bogus' found\n",
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
            "version",
            "help"
        ],
        "{text}"
    );
}

#[test]
fn read_command_groups_list_exactly_their_shipped_commands() {
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
        assert_eq!(commands, ["list", "get", "help"], "{group}: {text}");
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
        .stderr(predicate::str::starts_with("Error: invalid client id"));
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
