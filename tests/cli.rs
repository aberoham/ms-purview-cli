//! Offline process contracts, run against the built binary.

use assert_cmd::Command;
use predicates::prelude::*;
use serde_json::Value;

fn purview() -> Command {
    let mut command = Command::new(assert_cmd::cargo::cargo_bin!("purview"));
    for name in [
        "PURVIEW_JSON",
        "PURVIEW_RESULTS_ONLY",
        "PURVIEW_PLAIN",
        "PURVIEW_BUILD_COMMIT",
    ] {
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

#[test]
fn a_recorded_commit_is_not_needed_for_the_text_form() {
    let output = purview().arg("version").output().unwrap();
    let text = String::from_utf8(output.stdout).unwrap();
    let commit = text.split(' ').nth(2).unwrap();
    assert!(!commit.contains(char::is_whitespace));
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
        .stderr(predicate::str::contains("--bogus"));
    purview()
        .assert()
        .code(1)
        .stdout(predicate::str::is_empty())
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
fn an_invalid_json_variable_is_refused_by_clap_in_human_form() {
    purview()
        .env("PURVIEW_JSON", "yes")
        .arg("version")
        .assert()
        .code(1)
        .stdout(predicate::str::is_empty())
        .stderr(predicate::str::contains("PURVIEW_JSON").or(predicate::str::contains("yes")));
}

#[test]
fn help_is_success_and_lists_only_version() {
    let output = purview()
        .arg("--help")
        .assert()
        .success()
        .stderr(predicate::str::is_empty())
        .get_output()
        .stdout
        .clone();
    let text = String::from_utf8(output).unwrap();
    assert!(text.contains("version"), "{text}");
    for later in [
        "auth", "case", "search", "estimate", "report", "export", "parse",
    ] {
        assert!(
            !text
                .lines()
                .any(|line| line.trim_start().starts_with(&format!("{later} "))),
            "{later} is listed before it exists: {text}"
        );
    }
}
