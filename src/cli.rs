//! The Clap command tree, dispatch, and the top-level printer that turns a
//! command's `Outcome` or error into output and an exit code.

use std::ffi::OsString;
use std::io::Write;

use clap::{error::ErrorKind, Parser, Subcommand};
use serde_json::{json, Value};

use crate::env::Env;
use crate::error::Result;
use crate::output::{
    error_value, sanitize, sanitize_multiline, write_pretty_json, OutputFormat, OutputOptions,
};

#[derive(Debug, Clone, Parser)]
#[command(
    name = "purview",
    about = "Microsoft Purview eDiscovery (Premium) from the terminal, through Microsoft Graph",
    after_help = "\
Examples:
  purview version
  purview version --json",
    next_help_heading = "Global Options"
)]
pub struct Cli {
    #[arg(
        long,
        global = true,
        env = "PURVIEW_JSON",
        help = "Print JSON, as {\"results\": ..., \"count\": ...}"
    )]
    json: bool,
    #[arg(
        long,
        global = true,
        env = "PURVIEW_RESULTS_ONLY",
        help = "With --json, print the results without the {results, count} envelope"
    )]
    results_only: bool,
    #[arg(
        long,
        global = true,
        env = "PURVIEW_PLAIN",
        help = "Print lists as tab-separated values with no header row"
    )]
    plain: bool,
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Clone, Subcommand)]
enum Command {
    #[command(
        about = "Show the version, commit and build target",
        after_help = "\
Examples:
  purview version
  purview version --json"
    )]
    Version,
}

/// What a command produced. Exit code 0 is success; a fatal error is an
/// `Err` from the command, which the top-level printer turns into exit 1.
/// `stdout_value` is the JSON document written to stdout, when there is one.
#[doc(hidden)]
#[derive(Debug, Clone, PartialEq)]
pub struct Outcome {
    pub exit_code: i32,
    pub stdout_value: Option<Value>,
}

impl Outcome {
    fn success(stdout_value: Option<Value>) -> Self {
        Self {
            exit_code: 0,
            stdout_value,
        }
    }
}

/// Runs the process's own command line and returns its exit code.
pub async fn execute() -> i32 {
    execute_with(Env::production(), std::env::args_os())
        .await
        .exit_code
}

/// Runs one command line in-process against `env`. Everything the command
/// prints goes to `env.stdout` and `env.stderr`, through the redactor.
#[doc(hidden)]
pub async fn execute_with<I, T>(mut env: Env, args: I) -> Outcome
where
    I: IntoIterator<Item = T>,
    T: Into<OsString> + Clone,
{
    let args: Vec<OsString> = args.into_iter().map(Into::into).collect();
    let outcome = match Cli::try_parse_from(&args) {
        Ok(cli) => {
            let json_mode = cli.json;
            match run(&mut env, cli).await {
                Ok(outcome) => {
                    if let Some(value) = &outcome.stdout_value {
                        if write_pretty_json(&mut env.stdout, value).is_err() {
                            let _ = writeln!(env.stderr, "Error: JSON output failed");
                        }
                    }
                    outcome
                }
                Err(error) => {
                    let value = error_value(&error);
                    write_failure(&mut env, json_mode, &value, &error.to_string())
                }
            }
        }
        Err(error) => parse_failure(&mut env, &args, error),
    };
    let _ = env.stdout.flush();
    let _ = env.stderr.flush();
    outcome
}

/// Clap's help is success on stdout. Any other parse failure is an
/// argument error, exit 1, in the JSON error shape when JSON was asked for.
fn parse_failure(env: &mut Env, args: &[OsString], error: clap::Error) -> Outcome {
    let rendered = error.render().to_string();
    if matches!(
        error.kind(),
        ErrorKind::DisplayHelp | ErrorKind::DisplayVersion
    ) {
        let _ = env.stdout.write_all(rendered.as_bytes());
        return Outcome::success(None);
    }
    let json_mode = json_requested(args, std::env::var_os("PURVIEW_JSON"));
    let message = rendered.trim();
    let value = json!({
        "error": { "code": "CommandFailed", "status": 0, "message": message }
    });
    if json_mode {
        write_failure(env, true, &value, message)
    } else {
        // Clap's own text, which already carries usage and a pointer to
        // --help.
        let _ = writeln!(env.stderr, "{}", sanitize_multiline(message));
        Outcome {
            exit_code: 1,
            stdout_value: None,
        }
    }
}

/// Exit 1: the error document on stdout under `--json`, otherwise
/// `Error: …` on stderr.
fn write_failure(env: &mut Env, json_mode: bool, value: &Value, message: &str) -> Outcome {
    if json_mode {
        if write_pretty_json(&mut env.stdout, value).is_err() {
            let _ = writeln!(env.stderr, "Error: JSON error output failed");
        }
        return Outcome {
            exit_code: 1,
            stdout_value: Some(value.clone()),
        };
    }
    let _ = writeln!(env.stderr, "Error: {}", sanitize_multiline(message));
    Outcome {
        exit_code: 1,
        stdout_value: None,
    }
}

/// Whether a command line Clap refused asked for JSON, through `--json`
/// before any `--`, or `PURVIEW_JSON`. Clap accepts only `true` or `false`
/// for that variable, so only `true` asks for JSON here.
fn json_requested(args: &[OsString], env: Option<OsString>) -> bool {
    let flag = args
        .iter()
        .skip(1)
        .take_while(|arg| *arg != "--")
        .any(|arg| arg == "--json");
    flag || env.is_some_and(|value| value == "true")
}

async fn run(env: &mut Env, cli: Cli) -> Result<Outcome> {
    let output = OutputOptions {
        format: if cli.json {
            OutputFormat::Json
        } else if cli.plain {
            OutputFormat::Plain
        } else {
            OutputFormat::Table
        },
        select: String::new(),
        results_only: cli.results_only,
    };
    match cli.command {
        Command::Version => version(env, &output),
    }
}

const VERSION: &str = env!("CARGO_PKG_VERSION");
/// The release workflow sets these at build time; a local build has none.
const BUILD_COMMIT: Option<&str> = option_env!("PURVIEW_BUILD_COMMIT");
/// Set by `build.rs` from Cargo's `TARGET`.
const BUILD_TARGET: &str = env!("PURVIEW_BUILD_TARGET");

/// `purview <version> <commit> <target>`, or the same three fields in the
/// JSON envelope. A build without a recorded commit prints `unknown` and
/// JSON `null`.
fn version(env: &mut Env, output: &OutputOptions) -> Result<Outcome> {
    let commit = BUILD_COMMIT.filter(|value| !value.is_empty());
    if output.format == OutputFormat::Json {
        let result = json!({
            "version": VERSION,
            "commit": commit,
            "target": BUILD_TARGET,
        });
        return Ok(Outcome::success(Some(output.json_value(&result, 1)?)));
    }
    writeln!(
        env.stdout,
        "purview {VERSION} {} {}",
        sanitize(commit.unwrap_or("unknown")),
        sanitize(BUILD_TARGET)
    )?;
    Ok(Outcome::success(None))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn version_runs_in_process_and_prints_three_fields() {
        let (env, captured) = Env::in_memory();
        let outcome = execute_with(env, ["purview", "version"]).await;
        assert_eq!(outcome, Outcome::success(None));
        let text = captured.stdout.text();
        let fields: Vec<&str> = text.trim_end().split(' ').collect();
        assert_eq!(fields.len(), 4, "{text:?}");
        assert_eq!(fields[..2], ["purview", VERSION]);
        assert_eq!(fields[3], BUILD_TARGET);
        assert!(captured.stderr.text().is_empty());
    }

    #[tokio::test]
    async fn version_json_is_returned_and_printed() {
        let (env, captured) = Env::in_memory();
        let outcome = execute_with(env, ["purview", "--json", "version"]).await;
        let value = outcome.stdout_value.expect("a JSON document");
        assert_eq!(value["count"], 1);
        assert_eq!(value["results"]["version"], VERSION);
        assert_eq!(value["results"]["target"], BUILD_TARGET);
        let printed: Value = serde_json::from_str(&captured.stdout.text()).unwrap();
        assert_eq!(printed, value);
    }

    #[tokio::test]
    async fn an_unknown_flag_under_json_is_one_error_document() {
        let (env, captured) = Env::in_memory();
        let outcome = execute_with(env, ["purview", "version", "--bogus", "--json"]).await;
        assert_eq!(outcome.exit_code, 1);
        let printed: Value = serde_json::from_str(&captured.stdout.text()).unwrap();
        assert_eq!(Some(&printed), outcome.stdout_value.as_ref());
        assert_eq!(printed["error"]["code"], "CommandFailed");
        assert_eq!(printed["error"]["status"], 0);
        assert!(printed["error"]["message"]
            .as_str()
            .unwrap()
            .contains("--bogus"));
        assert!(captured.stderr.text().is_empty());
    }

    #[tokio::test]
    async fn help_is_success_on_stdout() {
        let (env, captured) = Env::in_memory();
        let outcome = execute_with(env, ["purview", "--help"]).await;
        assert_eq!(outcome.exit_code, 0);
        assert!(captured.stdout.text().contains("version"));
        assert!(captured.stderr.text().is_empty());
    }

    #[test]
    fn json_is_requested_by_flag_before_a_double_dash_or_by_true() {
        let args = |list: &[&str]| list.iter().map(OsString::from).collect::<Vec<_>>();
        assert!(json_requested(&args(&["purview", "x", "--json"]), None));
        assert!(!json_requested(&args(&["purview", "--", "--json"]), None));
        assert!(!json_requested(&args(&["--json"]), None));
        assert!(json_requested(&args(&["purview"]), Some("true".into())));
        assert!(!json_requested(&args(&["purview"]), Some("1".into())));
    }
}
