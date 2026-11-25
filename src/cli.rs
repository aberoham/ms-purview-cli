//! The Clap command tree, dispatch, and the top-level printer that turns a
//! command's `Outcome` or error into output and an exit code.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::io::Write;

use clap::{error::ErrorKind, CommandFactory, Parser, Subcommand};
use serde_json::{json, Value};

use crate::env::Env;
use crate::error::{PurviewError, Result};
use crate::output::{error_value, sanitize, sanitize_multiline, OutputFormat, OutputOptions};

/// The command line. Clap never reads the process environment here: flag
/// defaults come from `Env::vars` (see `FlagDefaults`).
#[derive(Debug, Clone, Parser)]
#[command(
    name = "purview",
    // Fixed, so usage reads `purview` and not `purview.exe` on Windows.
    bin_name = "purview",
    about = "Microsoft Purview eDiscovery (Premium) from the terminal, through Microsoft Graph",
    after_help = "\
Examples:
  purview version
  purview version --json",
    next_help_heading = "Global Options"
)]
struct Cli {
    #[arg(
        long,
        global = true,
        help = "Print JSON, as {\"results\": ..., \"count\": ...} [env: PURVIEW_JSON=true]"
    )]
    json: bool,
    #[arg(
        long,
        global = true,
        help = "With --json, print the results without the {results, count} envelope \
[env: PURVIEW_RESULTS_ONLY=true]"
    )]
    results_only: bool,
    #[arg(
        long,
        global = true,
        help = "Print lists as tab-separated values with no header row [env: PURVIEW_PLAIN=true]"
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

/// Defaults for the global flags, from `PURVIEW_JSON`,
/// `PURVIEW_RESULTS_ONLY` and `PURVIEW_PLAIN`. Each accepts `true` or
/// `false`; an empty or unset variable is `false`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct FlagDefaults {
    json: bool,
    results_only: bool,
    plain: bool,
}

impl FlagDefaults {
    fn from_vars(vars: &BTreeMap<String, OsString>) -> std::result::Result<Self, String> {
        let flag = |name: &str| match vars.get(name) {
            None => Ok(false),
            Some(value) if value.is_empty() || value == "false" => Ok(false),
            Some(value) if value == "true" => Ok(true),
            Some(_) => Err(format!("{name} must be true or false")),
        };
        Ok(Self {
            json: flag("PURVIEW_JSON")?,
            results_only: flag("PURVIEW_RESULTS_ONLY")?,
            plain: flag("PURVIEW_PLAIN")?,
        })
    }
}

/// What a command produced. Exit code 0 is success; a fatal error is an
/// `Err` from the command, which the top-level printer turns into exit 1.
/// `stdout_value` is the JSON document written to stdout, after redaction,
/// when one was written in full.
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

    fn failure(stdout_value: Option<Value>) -> Self {
        Self {
            exit_code: 1,
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
/// prints goes to `env.stdout` and `env.stderr`, through the redactor; JSON
/// is redacted as a value before it is serialised. A failure to write or
/// flush stdout makes the exit code 1.
#[doc(hidden)]
pub async fn execute_with<I, T>(mut env: Env, args: I) -> Outcome
where
    I: IntoIterator<Item = T>,
    T: Into<OsString> + Clone,
{
    let args: Vec<OsString> = args.into_iter().map(Into::into).collect();
    let defaults = FlagDefaults::from_vars(&env.vars);
    // Read on its own, so that an invalid PURVIEW_PLAIN or
    // PURVIEW_RESULTS_ONLY still gets its error in JSON when asked.
    let json_default = env
        .vars
        .get("PURVIEW_JSON")
        .is_some_and(|value| value == "true");
    let mut printer = Printer::default();
    let mut outcome = match (Cli::try_parse_from(&args), defaults) {
        (Ok(cli), Ok(defaults)) => {
            let options = output_options(&cli, defaults);
            let json_mode = options.format == OutputFormat::Json;
            match run(&mut env, &options, cli.command).await {
                Ok(outcome) => printer.deliver(&mut env, outcome),
                // A command that failed because stdout refused its output
                // gets the output diagnostic, not a second error.
                Err(PurviewError::Io(error)) if env.stdout.has_failed() => {
                    printer.output_failed(&mut env, &error)
                }
                Err(error) if env.stdout.has_failed() => printer.output_failed(&mut env, &error),
                Err(error) => printer.fail(&mut env, json_mode, &error),
            }
        }
        (Ok(cli), Err(message)) => {
            let usage = Cli::command().render_usage().to_string();
            let message = format!(
                "{message}\n\n{}\n\nFor more information, try '--help'.",
                usage.trim_end()
            );
            printer.fail(
                &mut env,
                cli.json || json_default,
                &PurviewError::message(message),
            )
        }
        (Err(error), _) => printer.parse_failure(&mut env, &args, json_default, error),
    };
    if let Err(error) = env.stdout.finish() {
        outcome = printer.output_failed(&mut env, &error);
    }
    if env.stderr.finish().is_err() {
        outcome.exit_code = 1;
    }
    outcome
}

fn output_options(cli: &Cli, defaults: FlagDefaults) -> OutputOptions {
    let json = cli.json || defaults.json;
    let plain = cli.plain || defaults.plain;
    OutputOptions {
        format: if json {
            OutputFormat::Json
        } else if plain {
            OutputFormat::Plain
        } else {
            OutputFormat::Table
        },
        select: String::new(),
        results_only: cli.results_only || defaults.results_only,
    }
}

/// Writes results and errors, and remembers whether stdout has already
/// failed, so the failure is reported once and no second document follows
/// a partial one.
#[derive(Debug, Default)]
struct Printer {
    stdout_failed: bool,
}

impl Printer {
    fn deliver(&mut self, env: &mut Env, outcome: Outcome) -> Outcome {
        let Some(value) = outcome.stdout_value else {
            return outcome;
        };
        match json_document(env, &value) {
            Some((safe, bytes)) => match env.stdout.write_all(&bytes) {
                Ok(()) => Outcome {
                    exit_code: outcome.exit_code,
                    stdout_value: Some(safe),
                },
                Err(error) => self.output_failed(env, &error),
            },
            None => self.fail(
                env,
                true,
                &PurviewError::message(
                    "refusing to print the result: a part of it outside a JSON string, such as \
                     a number, matches a secret the tool holds",
                ),
            ),
        }
    }

    /// Exit 1: the error document on stdout under `--json`, otherwise
    /// `Error: …` on stderr. An error document that cannot be printed
    /// safely falls back to stderr.
    fn fail(&mut self, env: &mut Env, json_mode: bool, error: &PurviewError) -> Outcome {
        if json_mode && !self.stdout_failed {
            if let Some((value, bytes)) = json_document(env, &error_value(error)) {
                return match env.stdout.write_all(&bytes) {
                    Ok(()) => Outcome::failure(Some(value)),
                    Err(write_error) => self.output_failed(env, &write_error),
                };
            }
        }
        let _ = writeln!(
            env.stderr,
            "Error: {}",
            sanitize_multiline(&error.to_string())
        );
        Outcome::failure(None)
    }

    /// Stdout could not be written or flushed: say so on stderr, once.
    fn output_failed(&mut self, env: &mut Env, error: &dyn std::fmt::Display) -> Outcome {
        if !self.stdout_failed {
            self.stdout_failed = true;
            let _ = writeln!(
                env.stderr,
                "Error: could not write to standard output: {}",
                sanitize(&error.to_string())
            );
        }
        Outcome::failure(None)
    }

    /// Clap's help is success on stdout. Any other parse failure is an
    /// argument error, exit 1, in the JSON error shape when JSON was asked
    /// for, and otherwise as `Error: …` followed by Clap's usage.
    fn parse_failure(
        &mut self,
        env: &mut Env,
        args: &[OsString],
        json_default: bool,
        error: clap::Error,
    ) -> Outcome {
        let rendered = error.render().to_string();
        if matches!(
            error.kind(),
            ErrorKind::DisplayHelp | ErrorKind::DisplayVersion
        ) {
            return match env.stdout.write_all(rendered.as_bytes()) {
                Ok(()) => Outcome::success(None),
                Err(write_error) => self.output_failed(env, &write_error),
            };
        }
        let message = if error.kind() == ErrorKind::DisplayHelpOnMissingArgumentOrSubcommand {
            format!("a command is required\n\n{}", rendered.trim_end())
        } else {
            let text = rendered.trim();
            text.strip_prefix("error: ").unwrap_or(text).to_owned()
        };
        let json_mode = json_requested(args, json_default);
        self.fail(env, json_mode, &PurviewError::message(message))
    }
}

/// The document as it will be printed: strings redacted as values, then
/// serialised with a final newline. `None` when the serialised bytes still
/// match a secret, which can only happen outside string contents (a number,
/// say); byte redaction there would break the JSON, so the caller fails
/// closed instead.
fn json_document(env: &Env, value: &Value) -> Option<(Value, Vec<u8>)> {
    let safe = env.redactor.redact_value(value);
    let mut bytes = serde_json::to_vec_pretty(&safe).ok()?;
    bytes.push(b'\n');
    (!env.redactor.recognises_bytes(&bytes)).then_some((safe, bytes))
}

/// Whether a command line Clap refused asked for JSON: `--json` before any
/// `--`, or `PURVIEW_JSON=true` in `Env`.
fn json_requested(args: &[OsString], json_default: bool) -> bool {
    json_default
        || args
            .iter()
            .skip(1)
            .take_while(|arg| *arg != "--")
            .any(|arg| arg == "--json")
}

async fn run(env: &mut Env, output: &OutputOptions, command: Command) -> Result<Outcome> {
    match command {
        Command::Version => version(env, output),
    }
}

const VERSION: &str = env!("CARGO_PKG_VERSION");
/// The release workflow sets this at build time; a local build has none.
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
    use std::io;
    use std::sync::{Arc, Mutex};

    use super::*;

    fn with_vars(env: &mut Env, vars: &[(&str, &str)]) {
        for (name, value) in vars {
            env.vars.insert((*name).to_owned(), (*value).into());
        }
    }

    #[tokio::test]
    async fn version_runs_in_process_and_prints_three_fields() {
        let (env, captured) = Env::in_memory();
        let outcome = execute_with(env, ["purview", "version"]).await;
        assert_eq!(outcome, Outcome::success(None));
        let text = captured.stdout.text();
        let fields: Vec<&str> = text.trim_end().split(' ').collect();
        assert_eq!(fields.len(), 4, "{text:?}");
        assert_eq!(fields[..2], ["purview", VERSION]);
        assert_eq!(
            fields[2],
            BUILD_COMMIT
                .filter(|commit| !commit.is_empty())
                .unwrap_or("unknown")
        );
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
    async fn flag_defaults_come_from_env_vars_not_the_process() {
        let (mut env, captured) = Env::in_memory();
        with_vars(
            &mut env,
            &[("PURVIEW_JSON", "true"), ("PURVIEW_RESULTS_ONLY", "true")],
        );
        let outcome = execute_with(env, ["purview", "version"]).await;
        assert_eq!(outcome.exit_code, 0);
        let printed: Value = serde_json::from_str(&captured.stdout.text()).unwrap();
        assert_eq!(printed["version"], VERSION);
    }

    #[tokio::test]
    async fn an_invalid_flag_variable_is_an_argument_error() {
        let (mut env, captured) = Env::in_memory();
        with_vars(&mut env, &[("PURVIEW_PLAIN", "yes")]);
        let outcome = execute_with(env, ["purview", "version"]).await;
        assert_eq!(outcome, Outcome::failure(None));
        let text = captured.stderr.text();
        assert_eq!(
            text.lines().next(),
            Some("Error: PURVIEW_PLAIN must be true or false"),
            "{text}"
        );
        assert!(
            text.contains("Usage: purview [OPTIONS] <COMMAND>"),
            "{text}"
        );
        assert!(captured.stdout.text().is_empty());
    }

    #[tokio::test]
    async fn an_invalid_flag_variable_still_answers_in_json_when_asked() {
        for args in [
            &["purview", "version"][..],
            &["purview", "version", "--bogus"][..],
        ] {
            let (mut env, captured) = Env::in_memory();
            with_vars(
                &mut env,
                &[("PURVIEW_JSON", "true"), ("PURVIEW_PLAIN", "yes")],
            );
            let outcome = execute_with(env, args.to_vec()).await;
            assert_eq!(outcome.exit_code, 1, "{args:?}");
            let printed: Value = serde_json::from_str(&captured.stdout.text()).unwrap();
            assert_eq!(Some(&printed), outcome.stdout_value.as_ref(), "{args:?}");
            assert_eq!(printed["error"]["code"], "CommandFailed");
            assert!(captured.stderr.text().is_empty(), "{args:?}");
        }
    }

    #[tokio::test]
    async fn a_secret_outside_a_json_string_fails_closed_with_valid_output() {
        // "1" matches the count; the error document has no 1 in it.
        let (env, captured) = Env::in_memory();
        env.redactor.register("1");
        let outcome = execute_with(env, ["purview", "--json", "version"]).await;
        assert_eq!(outcome.exit_code, 1);
        let printed: Value = serde_json::from_str(&captured.stdout.text()).unwrap();
        assert_eq!(Some(&printed), outcome.stdout_value.as_ref());
        assert!(printed["error"]["message"]
            .as_str()
            .unwrap()
            .starts_with("refusing to print the result"));

        // With "0" too, the error document cannot be printed either: it goes
        // to stderr and stdout stays empty.
        let (env, captured) = Env::in_memory();
        env.redactor.register("1");
        env.redactor.register("0");
        let outcome = execute_with(env, ["purview", "--json", "version"]).await;
        assert_eq!(outcome, Outcome::failure(None));
        assert!(captured.stdout.text().is_empty());
        assert!(captured
            .stderr
            .text()
            .starts_with("Error: refusing to print the result"));
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
        let message = printed["error"]["message"].as_str().unwrap();
        assert!(
            message.starts_with("unexpected argument '--bogus'"),
            "{message}"
        );
        assert!(captured.stderr.text().is_empty());
    }

    #[tokio::test]
    async fn a_human_argument_error_starts_with_error_and_keeps_usage() {
        let (env, captured) = Env::in_memory();
        let outcome = execute_with(env, ["purview", "version", "--bogus"]).await;
        assert_eq!(outcome, Outcome::failure(None));
        let text = captured.stderr.text();
        assert_eq!(
            text.lines().next(),
            Some("Error: unexpected argument '--bogus' found"),
            "{text}"
        );
        assert!(text.contains("Usage: purview version"), "{text}");
        assert!(!text.contains("error: "), "{text}");
    }

    #[tokio::test]
    async fn a_missing_command_is_an_error_then_the_help() {
        let (env, captured) = Env::in_memory();
        let outcome = execute_with(env, ["purview"]).await;
        assert_eq!(outcome.exit_code, 1);
        let text = captured.stderr.text();
        assert_eq!(text.lines().next(), Some("Error: a command is required"));
        assert!(text.contains("Commands:"), "{text}");
        assert!(captured.stdout.text().is_empty());
    }

    #[tokio::test]
    async fn help_is_success_on_stdout() {
        let (env, captured) = Env::in_memory();
        let outcome = execute_with(env, ["purview", "--help"]).await;
        assert_eq!(outcome.exit_code, 0);
        assert!(captured.stdout.text().contains("version"));
        assert!(captured.stderr.text().is_empty());
    }

    #[tokio::test]
    async fn json_errors_are_redacted_as_values_and_stay_valid() {
        let secret = "canary\"refresh\\0001";
        for json in [true, false] {
            let (env, captured) = Env::in_memory();
            env.redactor.register(secret);
            let mut args = vec!["purview", secret];
            if json {
                args.push("--json");
            }
            let outcome = execute_with(env, args).await;
            assert_eq!(outcome.exit_code, 1);
            let stdout = captured.stdout.text();
            let stderr = captured.stderr.text();
            assert!(!stdout.contains("canary") && !stderr.contains("canary"));
            if json {
                let printed: Value = serde_json::from_str(&stdout).unwrap();
                assert_eq!(Some(&printed), outcome.stdout_value.as_ref());
                let message = printed["error"]["message"].as_str().unwrap();
                assert!(message.contains("[redacted]"), "{message}");
            } else {
                assert!(stderr.contains("[redacted]"), "{stderr}");
            }
        }
    }

    /// A stream that fails on write, on flush, or neither, and records what
    /// reached it.
    #[derive(Clone)]
    struct Faulty {
        fail_write: bool,
        fail_flush: bool,
        /// Bytes accepted before writes start failing.
        accept: usize,
        written: Arc<Mutex<Vec<u8>>>,
    }

    impl Faulty {
        fn new(fail_write: bool, fail_flush: bool) -> Self {
            Self {
                fail_write,
                fail_flush,
                accept: 0,
                written: Arc::default(),
            }
        }

        fn accepting(accept: usize) -> Self {
            Self {
                accept,
                ..Self::new(true, false)
            }
        }

        fn text(&self) -> String {
            String::from_utf8(self.written.lock().unwrap().clone()).unwrap()
        }
    }

    impl Write for Faulty {
        fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
            let mut written = self.written.lock().unwrap();
            if self.fail_write {
                let room = self.accept.saturating_sub(written.len());
                if room == 0 {
                    return Err(io::Error::new(io::ErrorKind::BrokenPipe, "closed"));
                }
                let taken = room.min(buffer.len());
                written.extend_from_slice(&buffer[..taken]);
                return Ok(taken);
            }
            written.extend_from_slice(buffer);
            Ok(buffer.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            if self.fail_flush {
                return Err(io::Error::other("flush refused"));
            }
            Ok(())
        }
    }

    async fn run_with_stdout(stdout: Faulty, args: &[&str]) -> (Outcome, String) {
        let stderr = Faulty::new(false, false);
        let env = Env::with_writers(Box::new(stdout), Box::new(stderr.clone()));
        let outcome = execute_with(env, args.to_vec()).await;
        (outcome, stderr.text())
    }

    #[tokio::test]
    async fn a_failed_stdout_write_exits_1_and_reports_once() {
        for args in [
            &["purview", "version", "--json"][..],
            &["purview", "version"][..],
            &["purview", "--help"][..],
            &["purview", "version", "--bogus", "--json"][..],
        ] {
            for stdout in [
                Faulty::new(true, false),
                Faulty::new(true, true),
                Faulty::accepting(9),
            ] {
                let (outcome, stderr) = run_with_stdout(stdout, args).await;
                assert_eq!(outcome, Outcome::failure(None), "{args:?}");
                assert_eq!(
                    stderr, "Error: could not write to standard output: closed\n",
                    "{args:?}"
                );
            }
        }
    }

    #[tokio::test]
    async fn a_failed_stdout_flush_exits_1() {
        for args in [
            &["purview", "version", "--json"][..],
            &["purview", "--help"][..],
        ] {
            let stdout = Faulty::new(false, true);
            let (outcome, stderr) = run_with_stdout(stdout.clone(), args).await;
            assert_eq!(outcome.exit_code, 1, "{args:?}");
            assert!(stderr.contains("flush refused"), "{args:?}: {stderr}");
            assert!(!stdout.text().is_empty(), "{args:?}");
        }
    }

    #[test]
    fn json_is_requested_by_flag_before_a_double_dash_or_by_the_default() {
        let args = |list: &[&str]| list.iter().map(OsString::from).collect::<Vec<_>>();
        assert!(json_requested(&args(&["purview", "x", "--json"]), false));
        assert!(!json_requested(&args(&["purview", "--", "--json"]), false));
        assert!(!json_requested(&args(&["--json"]), false));
        assert!(json_requested(&args(&["purview"]), true));
    }

    #[test]
    fn flag_variables_accept_only_true_false_or_empty() {
        let vars = |pairs: &[(&str, &str)]| {
            pairs
                .iter()
                .map(|(name, value)| ((*name).to_owned(), OsString::from(value)))
                .collect::<BTreeMap<_, _>>()
        };
        assert_eq!(
            FlagDefaults::from_vars(&vars(&[])),
            Ok(FlagDefaults::default())
        );
        assert_eq!(
            FlagDefaults::from_vars(&vars(&[("PURVIEW_JSON", "true"), ("PURVIEW_PLAIN", "")])),
            Ok(FlagDefaults {
                json: true,
                ..FlagDefaults::default()
            })
        );
        assert!(FlagDefaults::from_vars(&vars(&[("PURVIEW_JSON", "1")])).is_err());
        assert!(FlagDefaults::from_vars(&vars(&[("PURVIEW_JSON", "TRUE")])).is_err());
    }
}
