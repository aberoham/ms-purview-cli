//! The Clap command tree, dispatch, and the top-level printer that turns a
//! command's `Outcome` or error into output and an exit code.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use clap::{error::ErrorKind, Args, CommandFactory, Parser, Subcommand};
use serde_json::{json, Value};

use crate::auth::{self, IdentityClient};
use crate::commands::{self, Session};
use crate::config::{self, AccountRecord, ClientConfig, Config};
use crate::env::{Env, LoginWrite};
use crate::error::{PurviewError, Result};
use crate::graph::{GraphClient, GraphSettings, DEFAULT_TIMEOUT, MAX_TIMEOUT_SECONDS};
use crate::model::valid::{self, CaseKey, SearchKey};
use crate::output::{
    error_value, sanitize, sanitize_multiline, write_rows, OutputFormat, OutputOptions,
};
use crate::poll;
use crate::routes::OperationId;
use crate::routes::{Query, ReadRoute};
use crate::secrets::{delete_value, entry_exists, token_key, CredentialLock};
use crate::token::{Credential, IdentityEndpoint, StoredPrincipal, StoredTokenProvider};
use crate::trace::TraceSink;

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
  purview auth login --client-id <application-client-id> --tenant-id <tenant-id>
  purview auth status
  purview case list --status active
  purview search list <case>
  purview operation get <case> <op> --wait
  purview kql --term orders-api --participant alex@contoso.example
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
    #[arg(
        long,
        global = true,
        value_name = "COLS",
        help = "Table or --plain columns to print, by header name, comma-separated \
[env: PURVIEW_SELECT]"
    )]
    select: Option<String>,
    #[arg(
        long,
        global = true,
        value_name = "EMAIL",
        help = "Stored account to use, by its address or the upn recorded at sign-in, ignoring \
case (default: the default account) [env: PURVIEW_ACCOUNT]"
    )]
    account: Option<String>,
    #[arg(
        long,
        global = true,
        help = "Never prompt; a command that needs input fails instead [env: PURVIEW_NO_INPUT=true]"
    )]
    no_input: bool,
    #[arg(
        short,
        long,
        global = true,
        help = "Log each Microsoft Graph request, and each token refresh made for it or by 'auth \
refresh', on stderr through the redactor [env: PURVIEW_VERBOSE=true]"
    )]
    verbose: bool,
    #[arg(
        long,
        global = true,
        value_name = "SECS",
        help = "Timeout for each Microsoft Graph request; 0 means 60, at most 600 \
[env: PURVIEW_TIMEOUT]"
    )]
    timeout: Option<String>,
    #[arg(
        long,
        global = true,
        value_name = "DIR",
        help = "Record each Microsoft Graph exchange as a JSON file in DIR, without tokens or \
request headers; the files hold tenant data [env: PURVIEW_TRACE_DIR]"
    )]
    trace: Option<PathBuf>,
    #[arg(
        long,
        global = true,
        help = "In JSON, wrap text that tenant users wrote (names, descriptions, queries, file \
names) in [UNTRUSTED:<id>] markers [env: PURVIEW_WRAP_UNTRUSTED=true]"
    )]
    wrap_untrusted: bool,
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Clone, Subcommand)]
enum Command {
    #[command(
        about = "Sign in, refresh, check, list and sign out accounts",
        long_about = "\
Sign in, refresh, check, list and sign out accounts. Tokens are kept only in \
the operating system's credential store.",
        after_help = "\
Examples:
  purview auth login --client-id <application-client-id> --tenant-id <tenant-id>
  purview auth refresh
  purview auth status
  purview auth list
  purview auth logout --account alex@contoso.example"
    )]
    Auth(AuthArgs),
    #[command(
        about = "List and show eDiscovery cases",
        after_help = "\
Examples:
  purview case list
  purview case list --status active --mine
  purview case list --name orders --created-after 2026-01-01
  purview case get <case>"
    )]
    Case(CaseArgs),
    #[command(
        about = "List and show the searches in a case",
        after_help = "\
Examples:
  purview search list <case>
  purview search get <case> <search> --json"
    )]
    Search(SearchArgs),
    #[command(
        about = "List and show a case's operations: estimates, item reports and exports",
        after_help = "\
Examples:
  purview operation list <case>
  purview operation list <case> --resolve --action report
  purview operation get <case> <op>
  purview operation get <case> <op> --wait --wait-timeout 30m"
    )]
    Operation(OperationArgs),
    #[command(
        about = "Download an operation's files: estimate and item reports, export parts",
        long_about = "\
Download an operation's files. The operation is read again for current \
download addresses, and each file is streamed to a temporary file, checked \
(its size, and that it is a zip), then published under a name made safe for \
the file system. manifest.json in the directory records each file's size \
and SHA-256; a file already recorded and unchanged is not fetched again.

Files go to cases/<case-id>/<operation-id>/ under the user data directory \
(config.json defaults.data_dir changes it), or to --out. An existing file \
that is not a recorded download is never replaced without --overwrite. A \
file that cannot be downloaded, or an operation that finished without \
succeeding, exits 4 after the other files are written.",
        after_help = "\
Examples:
  purview download <case> <op>
  purview download <case> <op> --out ./evidence --json
  purview download <case> <op> --file <name> --overwrite"
    )]
    Download(DownloadArgs),
    #[command(
        about = "Check a query against the guard against generic tenant-wide searches",
        long_about = "\
Build a Keyword Query Language (KQL) query from the query flags, or take one \
with --kql, and check it as the guard of the search commands does. Every \
branch of the query that can match a message must be narrowed, by a \
specific term or by participants: on a full address. Prints the query, each \
term and restriction with its class and the rule that decided it, and the \
verdict. Exits 0 if the query is narrowed and 1 otherwise. Runs locally, \
with no sign-in; guard.specific_terms and guard.generic_terms in \
config.json change how terms are classified. docs/safety.md has the rules.",
        after_help = "\
Examples:
  purview kql --term orders-api --participant alex@contoso.example
  purview kql --term retention --participant alex@contoso.example --since 2025-01-01
  purview kql --kql '\"orders-api\" AND NOT from:noreply@notify.example' --json"
    )]
    Kql(QueryArgs),
    #[command(
        about = "Show the version, commit and build target",
        after_help = "\
Examples:
  purview version
  purview version --json"
    )]
    Version,
}

/// The query flags, shared with `search create` (`docs/SPEC.md` section
/// 3.5). The groups are ANDed in this order.
#[derive(Debug, Clone, Args)]
struct QueryArgs {
    #[arg(
        long = "term",
        value_name = "TEXT",
        help = "A word or phrase to search for, quoted in the query; repeat for more, all ORed"
    )]
    terms: Vec<String>,
    #[arg(
        long = "participant",
        value_name = "ADDR",
        help = "A full address that sent or received the item; repeat for more, all ORed"
    )]
    participants: Vec<String>,
    #[arg(
        long,
        value_name = "YYYY-MM-DD",
        value_parser = query_date,
        help = "Items sent on or after this date"
    )]
    since: Option<chrono::NaiveDate>,
    #[arg(
        long,
        value_name = "YYYY-MM-DD",
        value_parser = query_date,
        help = "Items sent on or before this date"
    )]
    until: Option<chrono::NaiveDate>,
    #[arg(long, value_enum, help = "Only email, or only Teams messages")]
    kind: Option<KindArg>,
    #[arg(
        long = "exclude-from",
        value_name = "ADDR",
        help = "Leave out items from this full address; repeat for more"
    )]
    exclude_from: Vec<String>,
    #[arg(
        long,
        value_name = "KQL",
        conflicts_with_all = ["terms", "participants", "since", "until", "kind", "exclude_from"],
        help = "A raw query in the guard's subset of KQL, instead of the flags above"
    )]
    kql: Option<String>,
}

/// A `--since` or `--until` date, in exactly the form the query takes, so
/// that the flags and `--kql` accept the same dates.
fn query_date(text: &str) -> std::result::Result<chrono::NaiveDate, String> {
    crate::kql::lexer::parse_date(text)
        .ok_or_else(|| "expected a date in the form YYYY-MM-DD".to_owned())
}

#[derive(Debug, Clone, Copy, clap::ValueEnum)]
enum KindArg {
    Email,
    Teams,
}

impl QueryArgs {
    fn flags(self) -> crate::kql::build::QueryFlags {
        crate::kql::build::QueryFlags {
            terms: self.terms,
            participants: self.participants,
            since: self.since,
            until: self.until,
            kind: self.kind.map(|kind| match kind {
                KindArg::Email => crate::kql::build::Kind::Email,
                KindArg::Teams => crate::kql::build::Kind::Teams,
            }),
            exclude_from: self.exclude_from,
            kql: self.kql,
        }
    }
}

#[derive(Debug, Clone, Args)]
struct AuthArgs {
    #[command(subcommand)]
    command: AuthCommand,
}

#[derive(Debug, Clone, Subcommand)]
enum AuthCommand {
    #[command(
        about = "Sign in and store the Graph and download tokens",
        long_about = "\
Sign in with a device code, or with --browser in the system browser. The \
sign-in asks for the Microsoft Graph eDiscovery permission, then redeems the \
refresh token for the Purview eDiscovery download token. Both tokens go to \
the operating system's credential store.

--browser opens the identity platform's sign-in page and receives the answer \
on a loopback address (http://localhost:<port>/callback), so the browser must \
run on this computer. The app registration needs the public-client redirect \
http://localhost/callback; contrib/create-purview-app.sh adds it.

purview has no app registration of its own. The first sign-in needs \
--client-id and --tenant-id (or PURVIEW_CLIENT_ID and PURVIEW_TENANT_ID); \
both are saved with the account, and a later sign-in reuses them.

If the app has no consent for the download permission, sign-in still \
succeeds with a warning, and downloads fail until 'purview auth refresh' \
succeeds after consent is granted.",
        after_help = "\
Examples:
  purview auth login --client-id <application-client-id> --tenant-id <tenant-id>
  purview auth login --browser
  purview auth login --read-only
  purview auth login --account alex@contoso.example"
    )]
    Login(AuthLogin),
    #[command(
        about = "Redeem the stored refresh token for both resources, with the scopes already held",
        long_about = "\
Redeem the stored refresh token for a new Graph token and a new download \
token, with the scopes already held. It never adds or removes a scope; sign \
in again with 'purview auth login' to change them. It succeeds only if the \
refresh and the credential-store write both succeed.",
        after_help = "\
Examples:
  purview auth refresh
  purview auth refresh --account alex@contoso.example --json"
    )]
    Refresh,
    #[command(
        about = "Check the Graph token and the Purview role with one read",
        long_about = "\
Check the account's Graph token and Purview role with one read of Microsoft \
Graph (the first case in the case list), refreshing the token first if it is \
about to expire. purviewRole is ok when Graph answers, denied when it refuses \
with HTTP 403, and unknown when the read fails any other way. A sign-in that \
no longer works (a refused refresh) is an error, not unknown; run 'purview \
auth login' again.

The download token's expiry comes from the stored credential; the download \
token is never sent.",
        after_help = "\
Examples:
  purview auth status
  purview auth status --account alex@contoso.example --json"
    )]
    Status,
    #[command(
        about = "List the signed-in accounts; * marks the default",
        after_help = "\
Examples:
  purview auth list
  purview auth list --json"
    )]
    List,
    #[command(
        about = "Remove an account's stored tokens and account file",
        after_help = "\
Examples:
  purview auth logout
  purview auth logout --account alex@contoso.example"
    )]
    Logout,
}

#[derive(Debug, Clone, Args)]
struct CaseArgs {
    #[command(subcommand)]
    command: CaseCommand,
}

const CASE_HELP: &str = "A case id, or the case's exact display name";
const SEARCH_HELP: &str = "A search id, or the search's exact display name within the case";

#[derive(Debug, Clone, Subcommand)]
enum CaseCommand {
    #[command(
        about = "List cases, filtered on this computer",
        long_about = "\
List every case the account can see, whatever its status, then filter on this \
computer. Dates are inclusive and compare UTC dates. --mine keeps the cases \
the signed-in account created.",
        after_help = "\
Examples:
  purview case list --status active
  purview case list --name orders --plain --select ID,NAME"
    )]
    List(CaseList),
    #[command(
        about = "Show one case",
        long_about = "\
Show one case. A name must match a case's display name exactly; names are not \
unique, and several matches fail with AmbiguousCase. --json prints Graph's \
record as it came.",
        after_help = "\
Examples:
  purview case get <case>
  purview case get \"Records research - Orders review\" --json"
    )]
    Get {
        #[arg(value_name = "CASE", help = CASE_HELP)]
        case: String,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
enum CaseStatusArg {
    Active,
    Closing,
    Closed,
    All,
}

#[derive(Debug, Clone, Args)]
struct CaseList {
    #[arg(
        long,
        value_enum,
        default_value = "all",
        help = "Keep cases in this status"
    )]
    status: CaseStatusArg,
    #[arg(
        long,
        value_name = "SUBSTR",
        help = "Keep cases whose display name contains SUBSTR, ignoring case"
    )]
    name: Option<String>,
    #[arg(
        long,
        value_name = "DATE",
        value_parser = parse_date,
        help = "Keep cases created on or before DATE (YYYY-MM-DD, UTC)"
    )]
    created_before: Option<chrono::NaiveDate>,
    #[arg(
        long,
        value_name = "DATE",
        value_parser = parse_date,
        help = "Keep cases created on or after DATE (YYYY-MM-DD, UTC)"
    )]
    created_after: Option<chrono::NaiveDate>,
    #[arg(long, help = "Keep cases the signed-in account created")]
    mine: bool,
}

fn parse_date(text: &str) -> std::result::Result<chrono::NaiveDate, String> {
    chrono::NaiveDate::parse_from_str(text.trim(), "%Y-%m-%d")
        // The value is not repeated, as in every argument error.
        .map_err(|_| "expected a date in the form YYYY-MM-DD".to_owned())
}

#[derive(Debug, Clone, Args)]
struct SearchArgs {
    #[command(subcommand)]
    command: SearchCommand,
}

#[derive(Debug, Clone, Subcommand)]
enum SearchCommand {
    #[command(
        about = "List the searches in a case",
        after_help = "\
Examples:
  purview search list <case>
  purview search list <case> --json"
    )]
    List {
        #[arg(value_name = "CASE", help = CASE_HELP)]
        case: String,
    },
    #[command(
        about = "Show one search, with its query, scope and sources",
        long_about = "\
Show one search: its query, its data source scope, and its custodian, \
non-custodial and additional sources, which an action on the search would \
also collect from. --json prints Graph's record, with the three source lists \
added under Graph's names for them.",
        after_help = "\
Examples:
  purview search get <case> <search>
  purview search get <case> <search> --json"
    )]
    Get {
        #[arg(value_name = "CASE", help = CASE_HELP)]
        case: String,
        #[arg(value_name = "SEARCH", help = SEARCH_HELP)]
        search: String,
    },
}

#[derive(Debug, Clone, Args)]
struct OperationArgs {
    #[command(subcommand)]
    command: OperationCommand,
}

#[derive(Debug, Clone, Subcommand)]
enum OperationCommand {
    #[command(
        about = "List a case's operations",
        long_about = "\
List a case's operations. The list shows both item reports and exports as \
exportResult, so their ACTION reads exportResult?, and --action report or \
--action export needs --resolve, which reads each operation on its own (four \
at a time) for its true action, counts and files.",
        after_help = "\
Examples:
  purview operation list <case>
  purview operation list <case> --status running
  purview operation list <case> --resolve --action export --json"
    )]
    List(OperationList),
    #[command(
        about = "Show one operation, or wait for it to finish",
        long_about = "\
Show one operation: its status, counts, result and files. --json includes \
each file's downloadUrl. An operation that finished without succeeding \
exits 4.

--wait reads the operation until it finishes: every 10 seconds for the first \
2 minutes, then every 30 seconds up to 10 minutes, then every minute. \
--wait-timeout (default 2h) ends the wait with exit 5, and Ctrl-C ends it \
with exit 130; either way the service carries on running the operation.",
        after_help = "\
Examples:
  purview operation get <case> <op>
  purview operation get <case> <op> --wait --wait-timeout 30m --json"
    )]
    Get(OperationGet),
}

#[derive(Debug, Clone, Args)]
struct DownloadArgs {
    #[arg(value_name = "CASE", help = CASE_HELP)]
    case: String,
    #[arg(value_name = "OP", help = "An operation id: 32 hexadecimal characters")]
    operation: String,
    #[arg(
        long,
        value_name = "DIR",
        help = "Write the files here instead of the data directory"
    )]
    out: Option<String>,
    #[arg(
        long,
        value_name = "NAME",
        help = "Download only the file with this exact name, as 'operation get' shows it"
    )]
    file: Option<String>,
    #[arg(
        long,
        help = "Replace files that exist, including verified downloads, instead of refusing"
    )]
    overwrite: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
enum ActionArg {
    Any,
    Estimate,
    Report,
    Export,
}

#[derive(Debug, Clone, Args)]
struct OperationList {
    #[arg(value_name = "CASE", help = CASE_HELP)]
    case: String,
    #[arg(
        long,
        value_enum,
        default_value = "any",
        help = "Keep operations of this action; report and export need --resolve"
    )]
    action: ActionArg,
    #[arg(
        long,
        value_name = "S",
        help = "Keep operations in this status: notStarted, running, succeeded, \
partiallySucceeded, failed or submissionFailed"
    )]
    status: Option<String>,
    #[arg(
        long,
        help = "Read each operation on its own for its true action, counts and files"
    )]
    resolve: bool,
}

#[derive(Debug, Clone, Args)]
struct OperationGet {
    #[arg(value_name = "CASE", help = CASE_HELP)]
    case: String,
    #[arg(value_name = "OP", help = "An operation id: 32 hexadecimal characters")]
    operation: String,
    #[arg(long, help = "Read the operation until it finishes")]
    wait: bool,
    #[arg(
        long,
        value_name = "DUR",
        requires = "wait",
        help = "How long --wait waits, such as 30m or 2h (default 2h, at most 24h)"
    )]
    wait_timeout: Option<String>,
    #[arg(
        long,
        value_name = "DUR",
        requires = "wait",
        help = "A fixed interval between reads, at least 5s (default: 10s, then 30s after 2 \
minutes, then 60s after 10)"
    )]
    poll_interval: Option<String>,
}

#[derive(Debug, Clone, Args)]
struct AuthLogin {
    #[arg(
        long,
        value_name = "GUID",
        help = "Application (client) id of the app registration [env: PURVIEW_CLIENT_ID]"
    )]
    client_id: Option<String>,
    #[arg(
        long,
        value_name = "GUID",
        help = "Directory (tenant) id [env: PURVIEW_TENANT_ID]"
    )]
    tenant_id: Option<String>,
    #[arg(
        long,
        help = "Ask for eDiscovery.Read.All instead of eDiscovery.ReadWrite.All; every write is \
then refused"
    )]
    read_only: bool,
    #[arg(
        long,
        help = "Sign in in the system browser on this computer instead of with a device code"
    )]
    browser: bool,
}

/// Defaults for flags, from the `PURVIEW_*` variables in `Env::vars`. The
/// boolean ones accept `true` or `false`, and an empty or unset variable
/// is `false`. The text ones are taken as given; an empty one is unset.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct FlagDefaults {
    json: bool,
    results_only: bool,
    plain: bool,
    no_input: bool,
    verbose: bool,
    wrap_untrusted: bool,
    select: Option<String>,
    account: Option<String>,
    timeout: Option<String>,
    trace_dir: Option<String>,
    client_id: Option<String>,
    tenant_id: Option<String>,
}

impl FlagDefaults {
    fn from_vars(vars: &BTreeMap<String, OsString>) -> std::result::Result<Self, String> {
        let flag = |name: &str| match vars.get(name) {
            None => Ok(false),
            Some(value) if value.is_empty() || value == "false" => Ok(false),
            Some(value) if value == "true" => Ok(true),
            Some(_) => Err(format!("{name} must be true or false")),
        };
        let text = |name: &str| match vars.get(name) {
            None => Ok(None),
            Some(value) => match value.to_str() {
                Some(text) if text.trim().is_empty() => Ok(None),
                Some(text) => Ok(Some(text.trim().to_owned())),
                None => Err(format!("{name} is not valid UTF-8")),
            },
        };
        Ok(Self {
            json: flag("PURVIEW_JSON")?,
            results_only: flag("PURVIEW_RESULTS_ONLY")?,
            plain: flag("PURVIEW_PLAIN")?,
            no_input: flag("PURVIEW_NO_INPUT")?,
            verbose: flag("PURVIEW_VERBOSE")?,
            wrap_untrusted: flag("PURVIEW_WRAP_UNTRUSTED")?,
            select: text("PURVIEW_SELECT")?,
            account: text("PURVIEW_ACCOUNT")?,
            timeout: text("PURVIEW_TIMEOUT")?,
            trace_dir: text("PURVIEW_TRACE_DIR")?,
            client_id: text("PURVIEW_CLIENT_ID")?,
            tenant_id: text("PURVIEW_TENANT_ID")?,
        })
    }
}

/// The global settings a command reads, after flags and their variables
/// are combined.
#[derive(Debug, Clone, Default)]
struct Globals {
    account: Option<String>,
    no_input: bool,
    verbose: bool,
    /// The per-request Graph timeout, already resolved (`0` is 60 s).
    timeout: Duration,
    trace_dir: Option<PathBuf>,
    client_id: Option<String>,
    tenant_id: Option<String>,
}

impl Globals {
    /// An explicit flag wins over its variable. An explicit flag that is
    /// blank is an error, never a fall back to the variable or the
    /// default: `--account "$unset"` must not act on the default account.
    fn new(cli: &Cli, defaults: &FlagDefaults) -> Result<Self> {
        Ok(Self {
            account: match cli.account.as_deref() {
                Some(value) => Some(explicit("--account", value)?),
                None => defaults.account.clone(),
            },
            no_input: cli.no_input || defaults.no_input,
            verbose: cli.verbose || defaults.verbose,
            timeout: match cli.timeout.as_deref() {
                Some(value) => graph_timeout("--timeout", &explicit("--timeout", value)?)?,
                None => match defaults.timeout.as_deref() {
                    Some(value) => graph_timeout("PURVIEW_TIMEOUT", value)?,
                    None => DEFAULT_TIMEOUT,
                },
            },
            trace_dir: match cli.trace.as_deref() {
                Some(dir) => Some(PathBuf::from(explicit(
                    "--trace",
                    dir.to_str().ok_or_else(|| {
                        PurviewError::message("--trace was given a path that is not UTF-8")
                    })?,
                )?)),
                None => defaults.trace_dir.as_deref().map(PathBuf::from),
            },
            client_id: defaults.client_id.clone(),
            tenant_id: defaults.tenant_id.clone(),
        })
    }
}

/// A per-request Graph timeout in whole seconds: `0` means the default of
/// 60, and at most `MAX_TIMEOUT_SECONDS`.
fn graph_timeout(name: &str, value: &str) -> Result<Duration> {
    match value.trim().parse::<u64>() {
        Ok(0) => Ok(DEFAULT_TIMEOUT),
        Ok(seconds) if seconds <= MAX_TIMEOUT_SECONDS => Ok(Duration::from_secs(seconds)),
        _ => Err(PurviewError::message(format!(
            "{name} must be a whole number of seconds from 0 to {MAX_TIMEOUT_SECONDS}"
        ))),
    }
}

/// The trimmed value of a flag given on the command line, refused when
/// blank.
fn explicit(flag: &str, value: &str) -> Result<String> {
    let value = value.trim();
    if value.is_empty() {
        return Err(PurviewError::message(format!(
            "{flag} was given an empty value; pass a value or leave the flag out"
        )));
    }
    Ok(value.to_owned())
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
            let json_mode = cli.json || defaults.json;
            let result = match (
                output_options(&cli, &defaults),
                Globals::new(&cli, &defaults),
            ) {
                (Ok(options), Ok(globals)) => run(&mut env, &options, &globals, cli.command).await,
                (Err(error), _) | (_, Err(error)) => Err(error),
            };
            match result {
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

fn output_options(cli: &Cli, defaults: &FlagDefaults) -> Result<OutputOptions> {
    let json = cli.json || defaults.json;
    let plain = cli.plain || defaults.plain;
    let select = match cli.select.as_deref() {
        Some(value) => explicit("--select", value)?,
        None => defaults.select.clone().unwrap_or_default(),
    };
    Ok(OutputOptions {
        format: if json {
            OutputFormat::Json
        } else if plain {
            OutputFormat::Plain
        } else {
            OutputFormat::Table
        },
        select,
        results_only: cli.results_only || defaults.results_only,
        wrap_untrusted: cli.wrap_untrusted || defaults.wrap_untrusted,
    })
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
        } else if matches!(
            error.kind(),
            ErrorKind::UnknownArgument | ErrorKind::InvalidSubcommand
        ) {
            // Clap names the word it did not expect, and repeats it in its
            // tip; the word could be part of a pasted value, such as the
            // second word of an unquoted query. Only Clap's usage context
            // is kept, which is built from the command, never the input.
            let usage = match error.get(clap::error::ContextKind::Usage) {
                Some(clap::error::ContextValue::StyledStr(usage)) => {
                    format!("\n\n{}", usage.to_string().trim_end())
                }
                _ => String::new(),
            };
            format!(
                "an argument that this command does not take (not repeated here); quote a \
                 value that holds spaces{usage}\n\nFor more information, try '--help'."
            )
        } else {
            let text = rendered.trim();
            text.strip_prefix("error: ").unwrap_or(text).to_owned()
        };
        // Clap quotes the value it refused, which could be a secret pasted
        // into the wrong place. That value is left out, and any other URL in
        // the message is redacted as in free text.
        let message = match error.get(clap::error::ContextKind::InvalidValue) {
            Some(clap::error::ContextValue::String(value)) if !value.is_empty() => {
                message.replace(&format!(" '{value}'"), "")
            }
            _ => message,
        };
        let message = crate::redact::urls_in_text(&message, &env.redactor);
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

async fn run(
    env: &mut Env,
    output: &OutputOptions,
    globals: &Globals,
    command: Command,
) -> Result<Outcome> {
    match command {
        Command::Auth(auth) => match auth.command {
            AuthCommand::Login(login) => auth_login(env, output, globals, login).await,
            AuthCommand::Refresh => auth_refresh(env, output, globals).await,
            AuthCommand::Status => auth_status(env, output, globals).await,
            AuthCommand::List => auth_list(env, output),
            AuthCommand::Logout => auth_logout(env, output, globals).await,
        },
        Command::Case(case) => {
            read_command(env, output, globals, ReadCommand::case(case.command)?).await
        }
        Command::Search(search) => {
            read_command(env, output, globals, ReadCommand::search(search.command)?).await
        }
        Command::Operation(operation) => {
            read_command(
                env,
                output,
                globals,
                ReadCommand::operation(operation.command)?,
            )
            .await
        }
        Command::Download(download) => {
            read_command(env, output, globals, ReadCommand::download(download)?).await
        }
        Command::Kql(query) => kql(env, output, query),
        Command::Version => version(env, output),
    }
}

/// `purview kql`: local. The query is built, and so checked as arguments,
/// before config.json is read.
fn kql(env: &mut Env, output: &OutputOptions, query: QueryArgs) -> Result<Outcome> {
    let kql = crate::kql::build::build(&query.flags())?;
    crate::output::selected_indices(&output.select, commands::kql::COLUMNS)?;
    let dir = configuration_dir(env)?;
    let stored = load_config(env, &dir)?;
    let guard = crate::kql::GuardConfig::from_config(&stored.extra)?;
    let produced = commands::kql::run(env, output, &kql, &guard)?;
    Ok(Outcome {
        exit_code: produced.exit_code,
        stdout_value: produced.document,
    })
}

/// A read command with its arguments checked, before any sign-in or
/// network call.
enum ReadCommand {
    CaseList(commands::case::ListFilters),
    CaseGet(CaseKey),
    SearchList(CaseKey),
    SearchGet(CaseKey, SearchKey),
    OperationList(CaseKey, commands::operation::ListFilters),
    OperationGet(CaseKey, OperationId, Option<commands::operation::Wait>),
    Download(commands::download::Request),
}

impl ReadCommand {
    /// The table columns of a list command, which `--select` must name.
    fn columns(&self) -> Option<&'static [&'static str]> {
        match self {
            Self::CaseList(_) => Some(commands::case::LIST_COLUMNS),
            Self::SearchList(_) => Some(commands::search::LIST_COLUMNS),
            Self::OperationList(..) => Some(commands::operation::LIST_COLUMNS),
            Self::Download(_) => Some(commands::download::COLUMNS),
            Self::CaseGet(_) | Self::SearchGet(..) | Self::OperationGet(..) => None,
        }
    }

    fn case(command: CaseCommand) -> Result<Self> {
        Ok(match command {
            CaseCommand::List(list) => Self::CaseList(commands::case::ListFilters {
                status: match list.status {
                    CaseStatusArg::Active => commands::case::StatusFilter::Active,
                    CaseStatusArg::Closing => commands::case::StatusFilter::Closing,
                    CaseStatusArg::Closed => commands::case::StatusFilter::Closed,
                    CaseStatusArg::All => commands::case::StatusFilter::All,
                },
                name: list
                    .name
                    .as_deref()
                    .map(|name| explicit("--name", name))
                    .transpose()?,
                created_before: list.created_before,
                created_after: list.created_after,
                mine: list.mine,
            }),
            CaseCommand::Get { case } => Self::CaseGet(CaseKey::parse(&case)?),
        })
    }

    fn search(command: SearchCommand) -> Result<Self> {
        Ok(match command {
            SearchCommand::List { case } => Self::SearchList(CaseKey::parse(&case)?),
            SearchCommand::Get { case, search } => {
                Self::SearchGet(CaseKey::parse(&case)?, SearchKey::parse(&search)?)
            }
        })
    }

    fn download(args: DownloadArgs) -> Result<Self> {
        Ok(Self::Download(commands::download::Request {
            case: CaseKey::parse(&args.case)?,
            operation: valid::operation_id(&args.operation)?,
            // Checked for blankness, then kept as given: a leading or
            // trailing space can be part of a file or directory name.
            out: args
                .out
                .map(|out| not_blank("--out", out).map(PathBuf::from))
                .transpose()?,
            file: args
                .file
                .map(|file| not_blank("--file", file))
                .transpose()?,
            overwrite: args.overwrite,
        }))
    }

    fn operation(command: OperationCommand) -> Result<Self> {
        Ok(match command {
            OperationCommand::List(list) => {
                let action = match list.action {
                    ActionArg::Any => commands::operation::ActionFilter::Any,
                    ActionArg::Estimate => commands::operation::ActionFilter::Estimate,
                    ActionArg::Report => commands::operation::ActionFilter::Report,
                    ActionArg::Export => commands::operation::ActionFilter::Export,
                };
                if action.needs_resolve() && !list.resolve {
                    return Err(PurviewError::ResolveRequired(
                        "--action report and --action export need --resolve: the operation list \
                         shows both item reports and exports as exportResult, so only a read of \
                         each operation tells them apart"
                            .to_owned(),
                    ));
                }
                Self::OperationList(
                    CaseKey::parse(&list.case)?,
                    commands::operation::ListFilters {
                        action,
                        status: list
                            .status
                            .as_deref()
                            .map(commands::operation::status_filter)
                            .transpose()?,
                        resolve: list.resolve,
                    },
                )
            }
            OperationCommand::Get(get) => {
                let case = CaseKey::parse(&get.case)?;
                let operation = valid::operation_id(&get.operation)?;
                let wait = if get.wait {
                    Some(commands::operation::Wait {
                        timing: poll::timing(
                            get.wait_timeout.as_deref(),
                            get.poll_interval.as_deref(),
                            poll::DEFAULT_WAIT_TIMEOUT,
                        )?,
                    })
                } else {
                    None
                };
                Self::OperationGet(case, operation, wait)
            }
        })
    }
}

/// Signs in, then runs a read command. A token that cannot be had is
/// reported as a broken sign-in, as in `auth status`.
async fn read_command(
    env: &mut Env,
    output: &OutputOptions,
    globals: &Globals,
    command: ReadCommand,
) -> Result<Outcome> {
    // Checked in every format, so that a typo fails the same way with or
    // without --json, before sign-in.
    if let Some(columns) = command.columns() {
        crate::output::selected_indices(&output.select, columns)?;
    }
    // The download settings in config.json are checked before sign-in.
    let download_setup = match &command {
        ReadCommand::Download(_) => Some(download_setup(env)?),
        _ => None,
    };
    let (account, credential) = signed_in(env, globals)?;
    let email = account.email.clone();
    let provider = Arc::new(token_provider(env, credential)?);
    let trace = open_trace(env, globals)?;
    let graph = Arc::new(graph_client(env, globals, provider.clone(), trace.clone())?);
    let download_context = match download_setup {
        Some((limits, data_root)) => Some(commands::download::Context {
            client: crate::download::DownloadClient::new(
                crate::download::DownloadSettings {
                    rule: env.download_rule.clone(),
                    resolve: env.download_resolve.clone(),
                    idle_timeout: env.download_idle_timeout,
                    verbose: globals.verbose,
                    trace,
                },
                provider,
                env.redactor.clone(),
                env.clock.clone(),
            )?,
            limits,
            data_root,
            faults: env.download_faults.clone(),
        }),
        None => None,
    };
    let mut session = Session {
        env,
        output,
        graph,
        account,
        verbose: globals.verbose,
    };
    let produced = match &command {
        ReadCommand::CaseList(filters) => commands::case::list(&mut session, filters).await,
        ReadCommand::CaseGet(key) => commands::case::get(&mut session, key).await,
        ReadCommand::SearchList(case) => commands::search::list(&mut session, case).await,
        ReadCommand::SearchGet(case, search) => {
            commands::search::get(&mut session, case, search).await
        }
        ReadCommand::OperationList(case, filters) => {
            commands::operation::list(&mut session, case, filters).await
        }
        ReadCommand::OperationGet(case, operation, wait) => {
            commands::operation::get(&mut session, case, operation, *wait).await
        }
        ReadCommand::Download(request) => match &download_context {
            Some(context) => commands::download::run(&mut session, request, context).await,
            None => Err(PurviewError::message("the download client was not set up")),
        },
    }
    .map_err(|error| {
        if error.is_token_unavailable() {
            error.context(format!(
                "getting a Graph token for {} (if the identity platform refused the refresh, \
                 sign in again with 'purview auth login')",
                sanitize(&email)
            ))
        } else {
            error
        }
    })?;
    Ok(Outcome {
        exit_code: produced.exit_code,
        stdout_value: produced.document,
    })
}

/// `value` unchanged, or the blank-value error `explicit` gives.
fn not_blank(flag: &str, value: String) -> Result<String> {
    explicit(flag, &value)?;
    Ok(value)
}

fn non_empty(value: Option<&str>) -> Option<&str> {
    value.map(str::trim).filter(|value| !value.is_empty())
}

fn configuration_dir(env: &Env) -> Result<PathBuf> {
    config::config_dir(env.config_dir.as_deref())
}

fn load_config(env: &mut Env, dir: &Path) -> Result<Config> {
    Config::load(dir, &mut env.stderr).map_err(|error| error.context("loading config.json"))
}

/// `auth login`: device-code or browser sign-in, then both tokens stored. Arguments
/// are checked, and `--no-input` refused, before any network call.
async fn auth_login(
    env: &mut Env,
    output: &OutputOptions,
    globals: &Globals,
    login: AuthLogin,
) -> Result<Outcome> {
    // An explicit flag is checked first, blank included, and only an
    // absent one falls back to its variable.
    let client_flag = match login.client_id.as_deref() {
        Some(value) => Some(auth::validate_client_id(&explicit("--client-id", value)?)?),
        None => globals
            .client_id
            .as_deref()
            .map(auth::validate_client_id)
            .transpose()?,
    };
    let tenant_flag = match login.tenant_id.as_deref() {
        Some(value) => Some(auth::validate_tenant_id(&explicit("--tenant-id", value)?)?),
        None => globals
            .tenant_id
            .as_deref()
            .map(auth::validate_tenant_id)
            .transpose()?,
    };
    if globals.no_input {
        return Err(PurviewError::message(
            "auth login is interactive (a person signs in in a browser) and --no-input was \
             given",
        ));
    }
    let dir = configuration_dir(env)?;
    let stored = load_config(env, &dir)?;
    let accounts = config::list_accounts(&dir, &mut env.stderr)?;
    let wanted = globals
        .account
        .as_deref()
        .map(|requested| wanted_account(&accounts, requested))
        .transpose()?;
    let registration = login_registration(
        client_flag.as_deref(),
        tenant_flag.as_deref(),
        &stored,
        wanted.as_ref().map(|wanted| wanted.key.as_str()),
    )?;
    let reused = registration
        .saved_with
        .as_deref()
        .map(|email| format!(", as saved with {}", sanitize(email)))
        .unwrap_or_default();
    writeln!(
        env.stderr,
        "Signing in through app registration {} in tenant {}{reused}",
        registration.client_id, registration.tenant_id
    )?;
    let identity = IdentityClient::new(
        env.identity_base.clone(),
        &registration.client_id,
        &registration.tenant_id,
        env.identity_timeout,
        env.redactor.clone(),
    )?;
    let outcome = if login.browser {
        auth::login_browser(
            &identity,
            env.clock.as_ref(),
            login.read_only,
            env.browser.clone(),
            env.browser_timeout,
            &mut env.stderr,
        )
        .await
    } else {
        auth::login_device_code(
            &identity,
            env.clock.as_ref(),
            login.read_only,
            &mut env.stderr,
        )
        .await
    }
    .map_err(|error| error.context("sign-in failed"))?;
    let record = outcome.record;
    if let Some(wanted) = &wanted {
        if !wanted.is(&record) {
            return Err(PurviewError::message(format!(
                "the browser signed in as {}, which is not the account --account names; \
                 nothing was stored. Sign in as that account in the browser, or leave --account \
                 out",
                sanitize(&record.email)
            )));
        }
    }
    store_login(env, &dir, &record, &outcome.credential, &registration).await?;
    let download_ready = outcome.credential.download.is_some();
    if let Some(refusal) = &outcome.download_refused {
        writeln!(
            env.stderr,
            "warning: no download token: the app has no consent for the Purview eDiscovery \
             permission eDiscovery.Download.Read ({}). Download commands will fail with \
             DownloadNotConsented until an administrator grants it and 'purview auth refresh' \
             succeeds",
            sanitize(&refusal.to_string())
        )?;
    }
    let graph_scope = outcome.credential.graph.scope.clone();
    if output.format == OutputFormat::Json {
        let result = json!({
            "account": record.email,
            "upn": record.upn,
            "tenantId": record.tenant_id,
            "clientId": record.client_id,
            "graphScope": graph_scope,
            "downloadReady": download_ready,
        });
        return Ok(Outcome::success(Some(output.json_value(&result, 1)?)));
    }
    let name = record
        .display_name
        .as_deref()
        .map(|name| format!("{} ", sanitize(name)))
        .unwrap_or_default();
    writeln!(
        env.stdout,
        "Signed in as {name}({})\nTenant: {}\nGraph scope: {}\nDownload token: {}",
        sanitize(&record.email),
        sanitize(&record.tenant_id),
        sanitize(&graph_scope),
        if download_ready {
            "stored"
        } else {
            "not issued"
        }
    )?;
    Ok(Outcome::success(None))
}

/// The account `--account` names for a sign-in. A stored account matches
/// by its key or recorded `upn`, as for every command; a name that matches
/// none is taken as the key of a signed-out account, whose saved
/// registration may still be reused.
#[derive(Debug)]
struct WantedAccount {
    requested: String,
    key: String,
    /// The stored account the name resolved to, if any.
    stored: Option<AccountRecord>,
}

impl WantedAccount {
    /// Whether the signed-in identity is the one asked for. A stored
    /// account is bound by its stable identifiers, the tenant and object
    /// ids recorded at its sign-in, because a name can match more than one
    /// identity (one account's `upn` can be another's address). A stored
    /// account recorded without them, and a name that matched no stored
    /// account, need the returned key or `upn` to be that name exactly.
    fn is(&self, record: &AccountRecord) -> bool {
        match &self.stored {
            Some(stored) if !stored.oid.is_empty() && !stored.tenant_id.is_empty() => {
                stored.oid.eq_ignore_ascii_case(&record.oid)
                    && stored.tenant_id.eq_ignore_ascii_case(&record.tenant_id)
            }
            Some(stored) => record.email.eq_ignore_ascii_case(&stored.email),
            None => record.matches(&self.requested),
        }
    }
}

fn wanted_account(accounts: &[AccountRecord], requested: &str) -> Result<WantedAccount> {
    let stored = match matching_accounts(accounts, requested)?.as_slice() {
        [only] => Some((*only).clone()),
        _ => None,
    };
    Ok(WantedAccount {
        requested: requested.to_owned(),
        key: stored.as_ref().map_or_else(
            || requested.to_ascii_lowercase(),
            |account| account.email.clone(),
        ),
        stored,
    })
}

/// The stored accounts `requested` names: the account whose key it is,
/// else the accounts whose recorded `upn` it is. Several are refused.
fn matching_accounts<'a>(
    accounts: &'a [AccountRecord],
    requested: &str,
) -> Result<Vec<&'a AccountRecord>> {
    let by_key: Vec<&AccountRecord> = accounts
        .iter()
        .filter(|account| account.email.eq_ignore_ascii_case(requested))
        .collect();
    let matches: Vec<&AccountRecord> = if by_key.is_empty() {
        accounts
            .iter()
            .filter(|account| account.matches(requested))
            .collect()
    } else {
        by_key
    };
    if matches.len() > 1 {
        return Err(PurviewError::message(format!(
            "--account matches several signed-in accounts ({}); pass the account's address",
            matches
                .iter()
                .map(|account| sanitize(&account.email))
                .collect::<Vec<_>>()
                .join(", ")
        )));
    }
    Ok(matches)
}

/// Stores a completed sign-in. The credential records the registration
/// that issued it, and every refresh uses that registration, so no order of
/// writes can pair tokens with the wrong app. The writes:
///
/// 1. The credential, replaced in place under its key. The old item is not
///    deleted first: on macOS that would discard its access list, and the
///    user would have to allow access again. If the store refuses the
///    write, the previous sign-in is left as it was. A failure the store
///    reports after the write took effect (a macOS label failure, a Windows
///    clean-up failure) may leave the new credential in place; on a first
///    sign-in everything under the key is then swept, and on a later one
///    the account file still names the previous sign-in, which refresh
///    checks against.
/// 2. `accounts/<email>.json`. If this fails on a first sign-in, the new
///    credential is removed again, so nothing is left that `auth list`
///    cannot show. On a later sign-in the old account file stays; if it
///    names another registration, `auth refresh` refuses and asks for a new
///    sign-in.
/// 3. `config.json`: the registration to offer at the next sign-in, and
///    the account as default when the default names no stored account. If
///    this fails, the account works, but a registration left in
///    `config.json` that differs makes `auth refresh` ask for a new
///    sign-in.
async fn store_login(
    env: &mut Env,
    dir: &Path,
    record: &AccountRecord,
    credential: &Credential,
    registration: &LoginRegistration,
) -> Result<()> {
    config::account_file_path(dir, &record.email)?;
    // Held from the ownership check to the last write or rollback, so a
    // concurrent sign-in under the same key cannot slip in between.
    let _lock = account_lock(env, &record.email).await?;
    let (first_sign_in, repair) = check_key_owner(env, dir, record)?;
    // The injected fault fires after the store has taken the write, as a
    // macOS label failure or a Windows clean-up failure does.
    let saved = if repair {
        credential.save_repairing(env.credentials.as_ref())
    } else {
        credential.save(env.credentials.as_ref())
    };
    if let Err(error) = saved.and_then(|()| fault(env, LoginWrite::Credential)) {
        return Err(credential_write_failed(
            env,
            &record.email,
            first_sign_in,
            error,
        ));
    }
    if let Err(error) = fault(env, LoginWrite::AccountFile)
        .and_then(|()| config::save_account(dir, record, &env.redactor))
    {
        if first_sign_in {
            return Err(remove_new_credential(
                env,
                &record.email,
                error.context("saving the account file"),
            ));
        }
        return Err(error.context(
            "saving the account file; the new tokens were stored, but the account file still \
             describes the previous sign-in. Run 'purview auth login' again",
        ));
    }
    // Read again, with the account list: the sign-in may have taken
    // minutes, and another command may have changed either.
    let mut stored = load_config(env, dir)?;
    let accounts = config::list_accounts(dir, &mut env.stderr)?;
    stored.set_client(
        &record.email,
        &registration.client_id,
        &registration.tenant_id,
    );
    let default_is_stored = accounts
        .iter()
        .any(|account| account.email.eq_ignore_ascii_case(&stored.default_account));
    if !default_is_stored {
        stored.default_account = record.email.clone();
    }
    fault(env, LoginWrite::Config)
        .and_then(|()| stored.save(dir, &env.redactor))
        .map_err(|error| {
            error.context(
                "saving config.json; the tokens and account file were stored, but config.json \
                 still names the previous registration or default. Run 'purview auth login' \
                 again",
            )
        })
}

/// Refuses to store a sign-in under a key that another identity owns, or
/// whose owner cannot be told. An address can be reassigned, or a rename
/// can land on a key another stored account holds; either way the key
/// keeps its owner until `auth logout` frees it. Each recorded id is
/// compared on its own:
///
/// - the account file at the exact key must be readable and record both
///   ids, each equal to the sign-in's; an unreadable, damaged or partly
///   recorded file counts as owned by someone else;
/// - a credential under the key that records an id different from the
///   sign-in's is someone else's;
/// - an unreadable credential, or one that records an id only partly,
///   counts as owned too, unless the account file matches this sign-in, in
///   which case the sign-in replaces (repairs) it.
///
/// Returns whether nothing at all is stored under the key (a first
/// sign-in), and whether the sign-in is authorised to repair a damaged
/// credential. The caller holds the account lock.
fn check_key_owner(env: &mut Env, dir: &Path, record: &AccountRecord) -> Result<(bool, bool)> {
    let same = |recorded: &str, signed_in: &str| {
        !recorded.trim().is_empty() && recorded.trim().eq_ignore_ascii_case(signed_in)
    };
    let file = config::read_account_file(dir, &record.email, &mut env.stderr);
    let (file_absent, file_matches) = match &file {
        Ok(None) => (true, false),
        Ok(Some(owner)) => (
            false,
            same(&owner.oid, &record.oid) && same(&owner.tenant_id, &record.tenant_id),
        ),
        Err(_) => (false, false),
    };
    let stored =
        Credential::stored_principal(env.credentials.as_ref(), &record.email, &env.redactor)?;
    let credential_ok = match &stored {
        StoredPrincipal::Absent => true,
        StoredPrincipal::Recorded { tid, oid } => {
            let differs = |recorded: &str, signed_in: &str| {
                !recorded.is_empty() && !recorded.eq_ignore_ascii_case(signed_in)
            };
            if differs(tid, &record.tenant_id) || differs(oid, &record.oid) {
                false
            } else if tid.is_empty() || oid.is_empty() {
                file_matches
            } else {
                true
            }
        }
        StoredPrincipal::Unreadable => file_matches,
    };
    if !(file_absent || file_matches) || !credential_ok {
        let key = sanitize(&record.email);
        return Err(PurviewError::message(format!(
            "the account key {key} belongs to another identity, or what is stored under it \
             cannot show whom it belongs to, so nothing was stored. If that address now belongs \
             to the identity that just signed in, run 'purview auth logout --account {key}' to \
             free the key, then sign in again"
        )));
    }
    let repair = file_matches && stored == StoredPrincipal::Unreadable;
    Ok((file_absent && stored == StoredPrincipal::Absent, repair))
}

/// After a credential write that reported a failure. The store may have
/// refused the write outright, or taken it and then failed (a macOS label
/// failure, a Windows clean-up failure). On a first sign-in, everything
/// under the key is swept, the primary entry and every chunk slot, whether
/// or not it can be read back; a sweep that fails is reported with the
/// logout command that finishes it.
fn credential_write_failed(
    env: &Env,
    email: &str,
    first_sign_in: bool,
    error: PurviewError,
) -> PurviewError {
    let error = error.context("storing the tokens");
    if !first_sign_in {
        return error.context(
            "the stored credential may or may not have been replaced; the account file still \
             describes the previous sign-in. Run 'purview auth login' again",
        );
    }
    remove_new_credential(env, email, error)
}

/// Sweeps what a failed first sign-in may have left under the key. If the
/// sweep fails, the error says how to finish it: `auth logout --account
/// <key>` removes whatever is under a key that has no account file.
fn remove_new_credential(env: &Env, email: &str, error: PurviewError) -> PurviewError {
    match delete_value(env.credentials.as_ref(), &token_key(email)) {
        Ok(()) => {
            error.context("nothing from this sign-in was kept; run 'purview auth login' again")
        }
        Err(removal) => {
            let key = sanitize(email);
            error.context(format!(
                "the new tokens may still be in the credential store, and removing them failed \
                 ({}); run 'purview auth logout --account {key}' to remove them",
                sanitize(&removal.to_string())
            ))
        }
    }
}

/// Takes the account lock for `email`, when `Env` has locks.
async fn account_lock(env: &Env, email: &str) -> Result<Option<CredentialLock>> {
    match &env.account_locks {
        Some(locks) => locks.lock(email).await.map(Some),
        None => Ok(None),
    }
}

/// The failure a test asked `Env` to inject at this write, if any.
fn fault(env: &Env, write: LoginWrite) -> Result<()> {
    if env.login_write_fault == Some(write) {
        return Err(PurviewError::message(format!(
            "injected failure at the {write:?} write"
        )));
    }
    Ok(())
}

/// Refuses a credential whose recorded app registration differs from the
/// one the account file or `config.json` names: a sign-in stopped part
/// way, and the account needs a new one.
fn check_registration(
    credential: &Credential,
    account: &AccountRecord,
    saved: Option<&ClientConfig>,
) -> Result<()> {
    let differs = |client_id: &str, tenant_id: &str| {
        (!client_id.trim().is_empty() && !client_id.eq_ignore_ascii_case(&credential.client_id))
            || (!tenant_id.trim().is_empty()
                && !tenant_id.eq_ignore_ascii_case(&credential.tenant_id))
    };
    let named_by = if differs(&account.client_id, &account.tenant_id) {
        Some("its account file")
    } else if saved.is_some_and(|client| differs(&client.client_id, &client.tenant_id)) {
        Some("config.json")
    } else {
        None
    };
    match named_by {
        Some(source) => Err(PurviewError::message(format!(
            "the tokens stored for {} were issued through another app registration than \
             {source} names, so an earlier sign-in did not finish; run 'purview auth login' \
             again",
            sanitize(&account.email)
        ))),
        None => Ok(()),
    }
}

#[derive(Debug, PartialEq)]
struct LoginRegistration {
    client_id: String,
    tenant_id: String,
    /// The stored account whose registration is reused, if any.
    saved_with: Option<String>,
}

/// The app registration to sign in through. `purview` ships with none, so
/// it comes from `--client-id` (or `PURVIEW_CLIENT_ID`) when given, and
/// otherwise from the registration saved at an earlier sign-in: the
/// `--account` named, else the default account, else the one registration
/// every saved account shares. The tenant follows the same order, with an
/// explicit tenant always winning. There is no `common` fallback: the app
/// is single-tenant.
fn login_registration(
    client_flag: Option<&str>,
    tenant_flag: Option<&str>,
    stored: &Config,
    account: Option<&str>,
) -> Result<LoginRegistration> {
    let missing_tenant = || {
        PurviewError::message(
            "no tenant id given and none is saved for this app registration; pass --tenant-id \
             <tenant-id> or set PURVIEW_TENANT_ID",
        )
    };
    if let Some(client_id) = client_flag {
        let tenant = match tenant_flag {
            Some(tenant) => tenant.to_owned(),
            None => auth::validate_tenant_id(
                &saved_tenant_for(stored, client_id, account)?.ok_or_else(missing_tenant)?,
            )
            .map_err(|error| error.context("the tenant saved for this app registration"))?,
        };
        return Ok(LoginRegistration {
            client_id: client_id.to_owned(),
            tenant_id: tenant,
            saved_with: None,
        });
    }
    let (email, client) = saved_registration(stored, account)?;
    let tenant = match tenant_flag {
        Some(tenant) => tenant.to_owned(),
        None => auth::validate_tenant_id(&client.tenant_id).map_err(|_| missing_tenant())?,
    };
    Ok(LoginRegistration {
        client_id: auth::validate_client_id(&client.client_id)
            .map_err(|error| error.context(format!("the registration saved with {email}")))?,
        tenant_id: tenant,
        saved_with: Some(email.to_owned()),
    })
}

/// The saved tenant for an explicitly given client id: the chosen or
/// default account's, when it used that app, else the one tenant every
/// account using that app shares. Several tenants are refused rather than
/// guessed.
fn saved_tenant_for(
    stored: &Config,
    client_id: &str,
    account: Option<&str>,
) -> Result<Option<String>> {
    let tenant_of = |client: &ClientConfig| {
        (client.client_id.eq_ignore_ascii_case(client_id))
            .then(|| non_empty(Some(&client.tenant_id)).map(str::to_owned))
            .flatten()
    };
    let preferred = non_empty(account).or(non_empty(Some(&stored.default_account)));
    if let Some(tenant) = preferred.and_then(|wanted| {
        stored
            .clients
            .iter()
            .find(|(email, _)| email.eq_ignore_ascii_case(wanted))
            .and_then(|(_, client)| tenant_of(client))
    }) {
        return Ok(Some(tenant));
    }
    let mut tenants: Vec<String> = stored.clients.values().filter_map(tenant_of).collect();
    tenants.sort_by_key(|tenant| tenant.to_ascii_lowercase());
    tenants.dedup_by(|left, right| left.eq_ignore_ascii_case(right));
    match tenants.as_slice() {
        [] => Ok(None),
        [only] => Ok(Some(only.clone())),
        _ => Err(PurviewError::message(format!(
            "app registration {client_id} is saved against several tenants ({}); pass \
             --tenant-id or --account",
            tenants
                .iter()
                .map(|tenant| sanitize(tenant))
                .collect::<Vec<_>>()
                .join(", ")
        ))),
    }
}

fn saved_registration<'a>(
    stored: &'a Config,
    account: Option<&str>,
) -> Result<(&'a str, &'a ClientConfig)> {
    let usable = |(email, client): (&'a String, &'a ClientConfig)| {
        (!client.client_id.trim().is_empty()).then_some((email.as_str(), client))
    };
    let lookup = |wanted: &str| {
        stored
            .clients
            .iter()
            .find(|(email, _)| email.eq_ignore_ascii_case(wanted))
            .and_then(usable)
    };
    if let Some(account) = non_empty(account) {
        return lookup(account).ok_or_else(|| {
            PurviewError::message(
                "no app registration is saved for the --account given; pass --client-id \
                 <application-client-id> and --tenant-id <tenant-id>",
            )
        });
    }
    if let Some(found) = non_empty(Some(&stored.default_account)).and_then(lookup) {
        return Ok(found);
    }
    let saved: Vec<_> = stored.clients.iter().filter_map(usable).collect();
    let first = saved.first().copied();
    let shared = first.filter(|(_, first)| {
        saved.iter().all(|(_, client)| {
            client.client_id.eq_ignore_ascii_case(&first.client_id)
                && client.tenant_id.eq_ignore_ascii_case(&first.tenant_id)
        })
    });
    shared.ok_or_else(|| {
        let reason = if saved.is_empty() {
            "no app registration given and none is saved from an earlier sign-in"
        } else {
            "no app registration given, and the saved accounts use different ones; choose with \
             --account"
        };
        PurviewError::message(format!(
            "{reason}; pass --client-id <application-client-id> and --tenant-id <tenant-id>, or \
             set PURVIEW_CLIENT_ID and PURVIEW_TENANT_ID"
        ))
    })
}

/// The one account a command acts as: `--account` (its key or recorded
/// `upn`, ignoring case), else the default account. There is no fallback
/// to another account (`docs/SPEC.md` section 4.2).
fn select_account(
    stored: &Config,
    accounts: &[AccountRecord],
    requested: Option<&str>,
) -> Result<AccountRecord> {
    if accounts.is_empty() {
        return Err(PurviewError::message(
            "no account is signed in; run 'purview auth login' first",
        ));
    }
    if let Some(requested) = non_empty(requested) {
        return match matching_accounts(accounts, requested)?.as_slice() {
            [only] => Ok((*only).clone()),
            _ => Err(PurviewError::message(
                "no signed-in account matches --account; 'purview auth list' shows the accounts",
            )),
        };
    }
    accounts
        .iter()
        .find(|account| account.email.eq_ignore_ascii_case(&stored.default_account))
        .cloned()
        .ok_or_else(|| {
            PurviewError::message(format!(
                "no default account is set; pass --account with one of: {}",
                accounts
                    .iter()
                    .map(|account| sanitize(&account.email))
                    .collect::<Vec<_>>()
                    .join(", ")
            ))
        })
}

/// The account a command acts as and its stored credential, checked
/// against the account file and `config.json` before anything is sent.
fn signed_in(env: &mut Env, globals: &Globals) -> Result<(AccountRecord, Credential)> {
    let dir = configuration_dir(env)?;
    let stored = load_config(env, &dir)?;
    let accounts = config::list_accounts(&dir, &mut env.stderr)?;
    let account = select_account(&stored, &accounts, globals.account.as_deref())?;
    let credential = Credential::load(env.credentials.as_ref(), &account.email, &env.redactor)?
        .ok_or_else(|| {
            PurviewError::message(format!(
                "no stored credential for {}; run 'purview auth login' again",
                sanitize(&account.email)
            ))
        })?;
    check_registration(&credential, &account, stored.client(&account.email))?;
    if !credential.belongs_to(&account.tenant_id, &account.oid) {
        let key = sanitize(&account.email);
        return Err(PurviewError::message(format!(
            "the tokens stored for {key} belong to another identity than its account file \
             records, so nothing was sent. Run 'purview auth logout --account {key}' to free the \
             key, then sign in again"
        )));
    }
    Ok((account, credential))
}

/// A token provider for `credential`, redeeming through the registration
/// it records.
fn token_provider(env: &Env, credential: Credential) -> Result<StoredTokenProvider> {
    Ok(StoredTokenProvider::new(
        &IdentityEndpoint {
            base: env.identity_base.clone(),
            request_timeout: env.identity_timeout,
        },
        env.credentials.clone(),
        env.redactor.clone(),
        env.clock.clone(),
        credential,
    )?
    .with_account_locks(env.account_locks.clone()))
}

/// The trace directory, opened when `--trace` was given, which prints its
/// warnings. The Graph and download clients share it.
fn open_trace(env: &mut Env, globals: &Globals) -> Result<Option<Arc<TraceSink>>> {
    Ok(match &globals.trace_dir {
        Some(dir) => Some(Arc::new(TraceSink::open(
            dir,
            env.redactor.clone(),
            env.clock.clone(),
            &mut env.stderr,
        )?)),
        None => None,
    })
}

/// The download limits and the data root from `config.json`
/// (`download.max_size`, `download.max_unknown_size`,
/// `defaults.data_dir`), else the defaults.
fn download_setup(env: &mut Env) -> Result<(crate::download::Limits, Option<PathBuf>)> {
    let dir = configuration_dir(env)?;
    let stored = load_config(env, &dir)?;
    let limits = crate::download::Limits::from_config(&stored.extra)?;
    // A missing object and `null` both mean unset, as in `download`.
    let defaults = match stored.extra.get("defaults") {
        None | Some(serde_json::Value::Null) => None,
        Some(serde_json::Value::Object(defaults)) => Some(defaults),
        Some(_) => {
            return Err(PurviewError::message(
                "config.json: defaults must be an object",
            ))
        }
    };
    let configured = match defaults.and_then(|defaults| defaults.get("data_dir")) {
        None | Some(serde_json::Value::Null) => None,
        Some(serde_json::Value::String(text)) if !text.trim().is_empty() => {
            Some(PathBuf::from(text))
        }
        Some(_) => {
            return Err(PurviewError::message(
                "config.json: defaults.data_dir must be a directory path or null",
            ))
        }
    };
    // The platform directory is looked up only when it is used, so --out
    // works where there is none.
    Ok((limits, configured.or_else(|| env.data_dir.clone())))
}

/// The Graph client for a command.
fn graph_client(
    env: &mut Env,
    globals: &Globals,
    tokens: Arc<dyn crate::token::TokenProvider>,
    trace: Option<Arc<TraceSink>>,
) -> Result<GraphClient> {
    GraphClient::new(
        GraphSettings {
            base: env.graph_base.clone(),
            timeout: globals.timeout,
            verbose: globals.verbose,
            trace,
        },
        tokens,
        env.redactor.clone(),
        env.clock.clone(),
    )
}

/// Writes the provider's notes under `--verbose`.
fn log_token_notes(env: &mut Env, globals: &Globals, provider: &StoredTokenProvider) {
    use crate::token::TokenProvider;
    for note in provider.take_notes() {
        if globals.verbose {
            let _ = writeln!(env.stderr, "[verbose] {}", sanitize(&note));
        }
    }
}

/// `auth refresh`: both resources, with the scopes already stored.
async fn auth_refresh(env: &mut Env, output: &OutputOptions, globals: &Globals) -> Result<Outcome> {
    let (account, credential) = signed_in(env, globals)?;
    let provider = token_provider(env, credential)?;
    let refreshed = provider.refresh_all().await;
    log_token_notes(env, globals, &provider);
    let credential = refreshed
        .map_err(|error| error.context(format!("refreshing {}", sanitize(&account.email))))?;
    let download_expires = credential
        .download
        .as_ref()
        .map(|token| token.expires_at_text());
    if output.format == OutputFormat::Json {
        let result = json!({
            "account": account.email,
            "graphExpiresAt": credential.graph.expires_at_text(),
            "downloadExpiresAt": download_expires,
            "graphScope": credential.graph.scope,
        });
        return Ok(Outcome::success(Some(output.json_value(&result, 1)?)));
    }
    writeln!(
        env.stdout,
        "Refreshed {}\nGraph token expires: {}\nDownload token expires: {}\nGraph scope: {}",
        sanitize(&account.email),
        credential.graph.expires_at_text(),
        download_expires.as_deref().unwrap_or("not issued"),
        sanitize(&credential.graph.scope)
    )?;
    Ok(Outcome::success(None))
}

/// `auth status`: one Graph read, `GET /security/cases/ediscoveryCases?$top=1`,
/// proves the Graph token and the Purview role (`docs/SPEC.md` section
/// 3.5). Graph answering is `ok`, a 403 is `denied`, and any other failure
/// of the read is `unknown`, each with exit 0. A Graph token that cannot be
/// had (a refused refresh, a store write that failed) is the command's
/// error: the sign-in itself is broken, and a script that checks only the
/// exit code must see that. The download token's expiry is read from the
/// stored credential; that token is never sent.
async fn auth_status(env: &mut Env, output: &OutputOptions, globals: &Globals) -> Result<Outcome> {
    let (account, credential) = signed_in(env, globals)?;
    let provider = Arc::new(token_provider(env, credential)?);
    let trace = open_trace(env, globals)?;
    let graph = graph_client(env, globals, provider.clone(), trace)?;
    let probe = graph
        .get_page(&ReadRoute::Cases, &Query::new().top(1), &mut env.stderr)
        .await;
    log_token_notes(env, globals, &provider);
    let (role, detail) = match probe {
        Ok(_) => ("ok", None),
        Err(error) if error.is_token_unavailable() => {
            return Err(error.context(format!(
                "getting a Graph token for {} (if the identity platform refused the refresh, \
                 sign in again with 'purview auth login')",
                sanitize(&account.email)
            )));
        }
        Err(error) if error.graph_status() == Some(403) => ("denied", Some(error.to_string())),
        Err(error) => ("unknown", Some(error.to_string())),
    };
    let credential = provider.credential().await;
    let download = credential.download.as_ref();
    if output.format == OutputFormat::Json {
        let result = json!({
            "account": account.email,
            "upn": account.upn,
            "tenantId": credential.tenant_id,
            "clientId": credential.client_id,
            "graphScope": credential.graph.scope,
            "graphExpiresAt": credential.graph.expires_at_text(),
            "downloadScope": download.map(|token| token.scope.clone()),
            "downloadExpiresAt": download.map(|token| token.expires_at_text()),
            "purviewRole": role,
            "purviewRoleDetail": detail,
        });
        return Ok(Outcome::success(Some(output.json_value(&result, 1)?)));
    }
    writeln!(
        env.stdout,
        "Account: {}\nTenant: {}\nGraph scope: {}\nGraph token expires: {}\nDownload scope: \
         {}\nDownload token expires: {}\nPurview role: {role}{}",
        sanitize(&account.email),
        sanitize(&credential.tenant_id),
        sanitize(&credential.graph.scope),
        credential.graph.expires_at_text(),
        download.map_or_else(|| "not issued".to_owned(), |token| sanitize(&token.scope)),
        download.map_or_else(
            || "not issued".to_owned(),
            |token| {
                if token.expires_at <= env.clock.now() {
                    format!(
                        "{} (expired; 'purview auth refresh' renews it)",
                        token.expires_at_text()
                    )
                } else {
                    token.expires_at_text()
                }
            }
        ),
        detail
            .map(|detail| format!(" ({})", sanitize(&detail)))
            .unwrap_or_default()
    )?;
    Ok(Outcome::success(None))
}

const ACCOUNT_COLUMNS: &[&str] = &["EMAIL", "NAME", "DEFAULT"];

/// `auth list`: the account files, with the default marked.
fn auth_list(env: &mut Env, output: &OutputOptions) -> Result<Outcome> {
    let dir = configuration_dir(env)?;
    let stored = load_config(env, &dir)?;
    let accounts = config::list_accounts(&dir, &mut env.stderr)?;
    if output.format == OutputFormat::Json {
        return Ok(Outcome::success(Some(
            output.json_value(&accounts, accounts.len())?,
        )));
    }
    let rows: Vec<Vec<String>> = accounts
        .iter()
        .map(|account| {
            vec![
                account.email.clone(),
                account.display_name.clone().unwrap_or_default(),
                if account.email.eq_ignore_ascii_case(&stored.default_account) {
                    "*".to_owned()
                } else {
                    String::new()
                },
            ]
        })
        .collect();
    write_rows(&mut env.stdout, output, ACCOUNT_COLUMNS, &rows)?;
    Ok(Outcome::success(None))
}

/// `auth logout`: removes the selected account's credential and account
/// file. The saved app registration stays, so signing in again needs no
/// flags. A signed-out default is replaced by the first remaining account.
async fn auth_logout(env: &mut Env, output: &OutputOptions, globals: &Globals) -> Result<Outcome> {
    let dir = configuration_dir(env)?;
    let stored = load_config(env, &dir)?;
    let accounts = config::list_accounts(&dir, &mut env.stderr)?;
    // An explicitly named key that exists as a file or a store entry is
    // that key, before any `upn` matching: the printed remedy for an
    // orphan names its exact key, which may be another account's `upn`.
    let exact = match globals.account.as_deref() {
        Some(requested) => {
            let key = requested.to_ascii_lowercase();
            let path = config::account_file_path(&dir, &key)?;
            // Inspected without following links: a link is refused here,
            // before anything is deleted.
            let file_exists = match std::fs::symlink_metadata(&path) {
                Ok(metadata) if metadata.file_type().is_symlink() => {
                    return Err(PurviewError::message(format!(
                        "the account file for {} is a link; refusing to sign it out",
                        sanitize(&key)
                    )));
                }
                Ok(_) => true,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
                Err(error) => return Err(error.into()),
            };
            let exists = file_exists || entry_exists(env.credentials.as_ref(), &token_key(&key))?;
            exists.then_some(key)
        }
        None => None,
    };
    let email = match exact {
        Some(key) => key,
        None => select_account(&stored, &accounts, globals.account.as_deref())?.email,
    };
    // Checked before the lock is taken and before anything is removed.
    config::account_file_path(&dir, &email)?;
    let _lock = account_lock(env, &email).await?;
    // Read again under the lock: another command may have changed either.
    let stored = load_config(env, &dir)?;
    let accounts = config::list_accounts(&dir, &mut env.stderr)?;
    delete_value(env.credentials.as_ref(), &token_key(&email)).map_err(|error| {
        error.context(format!("deleting the credential for {}", sanitize(&email)))
    })?;
    config::remove_account(&dir, &email)?;
    if stored.default_account.eq_ignore_ascii_case(&email) {
        let mut stored = stored;
        stored.default_account = accounts
            .iter()
            .map(|account| account.email.clone())
            .find(|other| !other.eq_ignore_ascii_case(&email))
            .unwrap_or_default();
        stored
            .save(&dir, &env.redactor)
            .map_err(|error| error.context("saving config.json"))?;
    }
    if output.format == OutputFormat::Json {
        let result = json!({"account": email, "signedOut": true});
        return Ok(Outcome::success(Some(output.json_value(&result, 1)?)));
    }
    writeln!(env.stdout, "Signed out {}", sanitize(&email))?;
    Ok(Outcome::success(None))
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
            message.starts_with("an argument that this command does not take"),
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
            Some("Error: an argument that this command does not take (not repeated here); quote a value that holds spaces"),
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
                // Clap's unexpected word is not repeated at all.
                assert!(message.contains("does not take"), "{message}");
            } else {
                assert!(stderr.contains("does not take"), "{stderr}");
            }
        }
    }

    /// The error printer redacts a secret that JSON escaping would hide
    /// from byte matching, in both forms. No argument error repeats a value
    /// any more, so the printer is driven directly.
    #[test]
    fn the_error_printer_redacts_escaped_secrets_in_both_forms() {
        let secret = "canary\"refresh\\0001";
        for json in [true, false] {
            let (mut env, captured) = Env::in_memory();
            env.redactor.register(secret);
            let error = PurviewError::message(format!("failed near {secret} here"));
            let outcome = Printer::default().fail(&mut env, json, &error);
            assert_eq!(outcome.exit_code, 1);
            env.stdout.finish().unwrap();
            env.stderr.finish().unwrap();
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
