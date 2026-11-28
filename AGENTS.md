# AGENTS.md

## Repository purpose

This repository builds `purview`, a Rust command-line interface (CLI) that
drives Microsoft Purview eDiscovery (Premium) through Microsoft Graph v1.0:
cases, tenant-wide mailbox searches, estimates, item reports and exports,
downloads, and offline parsing of the resulting zips.

`docs/SPEC.md` is the design and the phased plan. Each pull request
implements one item of its section 11 and nothing from later items. Today
the binary has `purview version`, `purview auth login` (device code, or
`--browser`), `auth refresh`, `auth status`, `auth list` and `auth logout`,
`case list`, `case get`, `case create`, `search list`, `search get`,
`case close`, `search create`, `estimate`, `report`, `export create`, `export read`,
`operation list` and
`operation get` (with
`--wait` and `--check`), `download`, `parse locations`, `parse failures`,
`parse summary`, `parse items`, `parse profile`, `kql`, and the global options `--verbose`, `--timeout`,
`--trace` and `--wrap-untrusted`. `case create`, `case close`, `search create`,
`estimate`, `report` and `export create` are the write commands so far; they
run through the safety
framework (`src/safety.rs`) with `--yes`, `--dry-run` and `--no-write`. Do not add
stubs for commands that a later pull request owns.

The tool never places, changes or releases a hold, never deletes or reopens a
case, and sends a Purview write only after a plan has been approved
(`docs/SPEC.md` section 6). Keep it that way unless a change introduces a
reviewed design.

## Public repository data rules

This is a public repository. Never log or commit access tokens, refresh
tokens, device codes, tenant ids, application (client) ids, organisation
names, domains, internal URLs, naming policies or real mailbox, case or
search data, in code, fixtures, docs, commit messages or issues.

- Use placeholders such as `<tenant-id>` and `<application-client-id>` in
  documentation.
- Tests use only synthetic data: `contoso.example` and `fabrikam.example`
  addresses, globally unique identifiers (GUIDs) of the form
  `00000000-0000-4000-8000-0000000000NN`, and operation ids such as
  `aaaaaaaa…0001`.
- Fixtures are written by hand from documented shapes. Recorded traces are
  never copied into fixtures, even redacted.
- Review history, private API notes and prototypes live outside the
  published tree. `docs/reviews/` must not exist in the working tree.

The public-data lint, `tests/fixture_lint.rs`, enforces these rules on
`tests/`, `docs/`, `contrib/`, `src/`, `.github/ISSUE_TEMPLATE/`,
`README.md`, `SKILL.md`, `AGENTS.md`, `CHANGELOG.md`, `CONTRIBUTING.md` and
`SECURITY.md`. It refuses GUIDs that are neither synthetic nor allowed
Microsoft constants, email addresses outside `*.example`, URLs whose
normalised host and path are not an allowed pair, absolute paths into a
home directory, files it cannot read as UTF-8 text, and `docs/reviews/`.
Each line is also checked percent-decoded and with JSON's `\/` undone. A
maintainer can add private terms or path fragments of their own through a
file outside the repository named by `PURVIEW_LINT_DENYLIST`, one term per
line. The report gives file, line, column and rule but never the matched
value, because CI logs are public; a deny-list finding gives the term's
line in that file, and a path containing a term is withheld. The lint runs
in `.github/workflows/public-data.yml` on every pull request and every push
to `main`, including changes to Markdown and `docs/` alone.

Test inputs that must fail the lint are joined from pieces at run time, so
that the test files pass their own scan.

## Python is for development only

The shipped binary is Rust only and never needs Python; a user of
`purview` is not expected to have it, so no feature may depend on a
Python script at run time. A contributor is expected to have a modern
Python environment with `uv`: development scripts (such as the `.msg`
cross-check against `extract-msg`, the fake `az` and the signing-helper
test) may use Python. A script that needs a third-party package runs
through `uv run` with it pinned; one on the standard library alone may
run with `python3`.

## Architecture

- `src/main.rs` is the tokio entry point. It calls `cli::execute`.
- `src/cli.rs` holds the Clap tree, dispatch and the top-level printer.
  `execute_with(Env, args) -> Outcome` runs a whole command in-process; it
  is `#[doc(hidden)]` and exists for tests. It checks a read command's
  arguments (`ReadCommand`) before sign-in, then signs in and hands the
  command a `commands::Session`. A write subcommand is checked into its
  `WriteCommand` (flags trimmed; blank text, or a control or invisible
  character, refused; the query built) and handed to `write_command`.
- `src/commands/` holds the bodies of the read commands: `case.rs`,
  `search.rs` and `operation.rs`, with key resolution in `mod.rs`.
  `case.rs` also holds `CaseClose`, the `WriteCommand` of `case close`:
  the case must be active and carry `naming.marker` (or have been created
  by the signed-in account) unless `--any-case`; its `custodians`,
  `noncustodialDataSources` and `legalHolds` are each read to the last
  page through paging links to that list alone, any entry refusing with
  `CaseHasHolds` and a failed read with `ClosePrecheckFailed` (a broken
  sign-in keeps `TokenUnavailable`), and read again, ownership included,
  after approval (`recheck`). The
  POST has no body (`WriteRoute::takes_body`), the plan asks for the case
  name typed (`WritePlan::with_typed_confirmation`), `--wait` polls the
  case through `Poller` until `closed`, and an unclear outcome reads the
  case once. `case.rs` also holds `CaseCreate` and `search.rs` `SearchCreate`, the
  `WriteCommand`s of `case create` and `search create`: each lists the
  cases or the case's searches to the last page and refuses a name in use
  (`CaseNameInUse` in any status, `SearchNameInUse`), lists the same again
  to name candidates after an unclear outcome, and warns when Graph's
  answer differs from what was observed (201, `status: active`, the echoed
  `contentQuery` and `dataSourceScopes`). `search create` runs
  `kql::enforce` in `check`, and refuses a case that is not active
  (`CaseNotActive`). A `--description` or rendered description always
  ends up holding `naming.marker`. A
  `<case>` or `<search>` that is an id is used as given, with no read; a
  name is matched exactly against the whole list, which must reach its
  last page. A command returns `Produced { exit_code, document }`, and
  `cli` prints the document. `commands/kql.rs` is `purview kql`, which is
  local: `cli` builds the query and reads `guard` from `config.json`, with
  no sign-in.
- `src/commands/action.rs` is the action preflight of `docs/SPEC.md`
  sections 6.4 and 6.7: `check_search` (the search by id or unique name,
  `dataSourceScopes` exactly `allTenantMailboxes` or `ScopeUnverified` /
  `ScopeNotAllowed`, the three source lists empty to their last page or
  `SearchHasSources` / `ScopeUnverified`, and the guard on its current
  query), `active_operations` (operations of an action not yet finished,
  which may be duplicates: `$expand=search` is refused, Observed) and
  `started_since` (reconciliation by `createdBy` and creation time), each
  over a list of actions (`EXPORT_ACTIONS` for reports and exports), and
  `ActionRun::after_send`, the run after an action's one POST: the 202
  and its `Location` header (`GraphClient::operation_in_location`, key or
  path form, `UnexpectedLocation` otherwise), the wait (`Poller` with a
  30-second not-found grace), the check that the operation is of the
  action sent, the download through `commands::download::fetch` and the
  collection check, with `Finished::finish` for `--strict`. An export
  downloads every part (`download::Keep::Every`); an estimate or item
  report never an items part (`Keep::NoItems`). `evidence_files` is the
  one rule for which files may be evidence, shared with `operation get
  --check`: action and detail must agree, an export's are its `Reports-`
  files, and no `Items.*.zip` part (`is_items_part`) ever is. A stopped
  action resumes with `operation get --wait --check`, or `--check` alone
  after Ctrl-C during the download, never `download`. `zipread::zip_end`
  reads a zip as ending at its end record, allowing up to
  `MAX_TRAILING_BYTES` after it (Observed on an items part), through
  `zipread::Bounded`.
  `commands/estimate.rs` is `estimate`: a plan that a duplicate blocks
  without `--allow-concurrent` (`safety::Blocked::Concurrent`,
  `ConcurrentOperation`), then `after_send` and the volume warning (`report::volume`, the `volume`
  limits of `config.json`, read only as far as a command's `volume_use()`
  is true); `--strict` adds `FailedLocations` or `EvidenceMissing`, never
  a volume reason. `commands/report.rs` is `report`: the same preflight
  over item reports and exports, then the size limit against the search's
  latest estimate (`ReadRoute::LastEstimate`, `latest_estimate`,
  `size_check`), which blocks the plan with `TooLarge` or
  `VolumeUnchecked` unless `--allow-large`; `defaults.teams_context`, read
  only by a command whose `reads_teams_context()` is true; the
  `ExportReportRequest` body; `after_send` with `EvidenceOf::Report`; and
  reconciliation that reads each candidate for its true action; and
  `--profile`, which reads `identity` and `defaults.top` before sign-in
  (`WriteCommand::profiles`, `safety::ProfileSettings`) and profiles the
  zip read as evidence (`Finished::evidence_path`), or exits 4 with
  `ProfileUnavailable`. The same
  file is `export create` (`Collect::Export`): the `ExportResultRequest`
  body (`exportFormat: msg`), the plan's export warnings, and every part
  downloaded, with only the `Reports-` part read.
  `commands/parse.rs` is `parse locations|failures|
  summary|items|profile`, local; `parse items` writes JSON Lines through
  `output::write_json_line`, which `export read` shares, and `parse
  profile` prints one document or a `SECTION`, `NAME`, `COUNT` table.
  `cli`'s `ItemFilterArgs` holds the filter flags both share. `operation get --check` downloads the evidence file and
  sets `collection`.
- `src/msg/` reads `.msg` items from memory, with no I/O: `cfbread.rs` is
  the Compound File Binary container through `cfb`, `props.rs` the MAPI
  properties of MS-OXMSG (`__substg1.0_<id><type>` streams and the fixed
  `__properties_version1.0`, whose header is 32 bytes for the message and
  8 for a recipient or attachment), and `body.rs` the body selection of
  `docs/SPEC.md` section 4.11 (`PidTagHtml` decoded with
  `PidTagInternetCodepage`, cleaned and converted with `html2text`, then
  `PidTagBody`, then `noBody`). `msg::parse_msg` is the entry point.
  `src/export/read.rs` is `export read`: local, a terminal stdout refused,
  each `.msg` of each items zip read in memory through `ZipReader` and
  written as one JSON Lines record (or one `--json` document), exit 4 when
  any item has an error.
- `src/zipread.rs` opens report zips under `ZipLimits` (entries, bytes per
  entry and in total, and a 1,000:1 ratio checked past 1 MiB, all counted
  on bytes read), refusing a name that fails `enclosed_name()` as
  `HostileZip`; nothing is extracted. `src/report/` reads the files:
  `csvread.rs` (flexible records, the byte-order mark, a per-record byte
  budget, `RecordTooLarge`), `estimate.rs` (Locations, Statistics errors,
  their union as failed locations, `Collection`), `summary.rs` (Summary
  groups split at blank lines outside quotes, known keys, Settings),
  `items.rs` (the `Items_N_*.csv` files in order of `N`, read a byte
  record at a time; the key by Internet message ID, Immutable ID or a
  SHA-256 of five fields; `Filters`; `Dedup`, with copies, interned
  distinct `Location ID`s and `TooManyUnique`; `is_thread_id` and
  `is_address_list`, the senders that name no person), `profile.rs` (the
  profile of section 4.8 over `Dedup`'s unique items: `Identity`, the
  `identity` section of `config.json` with one-step domain aliases,
  `top_setting` for `defaults.top`, sender normalisation, Teams items by
  the `IPM.SkypeTeams.` class prefix, and UTC buckets with ISO weeks), and
  `mod.rs`
  (`ReportFiles`, the zip's `Kind`, `ReportLimits` from `limits`).
- `src/kql/` is the guard of `docs/SPEC.md` section 6.3. `lexer.rs` lexes
  each restriction (`participants:…`, `subject:…`, `kind:…`, `sent>=…`)
  as one token with its value checked; `parser.rs` is the
  recursive-descent parser, with nesting bounded at 64; `classify.rs` holds
  the eight classification rules, the address pattern and
  `BUILT_IN_GENERIC`, which `docs/safety.md` and `docs/SPEC.md` reproduce
  between `built-in-generic-list` markers (a test compares the three);
  `guard.rs` holds `GuardConfig`, the verdict (`analyse`) and `enforce`,
  the entry point for write commands, whose `--allow-generic` needs a
  non-blank reason and never covers a parse error; `build.rs` turns the
  query flags into KQL that goes through the same parser. A refusal names
  a column and the construct, and quotes only ASCII punctuation, never a
  word or value from the query. A web address (`http://` or `https://`,
  as `redact::urls_in_text` detects one) is refused anywhere in a query,
  so `kql` never prints a URL and prints its JSON `kql` as given.
- `src/model/wire.rs` holds the wire records (`CaseRecord`,
  `SearchRecord`, `OperationRecord` and its typed details), each read field
  by field from the JSON so that no field is required and a field of the
  wrong type is `None`; each keeps the JSON it came from in `raw`.
  `src/model/valid.rs` holds the validated inputs (`CaseKey`, `SearchKey`,
  `CaseRef`, `SearchRef`, `PollTarget`). `src/model/requests.rs` holds the
  request bodies (`CreateCase`, `CreateSearch`); a search's
  `dataSourceScopes` is `AllTenantMailboxes`, which serialises only as
  `allTenantMailboxes`.
- `src/poll.rs` is the wait of `docs/SPEC.md` section 4.6, over any
  `Polled` record (an operation until it finishes, a case until it is
  closed): one
  deadline over reads, sleeps and retries (a read in flight is abandoned
  with tokio's timer), the interval schedule, a 404 grace only for a
  fresh submission, and Ctrl-C through `Env`'s `Interrupt`. A read that
  fails with no response, 429 or 5xx, including a `Retry-After` longer than
  `GraphClient` waits for, does not end the wait; the next read comes
  after the interval or the `Retry-After`, whichever is longer.
- `src/env.rs` defines `Env`: stdout and stderr (each through the
  Redactor), terminal detection, the configuration directory override
  (`PURVIEW_CONFIG_DIR`) and the `PURVIEW_*` variables that give flags their
  defaults. `Env::production()` captures those variables once; Clap never
  reads the process environment, so an in-process test does not depend on
  the shell that runs it. `Env::in_memory()` sets none. `Env` also carries
  the identity-platform base URL, the credential store and the clock:
  production uses `https://login.microsoftonline.com`, the operating-system
  keyring and the system clock; `Env::in_memory()` uses an unreachable
  `.example` host, an empty `MemoryStore` and a `ManualClock`, and tests
  point the base URL at a wiremock origin. It also carries the
  identity-platform request timeout and a test-only `login_write_fault`,
  always `None` in production, that makes one of `auth login`'s writes
  fail, and the per-account locks (`AccountLocks`) that serialise login,
  logout and refresh commits across processes; `Env::in_memory()` has none
  until a test sets them. It carries the `Interrupt` that ends an operation wait (tokio's Ctrl-C
  handler in production, a `ManualInterrupt` that tests fire in
  `Env::in_memory()`), the `Input` a write's `Apply? [y/N]` answer is read
  from (standard input in production, a `ScriptedInput` with no answers in
  `Env::in_memory()`), and the `BrowserOpener` that
`auth login --browser` uses (the system browser in production, `NoBrowser`
in `Env::in_memory()`, and the harness's `ScriptedBrowser`, which plays the
redirect against the loopback listener, in flows) and that sign-in's
timeout. It carries the Graph base URL (`origin::GRAPH_BASE` in production,
  an unreachable `.example` host in `Env::in_memory()`, and the harness's
  Graph mock in flows), whose origin is the only one Graph requests go to.
  It carries the download host rule (`DownloadRule::production()`
  everywhere but flows, which allow `http` and any port), the host names
  resolved to mock listeners for downloads (empty in production), the
  download idle timeout, the data directory root (`None` in production,
  for the platform's own; an unusable path in `Env::in_memory()`, so a test
  must set one) and the test-only `download_faults`, always off in
  production. `Env::production()` reads no
  environment variable that could change an endpoint, so the release binary
  has no test path that could send a token to another host.
- `src/auth.rs` holds the device-code flow, the browser flow (authorization
  code with PKCE on a `http://localhost:<port>/callback` listener bound on
  `127.0.0.1` and, when possible, `::1`; only an answer carrying the sign-in's
  `state` ends the wait), refresh-token redemption for
  Graph and for the Purview eDiscovery app (the download token), and the
  account claims from the id token. OAuth errors keep only the
  allow-listed fields of `docs/SPEC.md` section 6.8, redacted.
- `src/token.rs` defines `SecretString`, `GraphToken`, `DownloadToken`, the
  stored `Credential` (stamped with the app registration that issued it,
  which every refresh uses) and the `TokenProvider` trait. `StoredTokenProvider`
  refreshes lazily, shares one refresh per process behind a
  `tokio::sync::Mutex`, writes every refresh to the store before using it
  (a refused write is the command's error, and the provider reads the
  store again before its next redemption in case the write took effect),
  refuses a refresh that changes
  the Graph permission set, and registers every secret it sees with the
  Redactor.
- `src/secrets.rs` is the `CredentialStore` trait, `KeyringStore` (Windows
  chunking and lock, macOS label, Linux keyutils) and the in-memory
  `MemoryStore` tests use.
- `src/error.rs` defines `PurviewError` and `metadata()`, which gives the
  JSON error code and HTTP status.
- `src/output.rs` implements tables, `--plain` tab-separated values, the
  JSON envelopes and terminal sanitisation.
- `src/config.rs` reads and writes `config.json` atomically, refuses
  links (on Windows, any reparse point) at the configuration directory, the
  accounts directory and the file, keeps files at mode 0600 and directories
  at 0700 on Unix, keeps keys it does not read, and refuses to save a
  secret. On Windows it relies on the profile directory's default ACL. It
  also reads, lists and removes the `accounts/<email>.json` files with the
  same link and mode checks, and resolves the data directory for
  downloads.
- `src/redact.rs` defines the `Redactor`, `RedactingWriter` and
  `redact::url`, which keeps only the query values of `$top`, `$select`,
  `$filter`, `$expand`, `$skiptoken` and `downloadType`.
- `src/origin.rs` defines `Origin` (scheme, host, effective port; no
  origin for a URL with user information or a trailing-dot host) and
  `GRAPH_BASE`.
- `src/routes.rs` defines the id types, `ReadRoute` (every Graph read,
  each a `GET`), `WriteRoute` with `WriteRoute::ALL`, `Query` and
  `build_url`, which encodes each path segment on its own and refuses
  `.`, `..` and empty segments.
- `src/graph.rs` is `GraphClient`, the only Graph transport: `get`,
  `get_page`, `list` (paging) and `list_partial` (the pages read before
  one failed, with the failure, for reconciliation), the origin and base-path check on every
  request and paging link, the retry loop of `docs/SPEC.md` section 4.3
  (with `Retry-After` honoured up to 60 seconds; a longer one ends the read
  with Graph's error), the 8 MiB body limit and the Graph error allow-list.
  Every request method takes the command's stderr for `--verbose` lines.
  A token the provider cannot supply is `PurviewError::TokenUnavailable`,
  so a caller can tell a broken sign-in from Graph's answer. `send_write`
  takes a `safety::ApprovedWrite` and sends its one POST with the planned
  bytes, its token valid for five minutes, never again: a refused
  connection is `GraphUnreachable` (nothing sent), a 4xx is Graph's error,
  and no answer, a timeout, 429, a 5xx or an unreadable 2xx is
  `WriteOutcomeUnknown`. A write with no body sends `Content-Length: 0`
  and no `Content-Type` (Graph answers 411 without the length, Observed).
  The trace records the POST body.
- `src/safety.rs` is `WritePlan` (the body serialised once, the SHA-256 of
  method, path and body, effects, warnings, preflight), `decide` (dry run,
  `--yes`, the `Apply? [y/N]` prompt, or the typed name a plan asks for,
  through `Env`'s `Input`, exit 3 as
  `ConfirmationRequired` or `Declined`), `ApprovedWrite`, which only
  `approve` builds from an `Approval` only this module makes, and the
  `WriteCommand` trait (`check`, `plan`, `applied`, `reconcile`, which
  returns `Reconciled`: candidates by id, and notes). `check`
  gets the `WriteSettings` (`naming`, `guard` and the report limits from
  `config.json`); `plan` returns `Planned::Write(WritePlan)` or, when
  nothing needs to be sent, `Planned::Existing` (printed as `{"applied":
  false, "plan": null, "result", "reused": true}`). A plan may be
  `blocked`: a dry run prints it, any other run fails with
  `ConcurrentOperation` before anyone is asked. `plan` and `reconcile` get
  a `Preflight` (the Graph client, the signed-in account, shared, stderr
  and the clock), never `Env`, so a command cannot touch the terminal
  state, the approval input or the prompt. `applied` runs after the one
  send, when the approval is spent: it gets `After` (a `commands::Session`
  and, when `downloads()` says so, the download client) and returns
  `Applied::Result` (with exit-4 reasons, printed as the envelope's
  `outcome`) or `Applied::Produced` (its own document, such as the wait
  deadline's exit 5). `cli`'s `write_command` runs one: `--no-write`, the
  settings and `check` before sign-in, then the read-only check on the
  credential's `access`, then preflight, decision, send and output.
  `cli::execute_write_with` (`#[doc(hidden)]`) runs a `WriteCommand` with
  the global options, for the framework tests in `tests/writes.rs`.
- `src/naming.rs` parses and renders the `naming` templates of
  `config.json` (`docs/SPEC.md` section 5.5); an unknown variable is
  refused without being repeated.
- `src/download.rs` is `DownloadRule` (the host pattern of `docs/SPEC.md`
  section 4.7), `DownloadClient` (the download token and
  `X-AllowWithAADToken` only, same-origin redirects followed by hand, no
  decompression, streaming with SHA-256 under the size limits, reqwest's
  `read_timeout` as the idle timeout), and publishing: a `.part` file, the
  length and zip central-directory checks, then a hard link (or a rename
  under `--overwrite`). Never turn a `reqwest::Error` into an error with
  `?`: its message names the URL. `src/download/names.rs` makes local file
  names (section 4.7.1); `src/download/manifest.rs` is `manifest.json`.
  `src/commands/download.rs` holds the directory lock (`DirLock`) from
  reading the manifest to its last write, plans every file before any
  download request, recovers verified files that no manifest entry
  reaches, exits 4 when a file cannot be downloaded or the operation did
  not succeed, and 130 on Ctrl-C.
- `src/trace.rs` is `TraceSink` (`docs/SPEC.md` section 4.9). Only
  `GraphClient` and `DownloadClient` record, and a download's body never;
  token-endpoint exchanges are never traced.
- `build.rs` records the target triple for `purview version`. The release
  workflow sets `PURVIEW_BUILD_COMMIT`.
- `tests/cli.rs` holds offline process contracts (`assert_cmd`);
  `tests/flows.rs` runs whole commands in-process through `execute_with`
  against wiremock, with the harness and canary scanner in
  `tests/support/` and hand-written fixtures in `tests/fixtures/`;
  `tests/reads.rs` runs the read commands the same way, with the
  sign-in helpers it shares with `tests/flows.rs` in `tests/support/`;
  `tests/downloads.rs` runs `download` against mock download origins whose
  host names match the production pattern;
  `tests/kql.rs` runs `purview kql` in-process with no reachable host;
  `tests/items.rs` runs `parse items` the same way on zips it writes, with
  the 200,000-row timing test ignored by default; `tests/profiles.rs` runs
  `parse profile` the same way;
  `tests/graph.rs` drives `GraphClient`, and `Poller` over it, against
  wiremock with a fake token provider; `tests/writes.rs` runs a write
  command that exists only in the test through `execute_write_with`,
  recording every request to the mock Graph and identity platform;
  `tests/creates.rs` runs `case create` and `search create` through
  `execute_with` the same way (flows 1, 2 and 7 of `docs/SPEC.md`
  section 8.5); `tests/closes.rs` runs `case close` the same way (flow
  8); `tests/actions.rs` runs `estimate` and `operation get
  --check` against the mock Graph and a mock download origin (flows 3, 4
  and 5); `tests/reports.rs` runs `report` the same way, and
  `tests/exports.rs` `export create`; `tests/msgs.rs` runs the `.msg`
  reader and `export read` on items made by `tests/support/msggen.rs`;
  `tests/write_allow_list.rs` scans `src/` and `build.rs` for HTTP write
  methods, and allows a POST to be built only in `send_write` and the
  identity client; `tests/fixture_lint.rs` is the public-data lint.
- `contrib/resign.sh` gives local macOS builds a stable signing identity.
  `contrib/install.sh` tests, builds, signs and installs the per-user
  `~/.local/bin/purview`.
- `contrib/create-purview-app.sh` creates or updates the app registration,
  its service principals, assignments and consent grants under the
  contract in `docs/SPEC.md` section 5.2: a dry run by default, `--apply`
  to change anything, each change sent once and read back when its
  outcome is unclear. It must run under macOS's `/bin/bash` 3.2 and needs
  only `az`. Long `az` output goes to `awk`, `sed` and `grep` through
  here-strings, never a pipe into a reader that can stop early: under
  `pipefail` the writer's SIGPIPE would end the script without a message.
  `tests/scripts/create-purview-app-test.sh` runs it against the fake
  `az` in `tests/scripts/fake-bin/` (Python 3). The fake answers only the
  command words, options, queries and body fields the script sends, from
  a JSON state file. It refuses duplicates as Graph does and logs each
  call as one JSON array; any other call exits 99. `tests/scripts/azlog.py`
  reads that log for the harness. A change to a query or a body in the
  script needs the same change in the fake.
- `.github/workflows/release.yml` builds, signs, notarises, attests and
  publishes the release archives when a `v*` tag is pushed; the tag must
  equal `v` plus the `Cargo.toml` version. `.github/scripts/macos-signing.py`
  is its signing helper, and `docs/macos-signing.md` lists the GitHub
  settings it depends on. The Homebrew formula lives in the separate
  `aberoham/homebrew-tap` repository, which reads new releases by itself.

`docs/SPEC.md` section 4.1 lists the modules later pull requests add. Put new
code where that layout says.

Code copied from `aberoham/ms-entra-cli` (`output.rs`, the `config.rs` file
handling, `secrets.rs`, the device-code and token-endpoint parts of
`auth.rs`, `release.yml`, the signing helper and its test, and the two
`contrib/` scripts) is
maintained separately in each repository. When fixing a bug in copied code,
check whether the other repository needs the same fix.

## Command and output contracts

- Human output is the default. `--json` prints one document,
  `{"results": …, "count": …}`; `--results-only` prints `results` alone.
- A failure exits 1. Under `--json` it prints
  `{"error": {"code", "status", "message"}}` on stdout and nothing on
  stderr; otherwise `Error: …` goes to stderr and nothing to stdout.
- One exception: `auth login` writes its interactive sign-in text (the app
  registration line and the device-code prompt) to stderr in every mode,
  `--json` included, because the person signing in must see the code. Under
  `--json`, stdout still holds exactly one document, and a failure after
  the prompt still puts its error document on stdout.
- A second exception: `kql` with a query that is not narrowed (exit 1,
  `GenericQuery`) prints its report first, because the report is what the
  command is for. In a table the report goes to stdout and `Error: …` to
  stderr; under `--json` the one document is `{"analysis": …, "error": …}`,
  whatever `--results-only` says, so `error` is where every failure puts
  it. `KqlNotUnderstood` and every other failure follow the general rule.
  The write commands' guard refusals are plain errors.
- An explicit flag given a blank value (`--account ""`, `--client-id ""`,
  `--tenant-id ""`) is an error, raised before any fallback, configuration
  read or network call. An empty `PURVIEW_*` variable counts as unset.
- Argument errors, including Clap's and an invalid `PURVIEW_*` value, follow
  the same rule. Their code is `CommandFailed`; the human form is `Error: `
  and the message, then Clap's usage. `--json` before a `--`, or
  `PURVIEW_JSON=true`, asks for the JSON shape. `--help` exits 0 on stdout.
- If stdout cannot be written or flushed, the command exits 1 with
  `Error: could not write to standard output: …` on stderr, whatever it
  printed before. No second JSON document follows a partial one.
- `operation get` exits 4 when the operation finished without
  succeeding, 5 at the `--wait` deadline and 130 on Ctrl-C, in the shapes
  of `docs/SPEC.md` section 3.3; exit 4 prints the whole envelope even
  under `--results-only`. A write that is not approved exits 3 with
  `{"plan", "applied": false, "error"}`, whole even under `--results-only`;
  a write that ran, or a dry run, prints `{"results": {"applied", "plan",
  "result"}, "count": 1}`. The JSON Lines (JSONL) commands arrive with the
  pull requests that need them, as written in section 3.3.
- Every string from the tenant or a file goes through `sanitize` or
  `sanitize_multiline` before it reaches a terminal. JSON keeps the original
  value, apart from two changes. Every URL is redacted as in the trace (a
  string that is one URL keeps only its OData options; a URL in other text
  keeps only scheme, host and path; an object key holding a URL is
  redacted too, and two keys that become one keep both values, the second
  as `<key> (2)`), and `--wrap-untrusted` wraps every
  string under a key in `output::UNTRUSTED_KEYS`, at any depth. Human views
  put tenant text through `redact::shown` once, before it is sanitised or
  cut.
- A read command's JSON `results` is Graph's record as it came, with those
  changes. Keys the tool adds are ones Graph does not use on that record:
  `actionSource` on `operation list` entries, `collection` on `operation
  get`, and the three source lists that `search get` adds under Graph's
  navigation property names, replacing any list Graph sent inline, when
  the list reached its last page; otherwise the key is removed.
- Diagnostics never repeat an argument value (`--select`, `<op>`, a case or
  search name, `--account`, a `--client-id` or `--tenant-id` that is not a
  GUID, or the `PURVIEW_*` variable behind any of them) or tenant text: a
  pasted value could be a secret. They name the flag or variable instead. A
  stored account's own address, and an app registration that has passed the
  GUID check, may be shown; the sign-in notice prints the registration on
  purpose.
- Every sink writes through the Redactor: stdout and stderr through `Env`,
  and later trace files and the download manifest. Never write to
  `std::io::stdout()` or `std::io::stderr()`, or use `println!` and
  `eprintln!`, in command code. Pass `Env`'s writers instead.
- JSON is redacted as a value (`Redactor::redact_value`) before it is
  serialised, because escaping can hide a secret from byte-level matching.
  The serialised bytes are then checked; a match left outside string
  contents (a number, say) cannot be redacted without breaking the JSON,
  so the document is not printed and the command exits 1 with an error
  document, or with `Error: …` on stderr if that document matches too.
  `Outcome::stdout_value` is always the document actually printed. The
  writers redact the bytes again. `RedactingWriter::flush` keeps back
  any tail that could still become a match, and `finish` drains it;
  `execute_with` calls `finish` on both streams and checks the result.
- `config.json` never holds a secret: `Config::save` refuses to write a
  value the Redactor recognises.

## Transport guarantees

These rules apply to Graph and to downloads. Do not weaken them.

- Requests go only to an exact origin: scheme, host and effective port. The
  Graph origin is `https://graph.microsoft.com:443`, and Graph requests must
  also lie below `/v1.0/`. Paging links and polling URLs are checked
  against both too.
- Graph redirects are disabled. Downloads follow only same-origin redirects,
  at most 3, and refuse any other with `CrossOriginRedirect`.
- A GET makes at most 3 attempts, on the conditions in `docs/SPEC.md`
  section 4.3. A POST is never retried automatically, whatever the status;
  an unclear outcome runs the reconciliation and exits with
  `WriteOutcomeUnknown`.
- The download token goes only to the one download origin named by the
  operation; the Graph token never goes there.
- Tokens are never logged, printed or written to a file. The credential
  store is the only place a token persists.

## Write allow list

Every Purview write is a `WriteRoute` variant, and `WriteRoute::ALL` is the
six POSTs in `docs/SPEC.md` section 4.3: create case, close case, create
search, estimate statistics, export report and export result. They are sent
only by `GraphClient::send_write`, which takes an `ApprovedWrite`;
`case create`, `case close`, `search create`, `estimate`, `report` and
`export create` send create case, close case, create search, estimate
statistics, export report and export result. No
`PATCH`, `PUT` or `DELETE` may exist in the crate, in code, strings or
comments, and `tests/write_allow_list.rs` scans the source tree for them
and for calls that would choose a method at run time. Adding a write needs a
reviewed design, a change to that test and an update to `docs/safety.md`.
No route may add custodians, data sources or holds.

## Credential compatibility

Preserve these so that users do not have to sign in again after an upgrade:

- service name `purview`, key `purview:token:<email>`, macOS label
  `purview — <email>` and description `Microsoft Purview eDiscovery token`;
- the stored JSON shape with `"version": 1`, including the principal's
  `tid` and `oid` and the issuing `client_id` and `tenant_id`, and the
  optional `access` (`read-write` or `read-only`) that decides whether the
  account may write, and the optional `sign_in` id that ties refreshes to
  one sign-in; a credential without them reads as before
  (`docs/SPEC.md` section 5.1);
- the `config.json` and `accounts/<email>.json` shapes (section 5.3).

Tests use an in-memory credential store and synthetic records. They never
touch the real keyring, Microsoft Graph or the identity platform.

## Implementation conventions

- Validate arguments before sign-in or network work.
- Prefer `PurviewError` variants and typed predicates to parsing rendered
  messages. Machine errors keep a useful code and HTTP status.
- Keep asynchronous I/O under tokio.
- Use `wiremock` origins for HTTP behaviour, `execute_with` with an injected
  `Env` for in-process flows, and `assert_cmd` for offline process
  contracts.
- Each claim about the service in docs and comments carries its evidence
  label from `docs/SPEC.md` (Observed, Docs, Derived, Assumption).

## Review before every pull request

Before a pull request is opened, two independent reviewers read its diff
from `main`: Codex and agy (Gemini). The two reviews run in parallel.

- Fix every finding, then verify again with the commands below and a fresh
  review of the changed diff.
- Repeat until a pass finds no regression and no blocker an operator would
  hit in normal use.
- List any edge cases that remain as open items in the pull request body.
- The pull request body states that both reviews ran.

## Verification

Run these through rustup, so `rust-toolchain.toml` picks the same Rust
release CI uses; a Rust installed another way ignores that file. For ordinary
Rust changes, run:

```bash
cargo fmt --all -- --check
cargo check --all-targets
cargo clippy --all-targets -- -D warnings
cargo test --all-targets
cargo build --release
```

The public-data lint alone is `cargo test --test fixture_lint`. For workflow
changes, also run `actionlint` and `zizmor --offline .github/workflows`. For
shell changes, run `bash -n` and ShellCheck. For changes to
`contrib/create-purview-app.sh` or its fake, run
`tests/scripts/create-purview-app-test.sh`, and on macOS also
`TEST_BASH=/bin/bash tests/scripts/create-purview-app-test.sh`; name test
cases as arguments to run only those. `TEST_SCRIPT=<path>` runs the cases
against a copy of the script, which is how to check that a test fails when
the behaviour it covers is removed without editing the tracked file. For changes to the signing
helper, run `python3 .github/scripts/test_macos_signing.py`.
For changes to `src/msg/` or `export read`, run the cross-check against
`extract-msg` on an export you may read: `uv run
tests/scripts/msg-crosscheck.py <items.zip> <export-read.jsonl>`. It
prints counts only, never a value.

A passing suite does not show that the tenant behaves this way. Report live
checks separately, and update `docs/api-notes.md` with what they observed.

Before finishing, inspect `git diff --check` and the whole diff, and make
sure no credentials, tenant identifiers or real data entered tests, docs,
logs or commits.
