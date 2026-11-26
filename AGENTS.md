# AGENTS.md

## Repository purpose

This repository builds `purview`, a Rust command-line interface (CLI) that
drives Microsoft Purview eDiscovery (Premium) through Microsoft Graph v1.0:
cases, tenant-wide mailbox searches, estimates, item reports and exports,
downloads, and offline parsing of the resulting zips.

`docs/SPEC.md` is the design and the phased plan. Each pull request
implements one item of its section 11 and nothing from later items. Today
the binary has `purview version` and the device-code `purview auth login`,
`auth refresh`, `auth list` and `auth logout`. Do not add stubs for commands
that a later pull request owns.

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
`tests/`, `docs/`, `contrib/`, `src/`, `README.md`, `SKILL.md`, `AGENTS.md`
and `CHANGELOG.md`. It refuses GUIDs that are neither synthetic nor allowed
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

## Architecture

- `src/main.rs` is the tokio entry point. It calls `cli::execute`.
- `src/cli.rs` holds the Clap tree, dispatch and the top-level printer.
  `execute_with(Env, args) -> Outcome` runs a whole command in-process; it
  is `#[doc(hidden)]` and exists for tests.
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
  fail. Later pull requests add the Graph
  origin and the download host rule. `Env::production()` reads no
  environment variable that could change an endpoint, so the release binary
  has no test path that could send a token to another host.
- `src/auth.rs` holds the device-code flow, refresh-token redemption for
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
- `src/redact.rs` defines the `Redactor` and `RedactingWriter`.
- `build.rs` records the target triple for `purview version`. The release
  workflow sets `PURVIEW_BUILD_COMMIT`.
- `tests/cli.rs` holds offline process contracts (`assert_cmd`);
  `tests/flows.rs` runs whole commands in-process through `execute_with`
  against wiremock, with the harness and canary scanner in
  `tests/support/` and hand-written fixtures in `tests/fixtures/`;
  `tests/fixture_lint.rs` is the public-data lint.
- `contrib/resign.sh` gives local macOS builds a stable signing identity.
  `contrib/install.sh` tests, builds, signs and installs the per-user
  `~/.local/bin/purview`.
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
- Exit codes 3, 4, 5 and 130, the write-plan shapes and the JSON Lines
  (JSONL) commands arrive with the pull requests that need them. Their
  shapes are fixed in `docs/SPEC.md` section 3.3; implement them as written
  there.
- Every string from the tenant or a file goes through `sanitize` or
  `sanitize_multiline` before it reaches a terminal. JSON keeps the original
  value.
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

These apply from the pull requests that add the Graph and download clients.
Do not weaken them.

- Requests go only to an exact origin: scheme, host and effective port. The
  Graph origin is `https://graph.microsoft.com:443`. Paging links and polling
  URLs are checked against it too.
- Graph redirects are disabled. Downloads follow only same-origin redirects,
  at most 3, and refuse any other with `CrossOriginRedirect`.
- A GET is retried at most 3 times, on the conditions in `docs/SPEC.md`
  section 4.3. A POST is never retried automatically, whatever the status;
  an unclear outcome runs the reconciliation and exits with
  `WriteOutcomeUnknown`.
- The download token goes only to the one download origin named by the
  operation; the Graph token never goes there.
- Tokens are never logged, printed or written to a file. The credential
  store is the only place a token persists.

## Write allow list

The crate sends no Graph request today, only identity-platform requests.
From the transport pull request (1.3) on, every Purview write is a
`WriteRoute` variant, and `WriteRoute::ALL` is the six POSTs in
`docs/SPEC.md` section 4.3: create case, close case, create search,
estimate statistics, export report and export result. No
`PATCH`, `PUT` or `DELETE` may exist in the crate, and from that pull
request a test scans the source tree for them. Adding a write needs a
reviewed design, a change to that test and an update to `docs/safety.md`.
No route may add custodians, data sources or holds.

## Credential compatibility

Preserve these so that users do not have to sign in again after an upgrade:

- service name `purview`, key `purview:token:<email>`, macOS label
  `purview — <email>` and description `Microsoft Purview eDiscovery token`;
- the stored JSON shape with `"version": 1`, including the issuing
  `client_id` and `tenant_id` (`docs/SPEC.md` section 5.1);
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
shell changes, run `bash -n` and ShellCheck. For changes to the signing
helper, run `python3 .github/scripts/test_macos_signing.py`.

A passing suite does not show that the tenant behaves this way. Report live
checks separately, and update `docs/api-notes.md` with what they observed.

Before finishing, inspect `git diff --check` and the whole diff, and make
sure no credentials, tenant identifiers or real data entered tests, docs,
logs or commits.
