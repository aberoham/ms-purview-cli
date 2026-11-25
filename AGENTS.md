# AGENTS.md

## Repository purpose

This repository builds `purview`, a Rust command-line interface (CLI) that
drives Microsoft Purview eDiscovery (Premium) through Microsoft Graph v1.0:
cases, tenant-wide mailbox searches, estimates, item reports and exports,
downloads, and offline parsing of the resulting zips.

`docs/SPEC.md` is the design and the phased plan. Each pull request
implements one item of its section 11 and nothing from later items. Today
the binary has one command, `purview version`. Do not add stubs for commands
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
Microsoft constants, email addresses outside `*.example`, URLs outside the
allowed host and path pairs, absolute paths into a home directory, and
`docs/reviews/`. A maintainer can add private terms of their own through a
file outside the repository named by `PURVIEW_LINT_DENYLIST`, one term per
line; findings show the term's line number, never the term. The lint runs
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
  Redactor), terminal detection and the configuration directory override
  (`PURVIEW_CONFIG_DIR`). Later pull requests add the Graph origin, the token
  endpoint, the download host rule, the credential store and the clock.
  `Env::production()` reads no environment variable that could change an
  endpoint, so the release binary has no test path that could send a token
  to another host.
- `src/error.rs` defines `PurviewError` and `metadata()`, which gives the
  JSON error code and HTTP status.
- `src/output.rs` implements tables, `--plain` tab-separated values, the
  JSON envelopes and terminal sanitisation.
- `src/config.rs` reads and writes `config.json` atomically, refuses
  symlinks, and keeps files at mode 0600 and directories at 0700. It also
  resolves the data directory for downloads.
- `src/redact.rs` defines the `Redactor` and `RedactingWriter`.
- `build.rs` records the target triple for `purview version`. The release
  workflow sets `PURVIEW_BUILD_COMMIT`.
- `tests/cli.rs` holds offline process contracts (`assert_cmd`);
  `tests/fixture_lint.rs` is the public-data lint.

`docs/SPEC.md` section 4.1 lists the modules later pull requests add. Put new
code where that layout says.

Code copied from `aberoham/ms-entra-cli` (today `output.rs` and the
`config.rs` file handling; later `secrets.rs` and parts of `auth.rs`) is
maintained separately in each repository. When fixing a bug in copied code,
check whether the other repository needs the same fix.

## Command and output contracts

- Human output is the default. `--json` prints one document,
  `{"results": …, "count": …}`; `--results-only` prints `results` alone.
- A failure exits 1. Under `--json` it prints
  `{"error": {"code", "status", "message"}}` on stdout and nothing on
  stderr; otherwise `Error: …` goes to stderr and nothing to stdout.
- Argument errors that Clap raises follow the same rule. Their code is
  `CommandFailed`. `--json` before a `--`, or `PURVIEW_JSON=true`, asks for
  the JSON shape. `--help` exits 0 on stdout.
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

The crate sends no request today. From the transport pull request (1.3)
on, every Purview write is a `WriteRoute` variant, and `WriteRoute::ALL` is
the six POSTs in `docs/SPEC.md` section 4.3: create case, close case,
create search, estimate statistics, export report and export result. No
`PATCH`, `PUT` or `DELETE` may exist in the crate, and from that pull
request a test scans the source tree for them. Adding a write needs a
reviewed design, a change to that test and an update to `docs/safety.md`.
No route may add custodians, data sources or holds.

## Credential compatibility

Preserve these so that users do not have to sign in again after an upgrade:

- service name `purview`, key `purview:token:<email>`, macOS label
  `purview — <email>` and description `Microsoft Purview eDiscovery token`;
- the stored JSON shape with `"version": 1` (`docs/SPEC.md` section 5.1);
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

For ordinary Rust changes, run:

```bash
cargo fmt --all -- --check
cargo check --all-targets
cargo clippy --all-targets -- -D warnings
cargo test --all-targets
cargo build --release
```

The public-data lint alone is `cargo test --test fixture_lint`. For workflow
changes, also run `actionlint` and `zizmor --offline .github/workflows`. For
shell changes, run `bash -n` and ShellCheck.

A passing suite does not show that the tenant behaves this way. Report live
checks separately, and update `docs/api-notes.md` with what they observed.

Before finishing, inspect `git diff --check` and the whole diff, and make
sure no credentials, tenant identifiers or real data entered tests, docs,
logs or commits.
