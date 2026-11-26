# Changelog

## Unreleased

- Add `purview auth login --browser` using the authorisation code flow with Proof Key for Code Exchange (PKCE) on a loopback redirect (`http://localhost:<port>/callback`), opening the system browser with none of the command's output streams attached.
- Add `contrib/create-purview-app.sh` to create or update the tenant app registration, service principals, assignments and consent grants: dry run by default, `--apply` to make changes, each change sent once and read back on an unclear outcome, and reporting of existing consent grants broader than the plan.
- Add `docs/auth.md` covering permissions, app registration by script or by hand, consent choices, sign-in flows and token storage.
- Add the Microsoft Graph transport: requests only to the exact origin `https://graph.microsoft.com:443` and below `/v1.0/`, paging links checked the same way, redirects disabled, at most three attempts per read with `Retry-After` honoured up to 60 seconds, and one token refresh after a 401.
- Add `purview auth status`, which checks the Graph token and the Purview role with one read and reports `purviewRole` as `ok`, `denied` (HTTP 403) or `unknown`; a refresh the identity platform refuses is an error (exit 1).
- Add the global options `--verbose` (Graph requests and the token refreshes made for them or by `auth refresh`, on stderr through the redactor), `--timeout` (per-request Graph timeout, 0 to 600 seconds) and `--trace DIR` (one JSON file per Graph exchange, with no request headers, only allow-listed response headers and every URL's query values redacted except the OData options).
- Add `purview case list` (filters `--status`, `--name`, `--created-before`, `--created-after` and `--mine`) and `purview case get`. A `<case>` argument is a case id or an exact display name; several matches fail with `AmbiguousCase`, listing each match's id, status and creation date.
- Add `purview search list` and `purview search get`; `search get` also reads the search's custodian, non-custodial and additional sources.
- Add `purview operation list`, which marks entries the list cannot tell apart as `exportResult?` and refuses `--action report` and `--action export` without `--resolve` (`ResolveRequired`), and `purview operation get`, with `--wait`, `--wait-timeout` and `--poll-interval`. A finished operation that did not succeed exits 4 with an `outcome`; the wait deadline exits 5 (`WaitTimeout`) and Ctrl-C exits 130 (`Interrupted`), each with the command that resumes the wait.
- Add the global option `--wrap-untrusted` (`PURVIEW_WRAP_UNTRUSTED`), which wraps names, descriptions, external ids, queries and file names in JSON output in `[UNTRUSTED:<id>]` markers and adds an `untrustedNotice`.
- Add a test that fails if `PATCH`, `PUT` or `DELETE` appears anywhere in the crate's source.
- On macOS and Linux, create lock folders with mode 0700 and lock files with mode 0600, and refuse a linked lock folder; `v0.1.0-rc.1` created them with the default modes.

## v0.1.0-rc.1 - 2026-11-26

- Add the crate skeleton with `purview version`, global output flags (`--json`, `--results-only`, `--plain`, `--select`, `--account`, `--no-input`), terminal sanitisation, redaction across output sinks and the public-data lint (`tests/fixture_lint.rs`).
- Add credentials and device-code sign-in (`purview auth login`, `auth refresh`, `auth list`, `auth logout` and `--read-only`), storing tokens only in the operating system's credential store, redeeming one refresh token for both Microsoft Graph and the Purview download resource, and warning rather than failing at sign-in when the download permission has no consent.
- Serialise sign-in, sign-out and refresh commits for an account across processes with a per-account lock file.
- Add the release pipeline for macOS (Apple silicon and Intel, Developer ID signed and notarised), Linux (x86-64 and Arm64, statically linked) and Windows (x86-64), publishing a build provenance attestation and a checksum for every archive. The Homebrew formula, `aberoham/tap/purview`, lives in a separate tap repository that reads each release.
