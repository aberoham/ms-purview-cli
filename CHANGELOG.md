# Changelog

## Unreleased

- Add `purview auth login --browser` using the authorisation code flow with Proof Key for Code Exchange (PKCE) on a loopback redirect (`http://localhost:<port>/callback`), opening the system browser with none of the command's output streams attached.
- Add `contrib/create-purview-app.sh` to create or update the tenant app registration, service principals, assignments and consent grants: dry run by default, `--apply` to make changes, each change sent once and read back on an unclear outcome, and reporting of existing consent grants broader than the plan.
- Add `docs/auth.md` covering permissions, app registration by script or by hand, consent choices, sign-in flows and token storage.
- On macOS and Linux, create lock folders with mode 0700 and lock files with mode 0600, and refuse a linked lock folder; `v0.1.0-rc.1` created them with the default modes.

## v0.1.0-rc.1 - 2026-11-26

- Add the crate skeleton with `purview version`, global output flags (`--json`, `--results-only`, `--plain`, `--select`, `--account`, `--no-input`), terminal sanitisation, redaction across output sinks and the public-data lint (`tests/fixture_lint.rs`).
- Add credentials and device-code sign-in (`purview auth login`, `auth refresh`, `auth list`, `auth logout` and `--read-only`), storing tokens only in the operating system's credential store, redeeming one refresh token for both Microsoft Graph and the Purview download resource, and warning rather than failing at sign-in when the download permission has no consent.
- Serialise sign-in, sign-out and refresh commits for an account across processes with a per-account lock file.
- Add the release pipeline for macOS (Apple silicon and Intel, Developer ID signed and notarised), Linux (x86-64 and Arm64, statically linked) and Windows (x86-64), publishing a build provenance attestation and a checksum for every archive. The Homebrew formula, `aberoham/tap/purview`, lives in a separate tap repository that reads each release.
