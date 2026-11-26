# purview

**Drive Microsoft Purview eDiscovery (Premium) through Microsoft Graph v1.0 from a terminal. Today's binary signs in, stores credentials and checks the Purview role; case, search, download, export and parsing commands are planned.**

[![Latest release](https://img.shields.io/github/v/release/aberoham/ms-purview-cli?include_prereleases)](https://github.com/aberoham/ms-purview-cli/releases)
[![CI](https://img.shields.io/github/actions/workflow/status/aberoham/ms-purview-cli/ci.yml?branch=main&label=CI)](https://github.com/aberoham/ms-purview-cli/actions/workflows/ci.yml)
[![Licence](https://img.shields.io/github/license/aberoham/ms-purview-cli)](LICENSE)

Status: release candidate (`v0.1.0-rc.1`, published 2026-11-26). Today the binary implements `purview version` and authentication (`purview auth login`, `auth refresh`, `auth list` and `auth logout`), with global options `--json`, `--results-only`, `--plain`, `--select`, `--account` and `--no-input`. Browser sign-in (`auth login --browser`), `auth status`, the Microsoft Graph transport, the global options `--verbose`, `--timeout` and `--trace`, the app registration script and authentication documentation are on `main` since the release candidate. All case, search, download, export and parsing commands are planned in [docs/SPEC.md](docs/SPEC.md).

Sibling project of [ms-entra-cli](https://github.com/aberoham/ms-entra-cli), sharing output, configuration and credential-storage conventions.

## What it will do

`purview` is a command-line interface (CLI) for security, compliance and records staff holding the Purview eDiscovery Manager or eDiscovery Administrator role, and for artificial intelligence (AI) coding agents running under a skill file. Rules that an agent skill would otherwise state in prose are to be enforced in code by the write commands as they arrive.

Planned scope from [docs/SPEC.md](docs/SPEC.md):

- list, inspect, create and close eDiscovery cases;
- create searches over every mailbox in the tenant, covering email and Microsoft Teams chat and channel messages;
- run estimates, item reports and item exports, poll the resulting operations and download their files;
- turn report zip archives into summaries (hit counts per location, failed locations and a profile of unique items);
- join an item export to its report and stream message headers and body text from the zip archive;
- list old cases with their hold policies and ages, read-only.

None of the commands below exist in the current binary; each line is an independent example of the planned shape from [docs/SPEC.md](docs/SPEC.md), not a sequence:

```bash
# Independent examples of the planned shape (not yet implemented)
purview kql --term orders-api --participant alex@contoso.example
purview case create --topic "Orders review" --dry-run
purview search create "Records research - Orders review 2026-11" \
  --name "orders-api-mail" --term orders-api --participant alex@contoso.example --dry-run
purview estimate <existing-case> <existing-search> --strict
```

## Why it exists

Existing tools leave gaps across the eDiscovery workflow (recorded in [docs/SPEC.md](docs/SPEC.md) and [docs/api-notes.md](docs/api-notes.md)):

- **Purview portal:** supports every operation, but only by hand; per-location hit counts and failure details are inside the report zip files it returns (Observed).
- **Security & Compliance PowerShell:** creates and runs searches, but cannot download exports (Docs).
- **Azure CLI:** in live observations against a tenant, requesting a token for the Purview eDiscovery download application programming interface (API) failed with `AADSTS65002`, because first-party applications require pre-authorisation by the API owner (Observed).
- **Microsoft Graph Command Line Tools:** in live observations, this client obtained a Microsoft Graph token after consent, but received `AADSTS65001` for the download API, so it could search without being able to download (Observed).
- **A tenant-owned public-client app registration:** with no client secret, one refresh token was observed to obtain both the Microsoft Graph token and the Purview download token; `purview` is built on this flow (Observed).

## Status and roadmap

**Available in `v0.1.0-rc.1` (2026-11-26, pre-release):**

- `purview version`: show the version, commit and build target.
- `purview auth login`: sign in with a device code (pass `--client-id` and `--tenant-id` on first sign-in, saved for later; pass `--read-only` to request `eDiscovery.Read.All` instead of `eDiscovery.ReadWrite.All`).
- `purview auth refresh`: redeem the stored refresh token for both Microsoft Graph and the Purview download resource with the stored scopes.
- `purview auth list`: list stored accounts.
- `purview auth logout`: remove an account's stored tokens and account file.
- Global options: `--json`, `--results-only`, `--plain`, `--select`, `--account`, `--no-input`.

**On `main` since `v0.1.0-rc.1` (unreleased):**

- `purview auth login --browser`: sign in in the system browser on the same computer using the authorisation code flow with Proof Key for Code Exchange (PKCE) on `http://localhost:<port>/callback`.
- `contrib/create-purview-app.sh`: Azure CLI setup script for the app registration.
- `docs/auth.md`: authentication, permissions and setup guide.
- `purview auth status`: check the Graph token and the Purview role with one read (`purviewRole: ok`, `denied` or `unknown`), showing both token expiries without sending the download token.
- The Microsoft Graph transport: requests only to `https://graph.microsoft.com/v1.0/`, redirects disabled, bounded retries for reads.
- Global options `--verbose`, `--timeout SECS` and `--trace DIR` (trace files hold tenant data; keep them out of version control).

**Planned roadmap (not yet built, no dates):**

- **v0.1 (remaining items):** `case list`, `case get`, `search list`, `search get`, `operation list`, and `operation get` with `--wait`; `download`; the Keyword Query Language (KQL) guard and `purview kql`.
- **v0.2:** write commands (`case create`, `search create`, `estimate`, `report`, and `case close` if its live checks complete) with preflight checks and explicit approval, plus estimate report parsing (`parse locations`, `parse failures`, `parse summary`).
- **v0.3:** item report parsing (`parse items`, `parse profile`).
- **v0.4:** `export create` and `export index`.
- **v0.5:** reading message bodies from export zips (`export read`).
- **v0.6:** read-only inventory of old cases and holds.

## Safety

Design rules enforced in code as the download and write commands arrive:

- **No holds:** `purview` never places, changes or releases a hold.
- **No destructive case changes:** `purview` never deletes or reopens a case.
- **Plan before every write:** a Purview write is sent only after its plan is shown and approved (`--dry-run` previews without writing; interactive runs prompt for confirmation, and non-interactive runs require `--yes`).
- **Download origin:** the download token goes only to the one download origin named by each operation (from the download pull request onwards).

Protections active today:

- **Graph origin and redirects (on `main`):** Microsoft Graph requests, paging links included, go only to `https://graph.microsoft.com:443` below `/v1.0/`, with redirects disabled. A test fails the build if `PATCH`, `PUT` or `DELETE` appears in the source.

- **Credential storage:** tokens persist only in the operating system's credential store (macOS Keychain, Windows Credential Manager or Linux kernel keyring). `config.json` and account files hold no secrets.
- **Redaction:** everything the tool prints passes through a redactor that removes tokens it has seen; JavaScript Object Notation (JSON) is redacted as a value before serialisation, and `config.json` refuses to save a value the redactor recognises.
- **No tenant data in the repository:** a public-data lint (`tests/fixture_lint.rs`) runs in continuous integration (CI) on every pull request and every push to `main`. It refuses real-looking globally unique identifiers (GUIDs), email addresses outside `*.example`, unapproved URLs and home-directory paths across code, documentation and tests. Tests use synthetic `contoso.example` and `fabrikam.example` data only.

## Platforms

Release builds cover macOS (Apple silicon and Intel, Developer ID signed and notarised), Linux (x86-64 and Arm64, statically linked with musl) and Windows (x86-64). Every release smoke-tests each archive. The Windows binary is not code-signed.

## Install

### macOS and Linux (Homebrew)

```bash
brew install aberoham/tap/purview
```

The macOS binaries are signed with a Developer ID (`TeamIdentifier=2VLHJGU477`, identifier `com.aberoham.purview`) and notarised by Apple. See [troubleshooting](docs/troubleshooting.md#check-the-macos-signature).

### Windows

1. Download `purview-v<version>-x86_64-pc-windows-msvc.zip` and `checksums-sha256.txt`
   from the [releases page](https://github.com/aberoham/ms-purview-cli/releases).
2. Check the download against the published checksum. In PowerShell:

   ```powershell
   (Get-FileHash .\purview-v<version>-x86_64-pc-windows-msvc.zip -Algorithm SHA256).Hash.ToLower()
   Select-String x86_64-pc-windows-msvc .\checksums-sha256.txt
   ```

   The two hashes must be identical.
3. Extract the archive. It holds one folder, `purview-v<version>-x86_64-pc-windows-msvc`;
   copy `bin\purview.exe` from inside it to a folder on your `PATH`.
4. Run `purview --help`.

Microsoft Defender SmartScreen may warn on the first run. Select **More info**, then
**Run anyway**, once you have checked the hash.

### Other platforms, or from source

Release archives for macOS (Apple silicon and Intel), Linux (x86-64 and Arm64, statically linked) and Windows are on the [releases page](https://github.com/aberoham/ms-purview-cli/releases). Each archive contains `bin/purview` on macOS and Linux (or `bin\purview.exe` on Windows) and the documentation under `share/doc/purview/`. Gatekeeper accepts a browser-downloaded macOS copy after an online check the first time it runs. Check the archive against `checksums-sha256.txt`.

Every release archive also carries a build provenance attestation, which shows that this repository's release workflow built it from the tagged commit. With the GitHub CLI (for Unix archives; Windows archives end in `.zip`):

```bash
TAG="v<version>"   # replace <version> with the release you downloaded
gh attestation verify "purview-${TAG}-<target>.tar.gz" --repo aberoham/ms-purview-cli \
  --signer-workflow aberoham/ms-purview-cli/.github/workflows/release.yml \
  --source-ref "refs/tags/$TAG"
```

`--signer-workflow` requires the release workflow as the signer, and `--source-ref` requires the build to come from that tag.

To build from source you need Rust 1.100 or later. Under rustup, `rust-toolchain.toml` selects the release CI uses:

```bash
cargo build --release --locked
./target/release/purview --help
```

On macOS, `cargo build` produces an ad-hoc-signed binary, whose identity changes with every build. `./contrib/install.sh` runs the tests, builds, signs the binary with your own stable local certificate, and installs it as `~/.local/bin/purview`. See [troubleshooting](docs/troubleshooting.md#a-source-build-on-macos).

## Set up

`purview` has no app registration of its own. Create a single-tenant public-client registration in your Microsoft Entra ID tenant before signing in.

1. **Create the app registration.** With the Azure CLI (signed in as a Cloud Application Administrator, Application Administrator or higher), run `contrib/create-purview-app.sh` from a checkout of `main`. It performs a dry run by default and changes nothing until you pass `--apply`. The script grants `eDiscovery.ReadWrite.All` by default, and `auth login --read-only` alone does not narrow the registration's grant. For a read-only setup, add `READ_ONLY=1` to both the dry run and the `--apply` run (for example `READ_ONLY=1 TENANT_ID=<tenant-id> ASSIGN_USERS="alex@contoso.example" ./contrib/create-purview-app.sh`) and then sign in with the command the script prints at the end, which includes both identifiers and `--read-only`.

   ```bash
   az login --tenant <tenant-id>
   TENANT_ID=<tenant-id> ASSIGN_USERS="alex@contoso.example" ./contrib/create-purview-app.sh
   ```

   Review the printed plan, then run the same command with `--apply`. Manual setup steps, consent options and script variables are in [docs/auth.md](docs/auth.md).

2. **Assign the Purview role.** In the Microsoft Purview portal, add the account that will sign in to the **eDiscovery Manager** or **eDiscovery Administrator** subgroup of the eDiscovery Manager role group.

3. **Sign in:**

   ```bash
   purview auth login --client-id <application-client-id> --tenant-id <tenant-id>
   purview auth status   # on main: checks the token and the Purview role
   ```

   Add `--browser` (available on `main`) to sign in in the system browser on the same computer instead of with a device code, or `--read-only` to request `eDiscovery.Read.All`. Both identifiers are saved with the account for later sign-ins. Tokens are stored only in the operating system's credential store; `config.json` and account files contain no secrets.

## Documentation

- [docs/auth.md](docs/auth.md): permissions, the app registration (setup script and manual steps), consent choices and sign-in
- [docs/troubleshooting.md](docs/troubleshooting.md): installing, verifying checksums and checking binary signatures
- [docs/macos-signing.md](docs/macos-signing.md): how macOS releases are signed and notarised
- [docs/api-notes.md](docs/api-notes.md): observed Microsoft Graph and Purview service behaviour
- [docs/SPEC.md](docs/SPEC.md): design, safety model and phased implementation plan
- [AGENTS.md](https://github.com/aberoham/ms-purview-cli/blob/main/AGENTS.md): repository rules, contracts and verification steps for contributors and AI agents
- [CHANGELOG.md](https://github.com/aberoham/ms-purview-cli/blob/main/CHANGELOG.md): release history and unreleased changes

## Contributing

See [CONTRIBUTING.md](https://github.com/aberoham/ms-purview-cli/blob/main/CONTRIBUTING.md) for pull request scope, public-data rules and verification commands.

## Security

Report vulnerabilities privately; see [SECURITY.md](https://github.com/aberoham/ms-purview-cli/blob/main/SECURITY.md).

## Licence

MIT. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
