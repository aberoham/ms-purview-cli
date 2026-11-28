# purview

**Drive Microsoft Purview eDiscovery (Premium) through Microsoft Graph v1.0 from a terminal. It signs in, stores credentials, checks the Purview role, lists and shows cases, searches and operations, downloads an operation's files, and checks a search query against the guard against generic tenant-wide searches; write, export and parsing commands are planned.**

[![Latest release](https://img.shields.io/github/v/release/aberoham/ms-purview-cli)](https://github.com/aberoham/ms-purview-cli/releases)
[![CI](https://img.shields.io/github/actions/workflow/status/aberoham/ms-purview-cli/ci.yml?branch=main&label=CI)](https://github.com/aberoham/ms-purview-cli/actions/workflows/ci.yml)
[![Licence](https://img.shields.io/github/license/aberoham/ms-purview-cli)](LICENSE)

Status: `v0.1.0` (read-only). The binary implements authentication (`purview auth login`, with a device code or `--browser`, `auth refresh`, `auth status`, `auth list` and `auth logout`), the read commands for cases, searches and operations (`case list`, `case get`, `search list`, `search get`, `operation list`, `operation get`), `download`, `kql` and `version`, with global options `--json`, `--results-only`, `--plain`, `--select`, `--account`, `--no-input`, `--verbose`, `--timeout`, `--trace` and `--wrap-untrusted`. Write, export and parsing commands are planned in [docs/SPEC.md](docs/SPEC.md).

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

The read commands:

```bash
purview case list --status active --mine
purview search get "Records research - Orders review" <search>
purview operation list <case> --resolve --action report
purview operation get <case> <op> --wait --wait-timeout 30m
```

`purview kql` builds a query from the same flags that `search create` takes, or takes one with `--kql`, and shows whether the guard would allow it, with no sign-in:

```bash
purview kql --term orders-api --participant alex@contoso.example
```

The write commands show a plan and send it only when approved; `--dry-run` shows the plan and sends nothing:

```bash
purview case create --topic "Orders review" --dry-run
purview search create "Records research - Orders review 2026-11" \
  --name "orders-api-mail" --term orders-api --participant alex@contoso.example --dry-run
purview estimate <case> <search> --dry-run
purview parse failures <estimate-zip>
```

## Why it exists

Existing tools leave gaps across the eDiscovery workflow (recorded in [docs/SPEC.md](docs/SPEC.md) and [docs/api-notes.md](docs/api-notes.md)):

- **Purview portal:** supports every operation, but only by hand; per-location hit counts and failure details are inside the report zip files it returns (Observed).
- **Security & Compliance PowerShell:** creates and runs searches, but cannot download exports (Docs).
- **Azure CLI:** in live observations against a tenant, requesting a token for the Purview eDiscovery download application programming interface (API) failed with `AADSTS65002`, because first-party applications require pre-authorisation by the API owner (Observed).
- **Microsoft Graph Command Line Tools:** in live observations, this client obtained a Microsoft Graph token after consent, but received `AADSTS65001` for the download API, so it could search without being able to download (Observed).
- **A tenant-owned public-client app registration:** with no client secret, one refresh token was observed to obtain both the Microsoft Graph token and the Purview download token; `purview` is built on this flow (Observed).

## Status and roadmap

**Available in `v0.1.0` (2026-11-27):**

- `purview version`: show the version, commit and build target.
- `purview auth login`: sign in with a device code (pass `--client-id` and `--tenant-id` on first sign-in, saved for later; pass `--read-only` to request `eDiscovery.Read.All` instead of `eDiscovery.ReadWrite.All`).
- `purview auth refresh`: redeem the stored refresh token for both Microsoft Graph and the Purview download resource with the stored scopes.
- `purview auth list`: list stored accounts.
- `purview auth logout`: remove an account's stored tokens and account file.
- Global options: `--json`, `--results-only`, `--plain`, `--select`, `--account`, `--no-input`.
- `purview auth login --browser`: sign in in the system browser on the same computer using the authorisation code flow with Proof Key for Code Exchange (PKCE) on `http://localhost:<port>/callback`.
- `contrib/create-purview-app.sh`: Azure CLI setup script for the app registration.
- `docs/auth.md`: authentication, permissions and setup guide.
- `purview auth status`: check the Graph token and the Purview role with one read (`purviewRole: ok`, `denied` or `unknown`), showing both token expiries without sending the download token.
- The Microsoft Graph transport: requests only to `https://graph.microsoft.com/v1.0/`, redirects disabled, bounded retries for reads.
- Global options `--verbose`, `--timeout SECS` and `--trace DIR` (trace files hold tenant data; keep them out of version control).
- `purview case list` (filters `--status`, `--name`, `--created-before`, `--created-after`, `--mine`) and `purview case get`. A case is named by its id or its exact display name; names are not unique, and several matches fail with `AmbiguousCase`.
- `purview search list` and `purview search get`, which also reads the search's custodian, non-custodial and additional sources.
- `purview operation list` (filters `--action`, `--status`; `--resolve` reads each operation for its true action, because the list shows item reports and exports alike) and `purview operation get`, with `--wait`, `--wait-timeout` and `--poll-interval`. A finished operation that did not succeed exits 4 with the reasons; the wait deadline exits 5 and Ctrl-C exits 130, each with the command that resumes the wait.
- `purview download <case> <op>` (`--out`, `--file`, `--overwrite`): download an operation's files into the user data directory, each checked for its size and as a zip before it is published, and recorded with its SHA-256 in `manifest.json`; a recorded file that is unchanged is not fetched again unless `--overwrite` is given.
- `purview kql` (query flags `--term`, `--participant`, `--since`, `--until`, `--kind`, `--exclude-from`, or `--kql`): check a query against the guard against generic tenant-wide searches locally, showing each term's class and the rule that decided it; exits 1 with `GenericQuery` if some branch of the query is not narrowed by a specific term or a `participants:` restriction on a full address.
- Global option `--wrap-untrusted`: in JSON, wrap names, descriptions, queries and file names that tenant users wrote in `[UNTRUSTED:<id>]` markers.

**Unreleased, on `main`:**

- `purview case create --topic TEXT` (`--name`, `--requester`, `--description`, `--reuse-existing`): create a case named by the `naming.case_name` template; a name that any case has, in any status, is refused with `CaseNameInUse`.
- `purview search create <case> --name NAME [query flags]` (`--description`, `--allow-generic --reason TEXT`): create a search over every tenant mailbox in an active case, after the query guard; a name in use in the case is refused with `SearchNameInUse`.
- `purview estimate <case> <search>`: run a search's estimate after checking that it covers every tenant mailbox with no sources and that its query passes the guard, wait for it, download its report zip and report `collection` (`complete`, `incomplete` or `unchecked`) with the failed locations; `--strict` exits 4 when a location failed.
- The write commands show a plan and send one POST only when approved by `--yes` or at an `Apply? [y/N]` prompt; `--dry-run` sends nothing, and `--no-write` refuses them before sign-in.
- `purview report <case> <search>`: run a search's item report after the same checks and a size limit against its latest estimate, then download the zip and report `collection`.
- `purview export read <items.zip>`: read each message in an export's items zip on this computer (from and sender, recipients, subject, dates, attachment names and sizes, and the body, HTML first) as JSON Lines into a file; it refuses to write bodies to a terminal.
- `purview export create <case> <search>`: run a search's export as `.msg` files after the same checks and size limit, download every part into the data directory, and report `collection` from the report part; item content is never printed.
- `purview operation get --check`, and `purview parse locations`, `parse failures` and `parse summary` on a downloaded estimate or report zip, with no sign-in.

**Planned roadmap (not yet built, no dates):**

- **v0.2:** `case close`, if its live checks complete.
- **v0.3:** item report parsing (`parse items`, `parse profile`).
- **v0.4:** `export index`.
- **v0.5:** the rest of `export read` (the join to the report, quoted-reply cutting and thread de-duplication).
- **v0.6:** read-only inventory of old cases and holds.

## Safety

Design rules enforced in code by the write commands:

- **No holds:** `purview` never places, changes or releases a hold.
- **No destructive case changes:** `purview` never deletes or reopens a case.
- **Plan before every write:** a Purview write is sent only after its plan is shown and approved (`--dry-run` previews without writing; interactive runs prompt for confirmation, and non-interactive runs require `--yes`).

Protections active today:

- **Graph origin and redirects:** Microsoft Graph requests, paging links included, go only to `https://graph.microsoft.com:443` below `/v1.0/`, with redirects disabled. A test fails the build if `PATCH`, `PUT` or `DELETE` appears in the source.
- **Query guard (`purview kql`):** a query must be narrowed in every branch by a specific term or a `participants:` restriction on a full address; syntax outside a small Keyword Query Language (KQL) subset is refused. `search create` runs the same check before sign-in. See [docs/safety.md](docs/safety.md).
- **Download origin:** the download token goes only to the one `https` Purview download host on port 443 that each file names, never with the Graph token; a redirect to any other origin is refused without contacting it.

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

1. **Create the app registration.** With the Azure CLI (signed in as a Cloud Application Administrator, Application Administrator or higher), run `contrib/create-purview-app.sh`. Run the commands below from the root of a source checkout, or from `share/doc/purview` in an unpacked release archive (`cd share/doc/purview` first), where the script is `contrib/create-purview-app.sh` too. It performs a dry run by default and changes nothing until you pass `--apply`. The script grants `eDiscovery.ReadWrite.All` by default, and `auth login --read-only` alone does not narrow the registration's grant. For a read-only setup, add `READ_ONLY=1` to both the dry run and the `--apply` run (for example `READ_ONLY=1 TENANT_ID=<tenant-id> ASSIGN_USERS="alex@contoso.example" ./contrib/create-purview-app.sh`) and then sign in with the command the script prints at the end, which includes both identifiers and `--read-only`.

   ```bash
   az login --tenant <tenant-id>
   TENANT_ID=<tenant-id> ASSIGN_USERS="alex@contoso.example" ./contrib/create-purview-app.sh
   ```

   Review the printed plan, then run the same command with `--apply`. Manual setup steps, consent options and script variables are in [docs/auth.md](docs/auth.md).

2. **Assign the Purview role.** In the Microsoft Purview portal, add the account that will sign in to the **eDiscovery Manager** or **eDiscovery Administrator** subgroup of the eDiscovery Manager role group.

3. **Sign in:**

   ```bash
   purview auth login --client-id <application-client-id> --tenant-id <tenant-id>
   purview auth status   # checks the token and the Purview role
   ```

   Add `--browser` to sign in in the system browser on the same computer instead of with a device code, or `--read-only` to request `eDiscovery.Read.All`. Both identifiers are saved with the account for later sign-ins. Tokens are stored only in the operating system's credential store; `config.json` and account files contain no secrets.

## Documentation

- [docs/auth.md](docs/auth.md): permissions, the app registration (setup script and manual steps), consent choices and sign-in
- [docs/safety.md](docs/safety.md): the guard against generic tenant-wide searches: the supported query grammar, the term classifier and its settings
- [docs/troubleshooting.md](docs/troubleshooting.md): installing, verifying checksums and checking binary signatures; keychain prompts, sign-in, role and download errors
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
