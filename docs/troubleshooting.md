# Troubleshooting

This page covers installing and checking the `purview` binary, then signing
in, reading cases and downloading files. Entries for the write commands
(`ScopeUnverified`, `WriteOutcomeUnknown`, closing a case) arrive with them in
v0.2; they are listed at the end so that a search for the code finds this
page.

## Which binary is running

```bash
command -v purview
purview version
```

`purview version` prints the version, the commit and the build target, for
example `purview 0.1.0 <commit> aarch64-apple-darwin`. A release build reports
the commit it was built from. A build from source reports `unknown`, because
only the release workflow records the commit.

If the version is not the one you installed, an older copy earlier on `PATH`
is running. Remove it, or put the Homebrew or `~/.local/bin` directory first.

## Check a downloaded archive

Every release publishes `checksums-sha256.txt` next to the archives. On macOS
or Linux:

```bash
shasum -a 256 -c checksums-sha256.txt --ignore-missing
```

Every archive also carries a build provenance attestation, which shows that
this repository's release workflow built it from the tagged commit. With the
GitHub CLI:

```bash
TAG=v<version>
gh attestation verify "purview-${TAG}-<target>.tar.gz" --repo aberoham/ms-purview-cli \
  --signer-workflow aberoham/ms-purview-cli/.github/workflows/release.yml \
  --source-ref "refs/tags/$TAG"
```

`--signer-workflow` requires the release workflow as the signer, and
`--source-ref` requires the build to come from that tag.

The README's Windows install steps show the same checksum check in
PowerShell.

## Check the macOS signature

Release binaries for macOS are Developer ID signed with the identifier
`com.aberoham.purview` and notarized by Apple:

```bash
b="$(realpath "$(command -v purview)")"
codesign --verify --strict --verbose=2 "$b"
codesign -dv "$b" 2>&1 | grep -E '^(Identifier|TeamIdentifier)='
codesign --verify --strict --check-notarization "$b"
```

A release shows `Identifier=com.aberoham.purview` and
`TeamIdentifier=2VLHJGU477`. The notarization check needs network access.

A copy downloaded with a browser carries the quarantine flag. Gatekeeper
then checks Apple's notarization ticket online the first time it runs,
because a bare binary cannot carry a stapled ticket. Without network access
that first run fails; run it again once the network is back. Homebrew
installs are not quarantined.

**Do not run `contrib/resign.sh` on a release binary.** It replaces the
Developer ID signature with a local one. The script refuses unless
`PURVIEW_RESIGN_RELEASE=1` is set.

## A source build on macOS

`cargo build` produces an ad-hoc-signed binary whose identity changes with
every build, so macOS treats each rebuild as a different program.
`contrib/resign.sh` signs it with a stable local certificate; the comment at
the top of the script explains how to create one in Keychain Access. It looks
for a certificate named `purview-cli-signer`, `entra-cli-signer` or
`teams-cli-signer`, or the name in `SIGN_IDENTITY`. The installer runs the
tests, builds, signs and installs `~/.local/bin/purview` in one step:

```bash
./contrib/install.sh
```

A source build and a release have different signing identities, so macOS
treats them as different programs.

## Windows SmartScreen warning

The Windows binary is not code-signed. Microsoft Defender SmartScreen may warn
on the first run. Check the archive against `checksums-sha256.txt` first, then
select **More info** and **Run anyway**.

## Linux

The Linux archives hold a statically linked binary with no shared library
dependencies, so it runs on any distribution for its architecture. An
`Exec format error` means the archive is for the other architecture: use
`x86_64-unknown-linux-musl` on x86-64 and `aarch64-unknown-linux-musl` on
Arm64.

## Keychain or credential-store prompts after an upgrade

macOS asks for the keychain password, or to allow access, when a program it
does not recognise reads the `purview` keychain item. The release binaries
are signed with one stable identity, `com.aberoham.purview`, so an upgrade
from one release to the next reads the stored credential without a prompt.
A prompt after an upgrade means the binary changed identity:

- a source build replaced a release, or the other way round. They have
  different signing identities. Choose **Always Allow** once, or sign the
  source build with `contrib/resign.sh` (see "A source build on macOS");
- a release binary was re-signed locally. Do not re-sign release binaries.

Windows Credential Manager and the Linux kernel keyring do not prompt per
program. If the stored credential cannot be read at all, sign in again with
`purview auth login`.

## The device code is refused by Conditional Access

A tenant can block the device code flow with a Conditional Access policy
for authentication flows (Docs). The sign-in page then refuses the code
after you enter it, and `auth login` fails with the identity platform's
error. Sign in in the browser on the same computer instead:

```bash
purview auth login --browser
```

The browser flow needs a browser on the computer that runs `purview`,
because the sign-in returns to a loopback address. Over a remote shell,
ask the tenant administrator whether the policy can exclude the app
registration.

## 403 without the Purview role

`purview auth status` reports `purviewRole: denied` when Graph answers its
case read with HTTP 403. The likely cause is that the account holds no
eDiscovery role: it needs the eDiscovery Manager or eDiscovery
Administrator subgroup of the eDiscovery Manager role group, assigned in the
Microsoft Purview portal (Docs). That a missing role gives 403 has not been
observed yet (Assumption).

`purviewRole: unknown` means the read failed another way, such as a network
error or a Graph outage; `purview auth status --verbose` logs the
request on stderr.

## 401 or 403 on a download

`purview download` sends the download token, not the Graph token, to the
Purview download host. Two errors mean the token is missing or refused:

- **`DownloadNotConsented`**: the account has no download token, because the
  app has no consent for `eDiscovery.Download.Read` on the Purview eDiscovery
  app. Grant the consent (see `docs/auth.md`, "`AADSTS65001` and
  `AADSTS65002`"), then run `purview auth refresh`.
- **`DownloadRefused`** with status 401 or 403: the download service refused
  the token. Run `purview auth refresh` and try again. If it is refused
  again, check that the consent above exists and that the account holds an
  eDiscovery role. A Graph token sent to the download host is answered with
  401 (Observed), so a tool or script that uses a Graph token there fails
  the same way.

A file that cannot be downloaded does not stop the others: the command
writes the rest, then exits 4 with `FileNotDownloadable` for that file.
Running the same command again fetches only what is still missing.

## `CrossOriginRedirect` on a download

The download service answered with a redirect to another origin (scheme,
host or port). `purview` follows redirects only within the origin that the
operation named, so it refused the redirect without contacting the other
host, and the download token never left that origin. No redirect has been
observed on a download (Observed); one to another origin means the service
changed or something between you and it rewrote the answer, such as a
proxy. The error names only the other origin. Report it with that origin
and the output of `purview --verbose download <case> <op>`, which shows the
redacted request addresses.

## An operation that succeeded but missed some locations

An estimate or report can end with status `succeeded` and still have
failed to search some mailboxes. The operation's status alone does not
show this; the per-location results are in the report files. In v0.1,
download the operation's files with `purview download <case> <op>` and read
the locations report in the zip. From v0.2, `purview parse failures` lists
them and `--strict` turns them into exit 4.

`purview operation get` exits 4 when the operation itself did not succeed
(`partiallySucceeded`, `failed` or `submissionFailed`), with the reasons.

## A case in `closing` status

`purview case list --status closing` shows cases the service is still
closing. One observed close went from `active` to `closed` within seconds
without showing `closing` (Observed), and some cases were seen in `closing`
for longer (Observed); why is not known. v0.1 does not close cases, so it
only reads this status. `purview case close` arrives in v0.2, and waits for
the case to reach `closed`.

## Write commands (v0.2)

These errors come from the write commands, which arrive in v0.2. Their
entries will be written with those commands:

- **`ScopeUnverified`**: an action on an existing search was refused because
  the search's read did not show that it covers every tenant mailbox.
- **`WriteOutcomeUnknown`**: a write was sent but its outcome is not known,
  for example because the connection dropped; the command lists what to
  check before trying again, because writes are never retried
  automatically.
