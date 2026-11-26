# Troubleshooting

This page covers installing and checking the `purview` binary. Sections for
sign-in, searches and downloads arrive with the commands that need them.

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
gh attestation verify purview-<version>-<target>.tar.gz --repo aberoham/ms-purview-cli
```

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
