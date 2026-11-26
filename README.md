# purview

**Search every mailbox and Teams chat in a Microsoft 365 tenant with Microsoft Purview
eDiscovery from the terminal: create cases and searches, run estimates, item reports and
exports, download and read the results, and close cases.**

Status: early development. The binary signs in with a device code (`purview auth login`,
`auth refresh`, `auth list`, `auth logout`) and prints its version; nothing is released
yet, and the install steps below apply from the first release. The design and phased plan
are in [docs/SPEC.md](docs/SPEC.md).

Sibling of [ms-entra-cli](https://github.com/aberoham/ms-entra-cli).

## Platforms

Release builds cover macOS (Apple silicon and Intel, Developer ID signed and notarized),
Linux (x86-64 and Arm64, statically linked) and Windows (x86-64). Every release
smoke-tests each archive. The Windows binary is not code-signed.

## Install

### macOS and Linux (Homebrew)

```bash
brew install aberoham/tap/purview
```

The macOS binaries are signed with a Developer ID (`TeamIdentifier=2VLHJGU477`,
identifier `com.aberoham.purview`) and notarized by Apple. See
[troubleshooting](docs/troubleshooting.md#check-the-macos-signature).

### Windows

1. Download `purview-<version>-x86_64-pc-windows-msvc.zip` and `checksums-sha256.txt`
   from the [latest release](https://github.com/aberoham/ms-purview-cli/releases/latest).
2. Check the download against the published checksum. In PowerShell:

   ```powershell
   (Get-FileHash .\purview-<version>-x86_64-pc-windows-msvc.zip -Algorithm SHA256).Hash.ToLower()
   Select-String x86_64-pc-windows-msvc .\checksums-sha256.txt
   ```

   The two hashes must be identical.
3. Extract the archive. It holds one folder, `purview-<version>-x86_64-pc-windows-msvc`;
   copy `bin\purview.exe` from inside it to a folder on your `PATH`.
4. Run `purview --help`.

Microsoft Defender SmartScreen may warn on the first run. Select **More info**, then
**Run anyway**, once you have checked the hash.

### Other platforms, or from source

Release archives for macOS (Apple silicon and Intel), Linux (x86-64 and Arm64, statically
linked) and Windows are on the
[releases page](https://github.com/aberoham/ms-purview-cli/releases). Each archive
contains `bin/purview` and the documentation under `share/doc/purview/`. Gatekeeper
accepts a browser-downloaded macOS copy after an online check the first time it runs.
Check the archive against `checksums-sha256.txt`.

Every release archive also carries a build provenance attestation, which shows that this
repository's release workflow built it from the tagged commit. With the GitHub CLI:

```bash
TAG=v<version>
gh attestation verify "purview-${TAG}-<target>.tar.gz" --repo aberoham/ms-purview-cli \
  --signer-workflow aberoham/ms-purview-cli/.github/workflows/release.yml \
  --source-ref "refs/tags/$TAG"
```

`--signer-workflow` requires the release workflow as the signer, and
`--source-ref` requires the build to come from that tag.

To build from source you need Rust 1.100 or later. Under rustup, `rust-toolchain.toml`
selects the release CI uses:

```bash
cargo build --release --locked
./target/release/purview --help
```

`cargo build` produces an ad-hoc-signed binary, whose identity changes with every build.
On macOS, `./contrib/install.sh` runs the tests, builds, signs the binary with your own
stable local certificate, and installs it as `~/.local/bin/purview`. See
[troubleshooting](docs/troubleshooting.md#a-source-build-on-macos).

## Documentation

- [docs/SPEC.md](docs/SPEC.md): design and phased plan
- [docs/troubleshooting.md](docs/troubleshooting.md): installing and checking the binary
- [docs/macos-signing.md](docs/macos-signing.md): how releases are signed and notarized

## Licence

MIT. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
