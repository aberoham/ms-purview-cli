# Security policy

Do not report a vulnerability in a public issue.

## Reporting a vulnerability

Report security issues privately through GitHub on this repository: open the **Security** tab and select **Report a vulnerability**, or open a report directly at:

https://github.com/aberoham/ms-purview-cli/security/advisories/new

Include what is affected, the steps to reproduce the issue and the impact you expect. Fixes go into the latest release only.

## Do not send secrets or tenant data

Never include access tokens, refresh tokens, device codes, tenant or application (client) identifiers, real email addresses, case names, search queries or exported content in a vulnerability report. Replace identifiers with placeholders such as `<tenant-id>` and `<application-client-id>`, and use synthetic addresses under `contoso.example` or `fabrikam.example`.

## Protections in the current binary

- Tokens are kept only in the operating system's credential store (macOS Keychain, Windows Credential Manager or Linux kernel keyring). `config.json` and account files hold no secrets, and saving `config.json` refuses any value the redactor recognises.
- Everything `purview` prints passes through a redactor that removes tokens it has seen; JavaScript Object Notation (JSON) is redacted as a value before serialisation.
- A public-data lint (`tests/fixture_lint.rs`) runs in continuous integration (CI) on every pull request and every push to `main` to keep real tenant identifiers, addresses, URLs and home-directory paths out of the repository.

## Design rules for later pull requests

- Microsoft Graph requests go only to `https://graph.microsoft.com`, with redirects disabled, and the download token goes only to the one download origin named by each operation (from the transport and download pull requests onwards).
- The tool never places, changes or releases a hold, never deletes or reopens a case, and sends a Purview write only after a plan has been shown and approved. No Purview write command exists yet.

## Verifying releases

Release archives are built by this repository's release workflow, listed in `checksums-sha256.txt` and backed by a build provenance attestation. macOS binaries are Developer ID signed and notarised; the Windows binary is not code-signed. Verification commands are in [docs/troubleshooting.md](docs/troubleshooting.md).
