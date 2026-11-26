# Security policy

Do not report a vulnerability in a public issue.

## Reporting a vulnerability

Report security issues privately through GitHub on this repository: open the **Security** tab and select **Report a vulnerability**, or open a report directly at:

https://github.com/aberoham/ms-purview-cli/security/advisories/new

Include what is affected, the steps to reproduce the issue and the impact you expect. Fixes go into the latest release only.

## Do not send secrets or tenant data

Never include access tokens, refresh tokens, device codes, tenant or application (client) identifiers, real email addresses, case names, search queries or exported content in a vulnerability report. Replace identifiers with placeholders such as `<tenant-id>` and `<application-client-id>`, and use synthetic addresses under `contoso.example` or `fabrikam.example`.

## Security boundaries

- Tokens are kept only in the operating system's credential store (macOS Keychain, Windows Credential Manager or Linux kernel keyring); `config.json` and account files hold no secrets.
- Everything `purview` prints passes through a redactor that removes tokens it has seen; JSON is redacted as a value before serialisation, and `config.json` refuses to save a value the redactor recognises.
- From the transport pull request onwards, requests go only to fixed origins with Microsoft Graph redirects disabled.
- The tool never places, changes or releases a hold, never deletes or reopens a case, and sends a Purview write only after plan approval.

## Verifying releases

Release archives are built by this repository's release workflow, listed in `checksums-sha256.txt` and backed by a build provenance attestation. macOS binaries are Developer ID signed and notarised; the Windows binary is not code-signed. Verification commands are in [docs/troubleshooting.md](docs/troubleshooting.md).
