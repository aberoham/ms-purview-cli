# Contributing to purview

Each pull request implements one item from section 11 of [docs/SPEC.md](docs/SPEC.md) and nothing from later items. Open an issue before starting work larger than a bug fix; use the **Change proposal** issue form for this.

Read [AGENTS.md](AGENTS.md) before changing code. It documents the repository architecture, command and output contracts, credential compatibility rules and review process for both human contributors and artificial intelligence (AI) agents.

## Public-data rules

This is a public repository. Keep every change free of real tenant or user data:

- Use synthetic data only: `contoso.example` and `fabrikam.example` email addresses, and globally unique identifiers (GUIDs) of the form `00000000-0000-4000-8000-0000000000NN`.
- Never commit access tokens, refresh tokens, device codes, tenant or application (client) identifiers, organisation names, domains, internal URLs, naming policies, or real mailbox, case or search data.
- Write test fixtures by hand from documented shapes. Never copy recorded traffic into fixtures, even redacted.

## Safety and service claims

- No `PATCH`, `PUT` or `DELETE` requests may be added to the crate. Every Purview write is restricted to the six allowed `POST` routes listed under "Write allow list" in [AGENTS.md](AGENTS.md). Adding a write requires a reviewed design, a change to the allow-list test and an update to the safety documentation, as that rule describes.
- Label every claim about Microsoft Graph or Purview service behaviour in documentation and comments with its evidence level (`Observed`, `Docs`, `Derived` or `Assumption`), and record live tenant checks in [docs/api-notes.md](docs/api-notes.md).

## Python

The shipped `purview` binary is Rust only and never needs Python. Development may use Python: contributors are expected to have a modern Python environment with `uv`, and development scripts run through `uv run` with their dependencies pinned. No user-facing feature may depend on a Python script.

## Verification

Run Cargo through rustup so `rust-toolchain.toml` selects Rust 1.100:

```bash
cargo fmt --all -- --check
cargo check --all-targets
cargo clippy --all-targets -- -D warnings
cargo test --all-targets
cargo build --release
```

Run the public-data lint alone with `cargo test --test fixture_lint`.

Additional checks by area (see the Verification section of [AGENTS.md](AGENTS.md) for the full list):

- Workflow changes: `actionlint` and `zizmor --offline .github/workflows`.
- Shell script changes: `bash -n` and `shellcheck`.
- Changes to `contrib/create-purview-app.sh` or its fake `az` test harness: `tests/scripts/create-purview-app-test.sh`, and on macOS also `TEST_BASH=/bin/bash tests/scripts/create-purview-app-test.sh`.
- Signing-helper changes: `python3 .github/scripts/test_macos_signing.py`.

## Licence

Contributions are accepted under the MIT licence. See [LICENSE](LICENSE).
