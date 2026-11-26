#!/usr/bin/env bash
# Re-sign a source-built purview binary with a stable code-signing certificate
# so macOS keychain "Always Allow" grants persist across rebuilds.
#
# Why this is needed: macOS ties a keychain authorisation to the *identity of
# the program* that asked for it. `cargo build` produces an ad-hoc-signed
# binary whose identity changes with every build, so the system correctly
# treats each new binary as a different program and asks again. Signing with
# one stable certificate makes the grant stick.
#
# One-time setup, if you have no code-signing certificate yet (Keychain
# Access, about a minute):
#   Keychain Access -> Certificate Assistant -> Create a Certificate...
#     Name:             purview-cli-signer
#     Identity Type:    Self-Signed Root
#     Certificate Type: Code Signing
#   Then double-click the certificate -> Trust -> "When using this
#   certificate: Always Trust".
#
# Environment overrides:
#   SIGN_IDENTITY      certificate name, tried before the defaults below
#   SIGN_KEYCHAIN      keychain holding it (default: the login keychain)
#   PURVIEW_BUNDLE_ID  code-signing identifier (default: io.github.aberoham.purview-cli)
#
# Keep PURVIEW_BUNDLE_ID constant once chosen. Changing it, like changing the
# certificate, makes macOS ask once more.
#
# The default target is target/release/purview; explicit binary paths may be
# supplied as arguments. After a source build:
#   cargo build --release && ./contrib/resign.sh
# Release binaries are Developer ID signed (TeamIdentifier 2VLHJGU477) and
# keep keychain grants across upgrades on their own. Do not re-sign them: that
# replaces the release signature. The script refuses to unless
# PURVIEW_RESIGN_RELEASE=1.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUNDLE_ID="${PURVIEW_BUNDLE_ID:-io.github.aberoham.purview-cli}"
KEYCHAIN="${SIGN_KEYCHAIN:-$HOME/Library/Keychains/login.keychain-db}"

# A certificate made for the sibling Entra or Teams command-line tools works
# equally well. What matters is using the same trusted identity every time.
CANDIDATES=("${SIGN_IDENTITY:-}" "purview-cli-signer" "entra-cli-signer" "teams-cli-signer")

IDENTITY=""
for candidate in "${CANDIDATES[@]}"; do
  [ -n "$candidate" ] || continue
  if security find-identity -v -p codesigning "$KEYCHAIN" | grep -qF "$candidate"; then
    IDENTITY="$candidate"
    break
  fi
done

if [ -z "$IDENTITY" ]; then
  echo "error: no code-signing identity found." >&2
  echo "Tried: ${CANDIDATES[*]}" >&2
  echo "Create one via Keychain Access -> Certificate Assistant (see the header" >&2
  echo "of this script), or set SIGN_IDENTITY=<name> to use an existing one." >&2
  exit 1
fi

if [ "$#" -eq 0 ]; then
  BINARIES=("$REPO_ROOT/target/release/purview")
else
  BINARIES=("$@")
fi

signed=0
for bin in "${BINARIES[@]}"; do
  if [ ! -x "$bin" ]; then
    echo "error: binary is missing or not executable: $bin" >&2
    exit 1
  fi
  if [ "${PURVIEW_RESIGN_RELEASE:-}" != 1 ] &&
    codesign -dv "$bin" 2>&1 | grep -qx 'TeamIdentifier=2VLHJGU477'; then
    echo "error: $bin is a Developer ID signed release; it already keeps keychain" >&2
    echo "grants across upgrades. Set PURVIEW_RESIGN_RELEASE=1 to replace its signature anyway." >&2
    exit 1
  fi
  codesign --force --keychain "$KEYCHAIN" --sign "$IDENTITY" --identifier "$BUNDLE_ID" "$bin"
  codesign --verify --strict "$bin"
  echo "signed: $bin"
  signed=$((signed + 1))
done

echo
echo "Done ($signed signed) with identity '$IDENTITY'."
echo "The next keychain prompt is the last one: click 'Always Allow'."
