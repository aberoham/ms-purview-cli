#!/usr/bin/env bash
# Build, verify, sign and atomically install purview for the current user.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
INSTALL_DIR="${PURVIEW_INSTALL_DIR:-$HOME/.local/bin}"
RELEASE_BIN="$REPO_ROOT/target/release/purview"
INSTALL_BIN="$INSTALL_DIR/purview"

cd "$REPO_ROOT"

echo "==> Running tests"
cargo test --all-targets --locked

echo "==> Building release binary"
cargo build --release --locked

if [ "$(uname -s)" = "Darwin" ]; then
  echo "==> Signing release binary"
  "$REPO_ROOT/contrib/resign.sh" "$RELEASE_BIN"
fi

echo "==> Smoke-testing release binary"
"$RELEASE_BIN" version >/dev/null
"$RELEASE_BIN" --help >/dev/null

mkdir -p "$INSTALL_DIR"
STAGED_BIN=$(mktemp "$INSTALL_DIR/.purview.install.XXXXXX")
cleanup() {
  rm -f "$STAGED_BIN"
}
trap cleanup EXIT

install -m 0755 "$RELEASE_BIN" "$STAGED_BIN"
if [ "$(uname -s)" = "Darwin" ]; then
  codesign --verify --strict "$STAGED_BIN"
fi
mv -f "$STAGED_BIN" "$INSTALL_BIN"
trap - EXIT

if [ "$(uname -s)" = "Darwin" ]; then
  codesign --verify --strict "$INSTALL_BIN"
fi
"$INSTALL_BIN" version >/dev/null

echo "installed: $INSTALL_BIN"
case ":$PATH:" in
  *":$INSTALL_DIR:"*) ;;
  *) echo "warning: $INSTALL_DIR is not on PATH" >&2 ;;
esac
