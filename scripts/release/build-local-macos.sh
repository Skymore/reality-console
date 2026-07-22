#!/bin/bash
set -euo pipefail

if [[ $# -lt 1 || $# -gt 2 ]]; then
  echo "usage: $0 control|connect|node-host [TARGET]" >&2
  exit 64
fi

if [[ $(uname -s) != Darwin ]]; then
  echo "local macOS bundles must be built on macOS" >&2
  exit 69
fi

PRODUCT=$1
TARGET=${2:-$(rustc --print host-tuple)}
IDENTITY=${PRIVATE_NETWORK_LOCAL_SIGNING_IDENTITY:-Private Network Local Development}
ROOT=$(cd "$(dirname "$0")/../.." && pwd)

if ! /usr/bin/security find-identity -v -p codesigning | /usr/bin/grep -Fq "\"$IDENTITY\""; then
  echo "missing local code-signing identity: $IDENTITY" >&2
  echo "run scripts/release/setup-local-macos-signing.sh first" >&2
  exit 78
fi

case "$PRODUCT" in
  control) DIRECTORY=$ROOT ;;
  connect) DIRECTORY=$ROOT/client ;;
  node-host) DIRECTORY=$ROOT/node-host-app ;;
  *) echo "unknown product: $PRODUCT" >&2; exit 64 ;;
esac
APP_NAME=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["productName"])' \
  "$DIRECTORY/src-tauri/tauri.conf.json")

(
  cd "$DIRECTORY"
  npm run tauri -- build \
    --target "$TARGET" \
    --config src-tauri/tauri.local.conf.json
)

TARGET_DIR=$(python3 "$ROOT/scripts/release/cargo-target-dir.py" "$DIRECTORY/src-tauri/Cargo.toml")
APP="$TARGET_DIR/$TARGET/release/bundle/macos/$APP_NAME.app"
if [[ ! -d "$APP" ]]; then
  echo "Tauri did not produce a macOS application bundle" >&2
  exit 1
fi

/usr/bin/codesign --verify --deep --strict --verbose=2 "$APP"
AUTHORITY=$(/usr/bin/codesign -d --verbose=4 "$APP" 2>&1 | /usr/bin/sed -n 's/^Authority=//p' | /usr/bin/head -1)
if [[ "$AUTHORITY" != "$IDENTITY" ]]; then
  echo "unexpected application signing authority: ${AUTHORITY:-missing}" >&2
  exit 1
fi

printf 'Built and verified %s\n' "$APP"
