#!/bin/bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: $0 connect|node-host" >&2
  exit 64
fi

PRODUCT=$1
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
TARGET=${TAURI_ENV_TARGET_TRIPLE:-$(rustc --print host-tuple)}

case "$TARGET" in
  *-apple-darwin) ;;
  *) echo "local macOS sidecar signing requires an Apple target" >&2; exit 64 ;;
esac

case "$PRODUCT" in
  connect)
    npm run --prefix "$ROOT/client" prepare:xray -- --target="$TARGET"
    ;;
  node-host)
    "$ROOT/scripts/release/prepare-sidecars.sh" \
      --product node-host \
      --target "$TARGET" \
      --release
    ;;
  *) echo "unknown product: $PRODUCT" >&2; exit 64 ;;
esac
