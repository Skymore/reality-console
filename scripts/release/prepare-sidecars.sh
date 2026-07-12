#!/bin/sh
set -eu

usage() {
  echo "usage: $0 --product connect|node-host --target TARGET [--release]" >&2
  exit 64
}

PRODUCT=
TARGET=
PROFILE=debug
while [ "$#" -gt 0 ]; do
  case "$1" in
    --product) PRODUCT=${2-}; shift 2 ;;
    --target) TARGET=${2-}; shift 2 ;;
    --release) PROFILE=release; shift ;;
    *) usage ;;
  esac
done
[ -n "$PRODUCT" ] && [ -n "$TARGET" ] || usage

ROOT=$(CDPATH= cd -- "$(dirname "$0")/../.." && pwd)
EXT=
case "$TARGET" in
  *-windows-msvc) EXT=.exe ;;
esac

case "$PRODUCT" in
  connect)
    OUT="$ROOT/client/src-tauri/binaries/xray-$TARGET$EXT"
    ;;
  node-host)
    OUT_DIR="$ROOT/node-host-app/src-tauri/binaries"
    mkdir -p "$OUT_DIR"
    OUT="$OUT_DIR/xray-$TARGET$EXT"
    cargo build --locked --manifest-path "$ROOT/node-host/Cargo.toml" --target "$TARGET" $( [ "$PROFILE" = release ] && printf %s --release )
    SOURCE="$ROOT/node-host/target/$TARGET/$PROFILE/node-host$EXT"
    [ -f "$SOURCE" ] || { echo "missing Node Host build: $SOURCE" >&2; exit 1; }
    cp "$SOURCE" "$OUT_DIR/node-host-$TARGET$EXT"
    chmod 755 "$OUT_DIR/node-host-$TARGET$EXT" 2>/dev/null || true
    ;;
  *) usage ;;
esac

python3 "$ROOT/scripts/release/acquire-sidecar.py" --target "$TARGET" --output "$OUT"
PROVENANCE_DIR=$(dirname "$OUT")
if [ "$PRODUCT" = node-host ]; then
  NODE_VERSION=$(python3 -c 'import pathlib,tomllib; print(tomllib.loads(pathlib.Path("'"$ROOT"'/node-host/Cargo.toml").read_text())["package"]["version"])')
  python3 "$ROOT/scripts/release/verify-sidecars.py" --target "$TARGET" --xray "$OUT" --node-host "$OUT_DIR/node-host-$TARGET$EXT" --node-host-version "$NODE_VERSION" --output "$PROVENANCE_DIR/sidecars-$TARGET.json"
else
  python3 "$ROOT/scripts/release/verify-sidecars.py" --target "$TARGET" --xray "$OUT" --output "$PROVENANCE_DIR/sidecars-$TARGET.json"
fi
