#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/../.." && pwd)
SHARED_TARGET=$(python3 "$ROOT/scripts/release/cargo-target-dir.py" "$ROOT/src-tauri/Cargo.toml")

LEGACY_TARGETS=(
  "client/src-tauri/Cargo.toml|client/src-tauri/target"
  "control-server/Cargo.toml|control-server/target"
  "crates/control-protocol/Cargo.toml|crates/control-protocol/target"
  "crates/relay-provisioning/Cargo.toml|crates/relay-provisioning/target"
  "crates/release-manifest/Cargo.toml|crates/release-manifest/target"
  "crates/xray-runtime/Cargo.toml|crates/xray-runtime/target"
  "node-host-app/src-tauri/Cargo.toml|node-host-app/src-tauri/target"
  "node-host/Cargo.toml|node-host/target"
  "relay-server/Cargo.toml|relay-server/target"
  "scripts/release-manifest-tool/Cargo.toml|scripts/release-manifest-tool/target"
  "src-tauri/Cargo.toml|src-tauri/target"
)

usage() {
  echo "usage: $0 audit|clean-legacy|clean-all" >&2
  exit 64
}

audit() {
  echo "Shared Cargo target: $SHARED_TARGET"
  if [[ -d "$SHARED_TARGET" ]]; then
    du -sh "$SHARED_TARGET"
  else
    echo "0 B  $SHARED_TARGET"
  fi
  echo "Legacy per-component targets:"
  local entry target kib
  local legacy_kib=0
  for entry in "${LEGACY_TARGETS[@]}"; do
    target="$ROOT/${entry#*|}"
    if [[ -d "$target" ]]; then
      du -sh "$target"
      kib=$(du -sk "$target" | awk '{print $1}')
      legacy_kib=$((legacy_kib + kib))
    fi
  done
  awk -v kib="$legacy_kib" 'BEGIN { printf "Legacy total: %.2f GiB\n", kib / 1048576 }'
}

clean_legacy() {
  local entry manifest target
  for entry in "${LEGACY_TARGETS[@]}"; do
    manifest="$ROOT/${entry%%|*}"
    target="$ROOT/${entry#*|}"
    if [[ -d "$target" ]]; then
      echo "Cleaning legacy Cargo output: $target"
      cargo clean --manifest-path "$manifest" --target-dir "$target"
    fi
  done
}

case "${1-}" in
  audit)
    audit
    ;;
  clean-legacy)
    clean_legacy
    ;;
  clean-all)
    clean_legacy
    if [[ -d "$SHARED_TARGET" ]]; then
      echo "Cleaning shared Cargo output: $SHARED_TARGET"
      cargo clean --manifest-path "$ROOT/src-tauri/Cargo.toml" --target-dir "$SHARED_TARGET"
    fi
    ;;
  *)
    usage
    ;;
esac
