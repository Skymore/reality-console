#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 2 ]]; then
  echo "usage: $0 COMPONENT OUTPUT" >&2
  exit 64
fi

component=$1
output=$2
root=$(cd "$(dirname "$0")/../.." && pwd)
cd "$root"

rust_gate() {
  local manifest=$1
  cargo fmt --manifest-path "$manifest" -- --check
  cargo build --locked --manifest-path "$manifest" --all-targets
  cargo test --locked --manifest-path "$manifest" --all-targets
  cargo clippy --locked --manifest-path "$manifest" --all-targets -- -D warnings
  RUSTDOCFLAGS=-Dwarnings cargo doc --locked --manifest-path "$manifest" --no-deps
}

npm_gate() {
  local directory=$1
  shift
  npm ci --prefix "$directory"
  for command in "$@"; do
    (cd "$directory" && bash -euo pipefail -c "$command")
  done
}

case "$component" in
  control)
    manifest=control-server/Cargo.toml
    checks=(format build test clippy rustdoc migration-empty migration-previous)
    rust_gate "$manifest"
    cargo test --locked --manifest-path "$manifest" --lib db::tests::applies_required_pragmas_and_records_authoritative_migration -- --exact
    cargo test --locked --manifest-path "$manifest" --lib db::tests::v3_upgrade_discards_untrusted_heartbeat_progress_and_builds_revision_journal -- --exact
    cargo test --locked --manifest-path "$manifest" --lib db::tests::v4_upgrade_preserves_revision_graph_and_accepts_schema_two -- --exact
    python3 scripts/release/verify-control-previous-migration.py
    version=$(sed -n 's/^version = "\([^"]*\)"/\1/p' control-server/Cargo.toml | head -1)
    ;;
  protocol)
    manifest=crates/control-protocol/Cargo.toml
    checks=(format build test clippy rustdoc)
    rust_gate "$manifest"
    version=$(sed -n 's/^version = "\([^"]*\)"/\1/p' "$manifest" | head -1)
    ;;
  xray-runtime)
    manifest=crates/xray-runtime/Cargo.toml
    checks=(format build test clippy rustdoc)
    rust_gate "$manifest"
    version=$(sed -n 's/^version = "\([^"]*\)"/\1/p' "$manifest" | head -1)
    ;;
  node-host)
    manifest=node-host/Cargo.toml
    checks=(format build test clippy rustdoc migration-empty migration-previous)
    rust_gate "$manifest"
    cargo test --locked --manifest-path "$manifest" --test foundation migrations_are_recorded_once_and_pragmas_are_enabled -- --exact
    cargo test --locked --manifest-path "$manifest" --test foundation schema_sixteen_moves_legacy_identity_outside_state_without_rotation -- --exact
    version=$(sed -n 's/^version = "\([^"]*\)"/\1/p' "$manifest" | head -1)
    ;;
  relay)
    manifest=relay-server/Cargo.toml
    checks=(format build test clippy rustdoc)
    rust_gate "$manifest"
    version=$(sed -n 's/^version = "\([^"]*\)"/\1/p' "$manifest" | head -1)
    ;;
  relay-provisioning)
    manifest=crates/relay-provisioning/Cargo.toml
    checks=(format build test clippy rustdoc)
    rust_gate "$manifest"
    version=$(sed -n 's/^version = "\([^"]*\)"/\1/p' "$manifest" | head -1)
    ;;
  connect)
    checks=(format build test clippy rustdoc sidecar-test typecheck production-build)
    scripts/release/prepare-sidecars.sh --product connect --target aarch64-apple-darwin
    rust_gate client/src-tauri/Cargo.toml
    npm_gate client "npm run test:sidecar" "npx tsc --noEmit" "npm run build"
    version=$(python3 -c 'import json; print(json.load(open("client/src-tauri/tauri.conf.json"))["version"])')
    ;;
  control-app)
    checks=(format build test clippy rustdoc typecheck production-build)
    rust_gate src-tauri/Cargo.toml
    npm_gate . "npx tsc --noEmit" "npm run build"
    version=$(python3 -c 'import json; print(json.load(open("src-tauri/tauri.conf.json"))["version"])')
    ;;
  node-host-app)
    checks=(format build test clippy rustdoc package-frontend)
    scripts/release/prepare-sidecars.sh --product node-host --target aarch64-apple-darwin
    test -s node-host-app/dist/index.html
    rust_gate node-host-app/src-tauri/Cargo.toml
    version=$(python3 -c 'import json; print(json.load(open("node-host-app/src-tauri/tauri.conf.json"))["version"])')
    ;;
  probe-worker)
    checks=(test typecheck production-build)
    npm_gate probe-worker "npm test" "npm run check" "npx wrangler deploy --dry-run --outdir \"${RUNNER_TEMP:-/tmp}/probe-worker-build\""
    version=$(node -p 'require("./probe-worker/package.json").version')
    ;;
  *)
    echo "unknown release component: $component" >&2
    exit 64
    ;;
esac

python3 scripts/release/write-component-evidence.py \
  --name "$component" \
  --version "$version" \
  --source-commit "${GITHUB_SHA:?GITHUB_SHA is required}" \
  --checks "${checks[@]}" \
  --repository "${GITHUB_REPOSITORY:?GITHUB_REPOSITORY is required}" \
  --workflow "${GITHUB_WORKFLOW_REF:?GITHUB_WORKFLOW_REF is required}" \
  --run-id "${GITHUB_RUN_ID:?GITHUB_RUN_ID is required}" \
  --run-attempt "${GITHUB_RUN_ATTEMPT:?GITHUB_RUN_ATTEMPT is required}" \
  --job "component-gates ($component)" \
  --output "$output"
