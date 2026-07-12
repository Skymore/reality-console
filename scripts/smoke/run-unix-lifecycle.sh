#!/bin/sh
set -eu
ROOT_DIR=$(CDPATH= cd -- "$(dirname "$0")/../.." && pwd)
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT INT TERM
INSTALL="$WORK/install"

payload() {
  version=$1 dir="$WORK/payload-$1"
  mkdir -p "$dir"
  printf '#!/bin/sh\necho node-host-%s\n' "$version" > "$dir/node-host"
  printf '#!/bin/sh\necho xray-%s\n' "$version" > "$dir/xray"
  chmod 755 "$dir/node-host" "$dir/xray"
  if command -v shasum >/dev/null 2>&1; then
    (cd "$dir" && shasum -a 256 node-host xray) > "$dir/SHA256SUMS"
  else
    (cd "$dir" && sha256sum node-host xray) > "$dir/SHA256SUMS"
  fi
  printf '%s\n' "$dir"
}

V1=$(payload 1.0.0)
V2=$(payload 1.1.0)
"$ROOT_DIR/scripts/smoke/install.sh" "$INSTALL" "$V1" 1.0.0
[ "$(readlink "$INSTALL/current")" = releases/1.0.0 ]
printf 'durable-node-identity\n' > "$INSTALL/state/identity"

"$ROOT_DIR/scripts/smoke/upgrade.sh" "$INSTALL" "$V2" 1.1.0
[ "$(readlink "$INSTALL/current")" = releases/1.1.0 ]
[ "$(cat "$INSTALL/state/identity")" = durable-node-identity ]

"$ROOT_DIR/scripts/smoke/rollback.sh" "$INSTALL"
[ "$(readlink "$INSTALL/current")" = releases/1.0.0 ]
[ "$(cat "$INSTALL/state/identity")" = durable-node-identity ]

"$ROOT_DIR/scripts/smoke/uninstall.sh" "$INSTALL"
[ ! -e "$INSTALL/current" ]
[ "$(cat "$INSTALL/state/identity")" = durable-node-identity ]

mkdir -p "$INSTALL/releases/1.0.0"
ln -s releases/1.0.0 "$INSTALL/current"
"$ROOT_DIR/scripts/smoke/uninstall.sh" "$INSTALL" --purge-state
[ ! -e "$INSTALL/state" ]
echo "unix lifecycle smoke: passed"
