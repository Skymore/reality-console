#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname "$0")/../../.." && pwd)
SCRIPTS="
$ROOT/packaging/macos/build-node-host-pkg.sh
$ROOT/packaging/macos/pkg-scripts/preinstall
$ROOT/packaging/macos/pkg-scripts/postinstall
$ROOT/packaging/macos/pkg-scripts/service-state-rollback
$ROOT/packaging/macos/reality-node-service
$ROOT/packaging/macos/uninstall-node-host.sh
"

commands=$(
  /usr/bin/grep -Eho '/(usr/)?(s)?bin/[[:alnum:]_.-]+' $SCRIPTS \
    | /usr/bin/sort -u
)

for command in $commands; do
  case "$command" in
    /bin/private-network-node-uninstall|/bin/reality-node-service) continue ;;
  esac
  [ -x "$command" ] || {
    echo "macOS package script references a missing command: $command" >&2
    exit 1
  }
done

echo "macOS package command paths exist"
