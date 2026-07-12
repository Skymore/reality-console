#!/bin/sh
set -eu
[ "$#" -eq 3 ] || { echo "usage: $0 ROOT PAYLOAD VERSION" >&2; exit 64; }
. "$(dirname "$0")/lib.sh"
ROOT=$1 PAYLOAD=$2 VERSION=$3
previous=$(current_target "$ROOT")
install_release "$ROOT" "$PAYLOAD" "$VERSION"
printf '%s\n' "$previous" > "$ROOT/previous-release"
switch_current "$ROOT" "$VERSION"
