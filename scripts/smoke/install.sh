#!/bin/sh
set -eu
[ "$#" -eq 3 ] || { echo "usage: $0 ROOT PAYLOAD VERSION" >&2; exit 64; }
. "$(dirname "$0")/lib.sh"
ROOT=$1 PAYLOAD=$2 VERSION=$3
[ ! -e "$ROOT/current" ] || die "install requires an empty target"
install_release "$ROOT" "$PAYLOAD" "$VERSION"
switch_current "$ROOT" "$VERSION"
