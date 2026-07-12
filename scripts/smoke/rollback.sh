#!/bin/sh
set -eu
[ "$#" -eq 1 ] || { echo "usage: $0 ROOT" >&2; exit 64; }
. "$(dirname "$0")/lib.sh"
ROOT=$1
[ -f "$ROOT/previous-release" ] || die "previous release is missing"
previous=$(cat "$ROOT/previous-release")
case "$previous" in releases/*) ;; *) die "unsafe previous release" ;; esac
[ -d "$ROOT/$previous" ] || die "previous release directory is missing"
verify_payload "$ROOT/$previous"
current=$(current_target "$ROOT")
switch_current "$ROOT" "${previous#releases/}"
printf '%s\n' "$current" > "$ROOT/previous-release"
