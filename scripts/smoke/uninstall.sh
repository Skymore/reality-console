#!/bin/sh
set -eu
[ "$#" -ge 1 ] && [ "$#" -le 2 ] || { echo "usage: $0 ROOT [--purge-state]" >&2; exit 64; }
ROOT=$1
PURGE=${2-}
rm -f "$ROOT/current" "$ROOT/previous-release"
rm -rf "$ROOT/releases"
if [ "$PURGE" = --purge-state ]; then rm -rf "$ROOT/state"; fi
