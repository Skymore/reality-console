#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname "$0")/../../.." && pwd)
WORK=$(mktemp -d)
service_pid=
cleanup() {
  if [ -n "$service_pid" ]; then /bin/kill "$service_pid" >/dev/null 2>&1 || true; fi
  /bin/rm -rf "$WORK"
}
trap cleanup EXIT INT TERM

BASE="$WORK/Private Network Node"
/bin/mkdir -p "$BASE/releases/previous"
/bin/ln -s releases/previous "$BASE/current"

# Stand in for the previously loaded daemon. A payload-stage failure occurs
# after preinstall, before postinstall can own the stop/snapshot transaction.
/bin/sleep 30 &
service_pid=$!

/usr/bin/sed \
  -e "s|^BASE=.*$|BASE=\"$BASE\"|" \
  -e 's|/usr/sbin/pkgutil --pkg-info com.sky.realitynode.pkg|/usr/bin/true|' \
  "$ROOT/packaging/macos/pkg-scripts/preinstall" > "$WORK/preinstall"
/bin/sh "$WORK/preinstall"

# Simulated payload failure: postinstall is intentionally never invoked.
payload_status=73
[ "$payload_status" -ne 0 ]
/bin/kill -0 "$service_pid"
[ "$(/bin/cat "$BASE/.previous-release")" = releases/previous ]

# A failed first install can leave payload files without a package receipt.
# Such a partial candidate must never be selected as a rollback release.
/usr/bin/sed \
  -e "s|^BASE=.*$|BASE=\"$BASE\"|" \
  -e 's|/usr/sbin/pkgutil --pkg-info com.sky.realitynode.pkg|/usr/bin/false|' \
  "$ROOT/packaging/macos/pkg-scripts/preinstall" > "$WORK/preinstall-no-receipt"
/bin/sh "$WORK/preinstall-no-receipt"
[ ! -e "$BASE/.previous-release" ]

if /usr/bin/grep -q 'launchctl\|bootout' "$ROOT/packaging/macos/pkg-scripts/preinstall"; then
  echo "preinstall still controls the running service" >&2
  exit 1
fi

echo "preinstall payload-failure lifecycle passed"
