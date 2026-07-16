#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname "$0")/../../.." && pwd)
HELPER="$ROOT/packaging/macos/pkg-scripts/service-state-rollback"
WORK=$(mktemp -d /tmp/pnsr.XXXXXX)
trap '/bin/rm -rf "$WORK"' EXIT INT TERM
BASE="$WORK/Private Network Node"

run_helper() {
  /bin/sh "$HELPER" --test-root "$BASE" "$1"
}

/bin/mkdir -p "$BASE/state" "$BASE/identity" "$BASE/releases/previous"
/usr/sbin/chown "$(/usr/bin/id -u):$(/usr/bin/id -g)" "$BASE"
/bin/chmod 755 "$BASE"
/bin/chmod 700 "$BASE/state" "$BASE/identity"
printf 'schema=16\n' > "$BASE/state/node-host.sqlite3"
printf 'wal-before\n' > "$BASE/state/node-host.sqlite3-wal"
printf 'shm-before\n' > "$BASE/state/node-host.sqlite3-shm"
printf 'signing-seed-before\n' > "$BASE/identity/identity.ed25519.seed"
printf 'encryption-seed-before\n' > "$BASE/identity/identity.x25519.seed"
/bin/chmod 600 "$BASE/state/"* "$BASE/identity/"*
python3 - "$BASE/state/node-host.sock" <<'PY'
import socket
import sys

listener = socket.socket(socket.AF_UNIX)
listener.bind(sys.argv[1])
listener.close()
PY
[ -S "$BASE/state/node-host.sock" ]

cat > "$BASE/releases/previous/node-host" <<'SH'
#!/bin/sh
set -eu
base=$1
[ "$(/bin/cat "$base/state/node-host.sqlite3")" = 'schema=16' ]
[ "$(/bin/cat "$base/state/node-host.sqlite3-wal")" = 'wal-before' ]
[ "$(/bin/cat "$base/state/node-host.sqlite3-shm")" = 'shm-before' ]
[ "$(/bin/cat "$base/identity/identity.ed25519.seed")" = 'signing-seed-before' ]
[ "$(/bin/cat "$base/identity/identity.x25519.seed")" = 'encryption-seed-before' ]
[ "$(/usr/bin/stat -f '%Lp' "$base/state")" = 700 ]
[ "$(/usr/bin/stat -f '%Lp' "$base/identity")" = 700 ]
[ "$(/usr/bin/stat -f '%Lp' "$base/state/node-host.sqlite3")" = 600 ]
[ ! -e "$base/service-state" ]
SH
/bin/chmod 755 "$BASE/releases/previous/node-host"

run_helper snapshot
[ ! -e "$BASE/state/node-host.sock" ]
[ -f "$BASE/.service-state-rollback/complete" ]

# Simulate postinstall moving both trees and applying an incompatible schema,
# then inject a failure before launchctl bootstrap.
/bin/mkdir -m 700 "$BASE/service-state"
/bin/mv "$BASE/state" "$BASE/service-state/state"
/bin/mv "$BASE/identity" "$BASE/service-state/identity"
printf 'schema=17\n' > "$BASE/service-state/state/node-host.sqlite3"
printf 'wal-after\n' > "$BASE/service-state/state/node-host.sqlite3-wal"
printf 'new-seed\n' > "$BASE/service-state/identity/identity.ed25519.seed"
printf '{"schemaVersion":1}\n' > "$BASE/service-state/last-unpair.json"
injected_status=72

if [ "$injected_status" -ne 0 ]; then
  run_helper restore
fi

"$BASE/releases/previous/node-host" "$BASE"
[ ! -e "$BASE/.service-state-rollback" ]
[ ! -e "$BASE/.service-state-failed" ]

# Stale or symlinked snapshots are rejected rather than consumed.
/bin/ln -s "$BASE/state" "$BASE/.service-state-rollback"
if run_helper restore >/dev/null 2>&1; then
  echo "symlinked rollback snapshot was accepted" >&2
  exit 1
fi
/bin/rm "$BASE/.service-state-rollback"

# Snapshot construction is atomic. An injected copy failure cannot publish a
# partial canonical snapshot or leave staging behind.
if ROLLBACK_TEST_DITTO=/usr/bin/false run_helper snapshot >/dev/null 2>&1; then
  echo "snapshot unexpectedly ignored an injected copy failure" >&2
  exit 1
fi
[ ! -e "$BASE/.service-state-rollback" ]
if /usr/bin/find "$BASE" -maxdepth 1 -name '.service-state-rollback.staging.*' -print -quit | /usr/bin/grep -q .; then
  echo "failed snapshot left a staging directory" >&2
  exit 1
fi

echo "service-state rollback lifecycle passed"
