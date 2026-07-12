#!/bin/sh
set -eu

[ "$#" -eq 1 ] || { echo "usage: $0 CONNECT_BINARY" >&2; exit 64; }
BINARY=$1
[ -x "$BINARY" ] || { echo "Connect binary is not executable" >&2; exit 66; }

WORK=$(mktemp -d)
cleanup() {
  /bin/rm -rf "$WORK"
}
trap cleanup EXIT INT TERM

OUTPUT="$WORK/status.json"
printf '%s\n' '{"schemaVersion":1,"operation":{"method":"status"}}' | \
  "$BINARY" headless --output "$OUTPUT"

[ -f "$OUTPUT" ] && [ ! -L "$OUTPUT" ]
[ "$(/usr/bin/stat -f '%Lp' "$OUTPUT")" = 600 ]
python3 - "$OUTPUT" <<'PY'
import json
import pathlib
import sys

value = json.loads(pathlib.Path(sys.argv[1]).read_text())
assert set(value) == {"schemaVersion", "complete", "outcome"}
assert value["schemaVersion"] == 1
assert value["complete"] is True
assert value["outcome"]["status"] == "success"
PY

if printf '%s\n' '{"schemaVersion":1,"operation":{"method":"status"}}' | \
    "$BINARY" headless --output relative.json >/dev/null 2>&1; then
  echo "Connect accepted a relative headless output path" >&2
  exit 1
fi

INVALID="$WORK/invalid.json"
if printf '%s\n' '{"schemaVersion":1,"operation":{"method":"status","extra":true}}' | \
    "$BINARY" headless --output "$INVALID" >/dev/null 2>&1; then
  echo "Connect accepted an extended headless request" >&2
  exit 1
fi
python3 - "$INVALID" <<'PY'
import json
import pathlib
import sys

value = json.loads(pathlib.Path(sys.argv[1]).read_text())
assert value["complete"] is True
assert value["outcome"] == {"status": "error", "code": "headless_request_invalid"}
PY

echo "Connect installed-binary headless smoke passed"
