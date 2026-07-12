#!/bin/sh
set -eu
ROOT=$(CDPATH= cd -- "$(dirname "$0")/../.." && pwd)
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT INT TERM
printf 'package bytes\n' > "$WORK/connect.pkg"
printf '{"bomFormat":"CycloneDX","specVersion":"1.5","version":1}\n' > "$WORK/connect.cdx.json"
cat > "$WORK/input.json" <<EOF
{
  "releaseId": "82eb4802-d616-4f70-954b-7d4c09f15a72",
  "sourceCommit": "1111111111111111111111111111111111111111",
  "issuedAt": 1770000000,
  "releaseNotesUrl": "https://example.com/releases/1.0.0",
  "artifacts": [{
    "product": "connect",
    "platform": "macos",
    "architecture": "aarch64",
    "version": "1.0.0",
    "path": "$WORK/connect.pkg",
    "sbomPath": "$WORK/connect.cdx.json",
    "minimumConfigurationSchema": 1,
    "maximumConfigurationSchema": 1,
    "xrayVersion": "26.3.27"
  }]
}
EOF

TOOL="cargo run --quiet --locked --manifest-path $ROOT/scripts/release-manifest-tool/Cargo.toml --"
$TOOL generate "$WORK/input.json" "$WORK/unsigned.json" "$WORK/unsigned-evidence.json" unsigned_validation_key "$ROOT/packaging/release-trust.json"
python3 - "$WORK/unsigned.json" "$WORK/unsigned-evidence.json" <<'PY'
import json, sys
manifest = json.load(open(sys.argv[1]))
evidence = json.load(open(sys.argv[2]))
assert "signature" not in manifest
assert evidence["signatureStatus"] == "unsigned-validation"
PY

printf 'stale unsigned\n' > "$WORK/blocked.json"
printf 'stale evidence\n' > "$WORK/blocked-evidence.json"
if REQUIRE_SIGNING=1 $TOOL generate "$WORK/input.json" "$WORK/blocked.json" "$WORK/blocked-evidence.json" release_root_pending_2026 "$ROOT/packaging/release-trust.json" 2>/dev/null; then
  echo "signed release unexpectedly accepted without a private key" >&2
  exit 1
fi
[ ! -e "$WORK/blocked.json" ] && [ ! -e "$WORK/blocked-evidence.json" ]

cat > "$WORK/test-trust.json" <<'EOF'
{
  "schemaVersion": 1,
  "productionReady": true,
  "releaseKeys": [{"keyId":"release_test_2026","publicKey":"6kpsY-KcUgq-9VB7Ey7F-ZVHdq6-vnuSQh7qaRRG0iw"}],
  "rollbackKeys": [{"keyId":"rollback_test_2026","publicKey":"E5j2LG0aRXxRumpLXz29L2n8qTIWIY3ImX5Ba9F9k8o"}]
}
EOF
RELEASE_SIGNING_PRIVATE_KEY=BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc REQUIRE_SIGNING=1 \
  $TOOL generate "$WORK/input.json" "$WORK/signed.json" "$WORK/signed-evidence.json" release_test_2026 "$WORK/test-trust.json"
$TOOL verify "$WORK/signed.json" "$WORK/input.json" "$WORK/test-trust.json"
python3 - "$WORK/signed.json" "$WORK/signed-evidence.json" <<'PY'
import json, sys
manifest = json.load(open(sys.argv[1]))
evidence = json.load(open(sys.argv[2]))
assert len(manifest["signature"]) == 86
assert evidence["signatureStatus"] == "signed"
PY
echo "release manifest smoke: passed"
