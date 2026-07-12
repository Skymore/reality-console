#!/bin/sh
set -eu
[ "$#" -eq 2 ] || { echo "usage: $0 ARTIFACT STATUS_JSON" >&2; exit 64; }
ARTIFACT=$1
STATUS=$2
[ -f "$ARTIFACT" ] || { echo "notarization artifact is missing" >&2; exit 66; }

configured=0
if [ -n "${APPLE_ID:-}" ] || [ -n "${APPLE_PASSWORD:-}" ] || [ -n "${APPLE_TEAM_ID:-}" ]; then
  [ -n "${APPLE_ID:-}" ] && [ -n "${APPLE_PASSWORD:-}" ] && [ -n "${APPLE_TEAM_ID:-}" ] || {
    echo "macOS notarization credentials are partial" >&2; exit 78;
  }
  configured=1
fi

mkdir -p "$(dirname "$STATUS")"
if [ "$configured" -eq 0 ]; then
  [ "${REQUIRE_SIGNING:-0}" != 1 ] || { echo "notarization credentials are required" >&2; exit 78; }
  printf '{"schemaVersion":1,"status":"not-submitted-unsigned-validation"}\n' > "$STATUS"
  exit 0
fi

if ! /usr/bin/xcrun stapler validate "$ARTIFACT" >/dev/null 2>&1; then
  /usr/bin/xcrun notarytool submit "$ARTIFACT" --apple-id "$APPLE_ID" --password "$APPLE_PASSWORD" --team-id "$APPLE_TEAM_ID" --wait
  /usr/bin/xcrun stapler staple "$ARTIFACT"
fi
/usr/bin/xcrun stapler validate "$ARTIFACT"
printf '{"schemaVersion":1,"status":"accepted-and-stapled"}\n' > "$STATUS"
