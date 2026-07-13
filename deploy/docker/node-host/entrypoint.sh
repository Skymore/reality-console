#!/bin/sh
set -eu

STATE_DIR=${STATE_DIR:-/var/lib/private-network-node}
NODE_HOST=/opt/private-network/node-host
XRAY=/opt/private-network/xray
XRAY_SHA256=$(cat /opt/private-network/xray.sha256)

case "${1:-}" in
  setup)
    : "${PUBLIC_ADDRESS:?PUBLIC_ADDRESS is required for setup}"
    : "${PUBLIC_PORT:?PUBLIC_PORT is required for setup}"
    "$NODE_HOST" setup \
      --data-dir "$STATE_DIR" \
      --xray-binary-path "$XRAY" \
      --xray-sha256 "$XRAY_SHA256" \
      --accept-host-owner \
      --accept-exit-ip
    "$NODE_HOST" sync-once --data-dir "$STATE_DIR"
    "$NODE_HOST" configure-manual-endpoint \
      --data-dir "$STATE_DIR" \
      --address "$PUBLIC_ADDRESS" \
      --public-port "$PUBLIC_PORT" \
      --forwarded-local-port "$PUBLIC_PORT"
    ;;
  run)
    exec "$NODE_HOST" run \
      --data-dir "$STATE_DIR" \
      --sync-interval-seconds "${SYNC_INTERVAL_SECONDS:-30}" \
      --initial-backoff-seconds "${INITIAL_BACKOFF_SECONDS:-5}" \
      --max-backoff-seconds "${MAX_BACKOFF_SECONDS:-300}"
    ;;
  status)
    exec "$NODE_HOST" status --data-dir "$STATE_DIR"
    ;;
  *)
    echo "usage: private-network-node setup|run|status" >&2
    exit 64
    ;;
esac
