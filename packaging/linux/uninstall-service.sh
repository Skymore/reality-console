#!/bin/sh
set -eu
[ "$(id -u)" -eq 0 ] || { echo "run as root" >&2; exit 77; }
PURGE=${1-}
systemctl disable --now reality-node.service >/dev/null 2>&1 || true
rm -f /etc/systemd/system/reality-node.service
systemctl daemon-reload
rm -rf /opt/private-network-node
if [ "$PURGE" = --purge-state ]; then
  rm -rf /var/lib/private-network-node /var/log/private-network-node
  userdel reality-node >/dev/null 2>&1 || true
fi
