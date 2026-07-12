#!/bin/sh
set -eu
[ "$(id -u)" -eq 0 ] || { echo "run as root" >&2; exit 77; }
[ "$#" -eq 2 ] || { echo "usage: $0 PAYLOAD VERSION" >&2; exit 64; }
PAYLOAD=$1
VERSION=$2
BASE=/opt/private-network-node
RELEASE="$BASE/releases/$VERSION"

id reality-node >/dev/null 2>&1 || useradd --system --home-dir /var/lib/private-network-node --shell /usr/sbin/nologin reality-node
install -d -m 755 "$RELEASE" "$BASE/releases"
install -m 755 "$PAYLOAD/node-host" "$RELEASE/node-host"
install -m 755 "$PAYLOAD/xray" "$RELEASE/xray"
if [ -L "$BASE/current" ]; then readlink "$BASE/current" > "$BASE/previous-release"; fi
ln -sfn "releases/$VERSION" "$BASE/current.new"
mv -Tf "$BASE/current.new" "$BASE/current"
install -m 644 "$(dirname "$0")/reality-node.service" /etc/systemd/system/reality-node.service
install -d -o reality-node -g reality-node -m 700 /var/lib/private-network-node /var/log/private-network-node
systemctl daemon-reload
systemctl enable --now reality-node.service
