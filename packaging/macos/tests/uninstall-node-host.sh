#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname "$0")/../../.." && pwd)
WORK=$(mktemp -d)
cleanup() {
  /bin/rm -rf "$WORK"
}
trap cleanup EXIT INT TERM

BASE="$WORK/Library/Application Support/Private Network Node"
APP="$WORK/Applications/Private Network Node.app"
PLIST="$WORK/Library/LaunchDaemons/com.sky.realitynode.agent.plist"
RUNTIME="$BASE/run"
LEGACY_RUNTIME="$WORK/var/run/private-network-node"
LOGS="$WORK/Library/Logs/Private Network Node"
SCRIPT="$WORK/uninstall"
UID_VALUE=$(/usr/bin/id -u)
NODE_ID=11111111-1111-4111-8111-111111111111

/usr/bin/sed \
  -e "s|^BASE=.*$|BASE=\"$BASE\"|" \
  -e "s|^APP=.*$|APP=\"$APP\"|" \
  -e "s|^PLIST=.*$|PLIST=\"$PLIST\"|" \
  -e "s|^RUNTIME=.*$|RUNTIME=\"$RUNTIME\"|" \
  -e "s|^LEGACY_RUNTIME=.*$|LEGACY_RUNTIME=\"$LEGACY_RUNTIME\"|" \
  -e "s|^LOGS=.*$|LOGS=\"$LOGS\"|" \
  -e "s|^EXPECTED_UID=0$|EXPECTED_UID=$UID_VALUE|" \
  -e "s|^SERVICE_UID=.*$|SERVICE_UID=$UID_VALUE|" \
  -e 's|/bin/launchctl|/usr/bin/true|g' \
  -e 's|/usr/sbin/pkgutil|/usr/bin/true|g' \
  -e 's|/usr/bin/sudo -u "$SERVICE_ACCOUNT" -- ||' \
  "$ROOT/packaging/macos/uninstall-node-host.sh" > "$SCRIPT"
/bin/chmod 755 "$SCRIPT"

make_layout() {
  /bin/mkdir -p \
    "$BASE/bin" "$BASE/releases/1.0.0" "$BASE/service-state/state" \
    "$BASE/service-state/identity" "$APP" "$(dirname "$PLIST")" \
    "$RUNTIME" "$LEGACY_RUNTIME" "$LOGS"
  /bin/ln -s releases/1.0.0 "$BASE/current"
  printf 'plist\n' > "$PLIST"
  printf 'identity\n' > "$BASE/service-state/identity/seed"
  printf 'log\n' > "$LOGS/service.log"
  printf 'binary\n' > "$BASE/releases/1.0.0/xray"
}

make_layout
printf 'database\n' > "$BASE/service-state/state/node-host.sqlite3"
"$SCRIPT" --preserve-data
[ -f "$BASE/service-state/state/node-host.sqlite3" ]
[ -f "$BASE/service-state/identity/seed" ]
[ -f "$LOGS/service.log" ]
[ ! -e "$APP" ]
[ ! -e "$PLIST" ]
[ ! -e "$RUNTIME" ]
[ ! -e "$LEGACY_RUNTIME" ]
[ ! -e "$BASE/current" ]
[ ! -e "$BASE/releases" ]
[ ! -e "$BASE/bin" ]

/bin/mkdir -p "$BASE/bin" "$BASE/releases/1.0.0"
/bin/ln -s releases/1.0.0 "$BASE/current"
cat > "$BASE/releases/1.0.0/node-host" <<SH
#!/bin/sh
[ "\$1" = uninstall ]
[ "\$2" = --data-dir ]
[ "\$3" = "$BASE/service-state/state" ]
[ "\$4" = --confirm-node-id ]
[ "\$5" = "$NODE_ID" ]
/bin/rm -rf "$BASE/service-state/state" "$BASE/service-state/identity"
SH
/bin/chmod 755 "$BASE/releases/1.0.0/node-host"
"$SCRIPT" --purge-data --confirm-node-id "$NODE_ID"
[ ! -e "$BASE" ]
[ ! -e "$LOGS" ]

make_layout
"$SCRIPT" --purge-data --confirm-unpaired
[ ! -e "$BASE" ]
[ ! -e "$LOGS" ]

/bin/mkdir -p "$(dirname "$APP")" "$WORK/unsafe-target"
/bin/ln -s "$WORK/unsafe-target" "$APP"
if "$SCRIPT" --preserve-data >/dev/null 2>&1; then
  echo "symlinked application path was accepted" >&2
  exit 1
fi
[ -d "$WORK/unsafe-target" ]

/bin/rm -f "$APP"
make_layout
/bin/rm -rf "$BASE/service-state/state/node-host.sqlite3"
/bin/ln -s "$WORK/unsafe-target/database" "$BASE/service-state/state/node-host.sqlite3"
if "$SCRIPT" --purge-data --confirm-node-id "$NODE_ID" >/dev/null 2>&1; then
  echo "symlinked state database was accepted" >&2
  exit 1
fi
[ -d "$WORK/unsafe-target" ]

echo "macOS Node Host uninstall choices passed"
