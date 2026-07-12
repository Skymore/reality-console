#!/bin/sh
set -eu

BASE="/Library/Application Support/Private Network Node"
SERVICE_STATE="$BASE/service-state"
STATE="$SERVICE_STATE/state"
APP="/Applications/Private Network Node.app"
PLIST="/Library/LaunchDaemons/com.sky.realitynode.agent.plist"
RUNTIME="/var/run/private-network-node"
LOGS="/Library/Logs/Private Network Node"
RECEIPT="com.sky.realitynode.pkg"
EXPECTED_UID=0
SERVICE_ACCOUNT="_privnetnode"

usage() {
  echo "usage: $0 --preserve-data | --purge-data (--confirm-node-id UUID | --confirm-unpaired)" >&2
  exit 64
}

fail() {
  echo "Private Network Node uninstall: $*" >&2
  exit 70
}

[ "$(/usr/bin/id -u)" = "$EXPECTED_UID" ] || { echo "run as root" >&2; exit 77; }
SERVICE_UID=$(/usr/bin/id -u "$SERVICE_ACCOUNT" 2>/dev/null) || fail "service account is missing"

mode=${1-}
confirmation=${2-}
confirmed_node_id=${3-}
case "$mode" in
  --preserve-data)
    [ "$#" -eq 1 ] || usage
    ;;
  --purge-data)
    [ "$#" -eq 2 ] || [ "$#" -eq 3 ] || usage
    case "$confirmation" in
      --confirm-unpaired) [ "$#" -eq 2 ] || usage ;;
      --confirm-node-id)
        [ "$#" -eq 3 ] || usage
        printf '%s\n' "$confirmed_node_id" | /usr/bin/grep -Eq \
          '^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$' || usage
        ;;
      *) usage ;;
    esac
    ;;
  *) usage ;;
esac

validate_directory() {
  path=$1
  owner=$2
  [ ! -e "$path" ] && return 0
  [ -d "$path" ] && [ ! -L "$path" ] || fail "unsafe directory: $path"
  [ "$(/usr/bin/stat -f '%u' "$path")" = "$owner" ] || fail "unexpected owner: $path"
}

validate_regular_file() {
  path=$1
  owner=$2
  [ ! -e "$path" ] && return 0
  [ -f "$path" ] && [ ! -L "$path" ] || fail "unsafe file: $path"
  [ "$(/usr/bin/stat -f '%u' "$path")" = "$owner" ] || fail "unexpected owner: $path"
}

validate_directory "$BASE" "$EXPECTED_UID"
validate_directory "$BASE/bin" "$EXPECTED_UID"
validate_directory "$BASE/releases" "$EXPECTED_UID"
validate_directory "$SERVICE_STATE" "$SERVICE_UID"
validate_directory "$STATE" "$SERVICE_UID"
validate_directory "$SERVICE_STATE/identity" "$SERVICE_UID"
validate_directory "$APP" "$EXPECTED_UID"
validate_directory "$RUNTIME" "$EXPECTED_UID"
validate_directory "$LOGS" "$SERVICE_UID"
validate_regular_file "$PLIST" "$EXPECTED_UID"

if [ -e "$BASE/current" ] || [ -L "$BASE/current" ]; then
  [ -L "$BASE/current" ] || fail "current release pointer is not a symlink"
  current=$(/usr/bin/readlink "$BASE/current")
  case "$current" in
    releases/*)
      release=${current#releases/}
      case "$release" in ''|*/*|*[!A-Za-z0-9._-]*) fail "current release pointer is unsafe" ;; esac
      ;;
    *) fail "current release pointer is unsafe" ;;
  esac
fi

if [ "$mode" = --purge-data ]; then
  if [ -f "$STATE/node-host.sqlite3" ]; then
    [ "$confirmation" = --confirm-node-id ] || fail "paired state requires --confirm-node-id"
    validate_regular_file "$STATE/node-host.sqlite3" "$SERVICE_UID"
    agent="$BASE/current/node-host"
    validate_regular_file "$agent" "$EXPECTED_UID"
    [ -x "$agent" ] || fail "installed Node Host agent is unavailable"
  else
    [ "$confirmation" = --confirm-unpaired ] || fail "unpaired state requires --confirm-unpaired"
  fi
fi

/bin/launchctl bootout system/com.sky.realitynode.agent >/dev/null 2>&1 || true

if [ "$mode" = --purge-data ] && [ -f "$STATE/node-host.sqlite3" ]; then
  /usr/bin/sudo -u "$SERVICE_ACCOUNT" -- \
    "$BASE/current/node-host" uninstall --data-dir "$STATE" --confirm-node-id "$confirmed_node_id"
fi

/bin/rm -f "$PLIST"
/bin/rm -rf "$APP" "$RUNTIME"
/bin/rm -f "$BASE/current"
/bin/rm -rf "$BASE/bin" "$BASE/releases"

if [ "$mode" = --purge-data ]; then
  /bin/rm -rf "$SERVICE_STATE" "$LOGS"
fi

/usr/sbin/pkgutil --forget "$RECEIPT" >/dev/null 2>&1 || true
/bin/rmdir "$BASE" >/dev/null 2>&1 || true

if [ "$mode" = --preserve-data ]; then
  echo "Private Network Node removed; state and logs were preserved."
else
  echo "Private Network Node and local state removed."
fi
