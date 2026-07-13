#!/bin/sh
set -eu
export COPYFILE_DISABLE=1

usage() {
  echo "usage: $0 --app APP --agent AGENT --xray XRAY --target TARGET --version VERSION --output DIR" >&2
  exit 64
}

APP=
AGENT=
XRAY=
VERSION=
OUTPUT=
TARGET=
while [ "$#" -gt 0 ]; do
  case "$1" in
    --app) APP=${2-}; shift 2 ;;
    --agent) AGENT=${2-}; shift 2 ;;
    --xray) XRAY=${2-}; shift 2 ;;
    --target) TARGET=${2-}; shift 2 ;;
    --version) VERSION=${2-}; shift 2 ;;
    --output) OUTPUT=${2-}; shift 2 ;;
    *) usage ;;
  esac
done
[ -d "$APP" ] && [ -f "$AGENT" ] && [ -f "$XRAY" ] && [ -n "$TARGET" ] && [ -n "$VERSION" ] && [ -n "$OUTPUT" ] || usage

ROOT=$(CDPATH= cd -- "$(dirname "$0")/../.." && pwd)
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT INT TERM
PAYLOAD="$WORK/payload"
PKG_SCRIPTS="$WORK/scripts"
BASE="$PAYLOAD/Library/Application Support/Private Network Node"
NODE_VERSION=$(python3 -c 'import pathlib,tomllib; print(tomllib.loads(pathlib.Path("'"$ROOT"'/node-host/Cargo.toml").read_text())["package"]["version"])')
python3 "$ROOT/scripts/release/verify-sidecars.py" --target "$TARGET" --xray "$XRAY" --node-host "$AGENT" --node-host-version "$NODE_VERSION" --output "$WORK/sidecars.json"
if [ "${REQUIRE_SIGNING:-0}" = 1 ]; then
  /usr/bin/codesign --verify --strict --verbose=2 "$APP"
  /usr/bin/codesign --verify --strict --verbose=2 "$AGENT"
  /usr/bin/codesign --verify --strict --verbose=2 "$XRAY"
fi
mkdir -p "$PAYLOAD/Applications" "$BASE/bin" "$BASE/releases/$VERSION" "$PAYLOAD/Library/LaunchDaemons" "$PKG_SCRIPTS" "$OUTPUT"
# Copy the signed bundle without host-local xattrs. Those attributes are not
# part of the code signature and pkgbuild would encode them as AppleDouble files.
/usr/bin/ditto --norsrc --noextattr --noacl --noqtn "$APP" "$PAYLOAD/Applications/Private Network Node.app"
install -m 755 "$AGENT" "$BASE/releases/$VERSION/node-host"
install -m 755 "$XRAY" "$BASE/releases/$VERSION/xray"
install -m 644 "$WORK/sidecars.json" "$BASE/releases/$VERSION/sidecars.json"
install -m 755 "$ROOT/packaging/macos/reality-node-service" "$BASE/bin/reality-node-service"
install -m 755 "$ROOT/packaging/macos/uninstall-node-host.sh" "$BASE/bin/private-network-node-uninstall"
ln -s "releases/$VERSION" "$BASE/current"
install -m 644 "$ROOT/packaging/macos/com.sky.realitynode.agent.plist" "$PAYLOAD/Library/LaunchDaemons/com.sky.realitynode.agent.plist"
# Copy script bytes instead of metadata so Finder/provenance xattrs cannot become AppleDouble files.
/bin/cat "$ROOT/packaging/macos/pkg-scripts/preinstall" > "$PKG_SCRIPTS/preinstall"
/bin/cat "$ROOT/packaging/macos/pkg-scripts/postinstall" > "$PKG_SCRIPTS/postinstall"
/bin/cat "$ROOT/packaging/macos/pkg-scripts/service-state-rollback" > "$PKG_SCRIPTS/service-state-rollback"
/bin/chmod 755 "$PKG_SCRIPTS/preinstall" "$PKG_SCRIPTS/postinstall" "$PKG_SCRIPTS/service-state-rollback"

# Provenance and Finder xattrs become AppleDouble `._*` payload entries when
# pkgbuild archives the tree. Release packages carry only normal files and the
# embedded Mach-O signatures, never host-local metadata sidecars.
/usr/bin/xattr -cr "$PAYLOAD"
provenance_paths=$(/usr/bin/xattr -lr "$PAYLOAD" 2>/dev/null | /usr/bin/sed -n 's/: com\.apple\.provenance:.*//p')
if [ -n "$provenance_paths" ]; then
  printf 'build host retains protected com.apple.provenance metadata; refusing a polluted package:\n%s\n' "$provenance_paths" >&2
  exit 65
fi
if /usr/bin/find "$PAYLOAD" -name '._*' -print -quit | /usr/bin/grep -q .; then
  echo "payload contains an AppleDouble metadata file" >&2
  exit 65
fi

PKG="$OUTPUT/private-network-node-$VERSION-$TARGET-unsigned-validation.pkg"
/usr/bin/pkgbuild \
  --root "$PAYLOAD" \
  --scripts "$PKG_SCRIPTS" \
  --identifier com.sky.realitynode.pkg \
  --version "$VERSION" \
  --install-location / \
  "$PKG"

appledouble=$(/usr/sbin/pkgutil --payload-files "$PKG" | /usr/bin/grep -E '(^|/)\._' || true)
if [ -n "$appledouble" ]; then
  /bin/rm -f "$PKG"
  printf 'package contains AppleDouble metadata files:\n%s\n' "$appledouble" >&2
  exit 65
fi

if [ -n "${MACOS_INSTALLER_IDENTITY:-}" ]; then
  SIGNED="$OUTPUT/private-network-node-$VERSION-$TARGET.pkg"
  /usr/bin/productsign --sign "$MACOS_INSTALLER_IDENTITY" "$PKG" "$SIGNED"
  /usr/sbin/pkgutil --check-signature "$SIGNED"
  rm -f "$PKG"
  printf '%s\n' "$SIGNED"
elif [ "${REQUIRE_SIGNING:-0}" = 1 ]; then
  echo "MACOS_INSTALLER_IDENTITY is required for a signed release" >&2
  exit 78
else
  echo "created explicitly unsigned validation package: $PKG" >&2
  printf '%s\n' "$PKG"
fi
