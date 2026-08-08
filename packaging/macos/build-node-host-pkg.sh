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
OUTPUT=$(CDPATH= cd -- "$OUTPUT" && pwd)
# Copy the signed bundle without host-local xattrs. Those attributes are not
# part of the code signature and pkgbuild would encode them as AppleDouble files.
/usr/bin/ditto --norsrc --noextattr --noacl --noqtn "$APP" "$PAYLOAD/Applications/Private Network Node.app"
# Tauri preserves the source sidecar's owner-only mode. Once Installer assigns
# the bundle to root:wheel, the console user must still be able to validate and
# execute the signed embedded sidecar.
/bin/chmod 755 "$PAYLOAD/Applications/Private Network Node.app/Contents/MacOS/xray"
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

# Remove ordinary host metadata where macOS permits it. Protected provenance
# can remain on some managed build hosts, so the generated package is the
# source of truth: it must never contain AppleDouble payload entries.
/usr/bin/xattr -cr "$PAYLOAD"
if /usr/bin/find "$PAYLOAD" -name '._*' -print -quit | /usr/bin/grep -q .; then
  echo "payload contains an AppleDouble metadata file" >&2
  exit 65
fi

PKG="$OUTPUT/private-network-node-$VERSION-$TARGET-unsigned-validation.pkg"
RAW_PKG="$WORK/pkgbuild.pkg"
/usr/bin/pkgbuild \
  --root "$PAYLOAD" \
  --scripts "$PKG_SCRIPTS" \
  --identifier com.sky.realitynode.pkg \
  --version "$VERSION" \
  --install-location / \
  "$RAW_PKG"

appledouble=$(/usr/sbin/pkgutil --payload-files "$RAW_PKG" | /usr/bin/grep -E '(^|/)\._' || true)
if [ -n "$appledouble" ]; then
  if ! command -v docker >/dev/null 2>&1 || ! docker info >/dev/null 2>&1; then
    printf 'pkgbuild encoded protected xattrs as AppleDouble files, and Docker is unavailable for clean assembly:\n%s\n' "$appledouble" >&2
    exit 65
  fi

  COMPONENTS="$WORK/components"
  CLEAN_PARENT="$WORK/clean-components"
  mkdir -p "$COMPONENTS" "$CLEAN_PARENT"
  (
    cd "$COMPONENTS"
    /usr/bin/xar -xf "$RAW_PKG" PackageInfo
  )

  # Build the payload archives directly so host xattrs are never serialized.
  (
    cd "$PAYLOAD"
    /usr/bin/find . -print | LC_ALL=C /usr/bin/sort | COPYFILE_DISABLE=1 /usr/bin/cpio -o -H odc -R 0:0 2>/dev/null | /usr/bin/gzip -9n > "$COMPONENTS/Payload"
  )
  (
    cd "$PKG_SCRIPTS"
    /usr/bin/find . -print | LC_ALL=C /usr/bin/sort | COPYFILE_DISABLE=1 /usr/bin/cpio -o -H odc -R 0:0 2>/dev/null | /usr/bin/gzip -9n > "$COMPONENTS/Scripts"
  )

  # mkbom records source ownership, while installer payloads use root:wheel.
  /usr/bin/mkbom "$PAYLOAD" "$WORK/source.Bom"
  /usr/bin/lsbom "$WORK/source.Bom" | /usr/bin/awk -F '\t' 'BEGIN { OFS = "\t" } { if (NF >= 3) $3 = "0/0"; print }' > "$WORK/root-bom.list"
  /usr/bin/mkbom -i "$WORK/root-bom.list" "$COMPONENTS/Bom"

  payload_files=$(
    cd "$PAYLOAD"
    /usr/bin/find . -print | /usr/bin/wc -l | /usr/bin/tr -d ' '
  )
  install_kbytes=$(/usr/bin/du -skA "$PAYLOAD" | /usr/bin/awk '{ print ($1 > 0 ? $1 - 1 : 0) }')
  /usr/bin/python3 - "$COMPONENTS/PackageInfo" "$payload_files" "$install_kbytes" <<'PY'
import pathlib
import re
import sys

path = pathlib.Path(sys.argv[1])
text = path.read_text()
text, count = re.subn(
    r'<payload numberOfFiles="\d+" installKBytes="\d+"/>',
    f'<payload numberOfFiles="{sys.argv[2]}" installKBytes="{sys.argv[3]}"/>',
    text,
    count=1,
)
if count != 1:
    raise SystemExit("PackageInfo payload metadata was not found")
path.write_text(text)
PY

  # Docker's VM rematerializes the four flat-package components without the
  # protected host provenance attribute. No build tool runs inside the image.
  docker run --rm \
    -v "$COMPONENTS:/input:ro" \
    -v "$CLEAN_PARENT:/output" \
    "${DOCKER_CLEAN_IMAGE:-alpine:3.20}" \
    sh -ceu 'mkdir /output/flat; for name in Bom PackageInfo Payload Scripts; do cat "/input/$name" > "/output/flat/$name"; done'
  CLEAN_COMPONENTS="$CLEAN_PARENT/flat"
  remaining_xattrs=$(/usr/bin/xattr -lr "$CLEAN_COMPONENTS" 2>/dev/null || true)
  if [ -n "$remaining_xattrs" ]; then
    printf 'clean package components still contain extended attributes:\n%s\n' "$remaining_xattrs" >&2
    exit 65
  fi
  (
    cd "$CLEAN_COMPONENTS"
    /usr/bin/xar --compression none -cf "$PKG" Bom Payload Scripts PackageInfo
  )
else
  /bin/mv "$RAW_PKG" "$PKG"
fi

appledouble=$(/usr/sbin/pkgutil --payload-files "$PKG" | /usr/bin/grep -E '(^|/)\._' || true)
if [ -n "$appledouble" ]; then
  /bin/rm -f "$PKG"
  printf 'package contains AppleDouble payload files:\n%s\n' "$appledouble" >&2
  exit 65
fi

VERIFY="$WORK/verify"
mkdir -p "$VERIFY"
(
  cd "$VERIFY"
  /usr/bin/xar -xf "$PKG" Scripts
)
script_appledouble=$(/usr/bin/gzip -dc "$VERIFY/Scripts" | /usr/bin/cpio -it 2>/dev/null | /usr/bin/grep -E '(^|/)\._' || true)
if [ -n "$script_appledouble" ]; then
  /bin/rm -f "$PKG"
  printf 'package contains AppleDouble script files:\n%s\n' "$script_appledouble" >&2
  exit 65
fi
/usr/bin/xar --dump-toc="$WORK/package-toc.xml" -f "$PKG"
if /usr/bin/grep -Eq '<ea([ >])' "$WORK/package-toc.xml"; then
  /bin/rm -f "$PKG"
  echo "package container contains extended attributes" >&2
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
