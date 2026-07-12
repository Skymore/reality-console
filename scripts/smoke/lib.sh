#!/bin/sh
set -eu

die() { echo "$*" >&2; exit 1; }

valid_version() {
  case "$1" in
    ''|*[!0-9A-Za-z.+-]*) return 1 ;;
    *) return 0 ;;
  esac
}

digest() {
  if command -v shasum >/dev/null 2>&1; then shasum -a 256 "$1" | awk '{print $1}'
  else sha256sum "$1" | awk '{print $1}'
  fi
}

verify_payload() {
  payload=$1
  [ -f "$payload/node-host" ] || die "payload node-host is missing"
  [ -f "$payload/xray" ] || die "payload xray is missing"
  [ -f "$payload/SHA256SUMS" ] || die "payload checksums are missing"
  while read -r expected name; do
    [ "$name" = node-host ] || [ "$name" = xray ] || die "unexpected payload checksum entry"
    [ "$(digest "$payload/$name")" = "$expected" ] || die "payload checksum mismatch: $name"
  done < "$payload/SHA256SUMS"
}

install_release() {
  root=$1 payload=$2 version=$3
  valid_version "$version" || die "invalid release version"
  verify_payload "$payload"
  releases="$root/releases"
  target="$releases/$version"
  [ ! -e "$target" ] || die "release version already exists"
  mkdir -p "$releases" "$root/state"
  staging="$releases/.install-$version-$$"
  trap 'rm -rf "$staging"' EXIT INT TERM
  mkdir "$staging"
  cp "$payload/node-host" "$payload/xray" "$payload/SHA256SUMS" "$staging/"
  chmod 755 "$staging/node-host" "$staging/xray"
  mv "$staging" "$target"
  trap - EXIT INT TERM
}

switch_current() {
  root=$1 version=$2
  [ -d "$root/releases/$version" ] || die "release target does not exist"
  python3 - "$root" "$version" <<'PY'
import os
import pathlib
import sys

root = pathlib.Path(sys.argv[1])
temporary = root / f".current-{os.getpid()}"
temporary.symlink_to(f"releases/{sys.argv[2]}")
os.replace(temporary, root / "current")
PY
}

current_target() {
  root=$1
  [ -L "$root/current" ] || die "current release is missing"
  target=$(readlink "$root/current")
  case "$target" in releases/*) printf '%s\n' "$target" ;; *) die "unsafe current release link" ;; esac
}
