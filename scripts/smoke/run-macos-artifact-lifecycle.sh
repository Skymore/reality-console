#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 5 ]]; then
  echo "usage: $0 ARTIFACT TARGET MODE SIGNATURE_JSON LIFECYCLE_JSON" >&2
  exit 64
fi

artifact=$1
target=$2
mode=$3
signature_output=$4
lifecycle_output=$5
root=$(cd "$(dirname "$0")/../.." && pwd)
work=$(mktemp -d)
mount=
installed=
cleanup() {
  if [[ -n "$mount" ]]; then hdiutil detach "$mount" -force >/dev/null 2>&1 || true; fi
  if [[ "$target" == node-host-macos-* ]]; then
    sudo launchctl bootout system/com.sky.realitynode.agent >/dev/null 2>&1 || true
    sudo rm -f /Library/LaunchDaemons/com.sky.realitynode.agent.plist
    sudo rm -rf "/Applications/Private Network Node.app" "/Library/Application Support/Private Network Node"
  elif [[ -n "$installed" ]]; then
    sudo rm -rf "$installed" || true
  fi
  rm -rf "$work"
}
trap cleanup EXIT INT TERM

[[ "$mode" == release || "$mode" == validation ]] || { echo "invalid lifecycle mode" >&2; exit 64; }
[[ -f "$artifact" ]] || { echo "actual package is missing" >&2; exit 66; }

verify_inner() {
  local directory=$1 signer= file_info
  while IFS= read -r -d '' candidate; do
    file_info=$(file -b "$candidate")
    if [[ "$file_info" == *Mach-O* ]]; then
      codesign --verify --strict --verbose=2 "$candidate"
      current=$(codesign -d --verbose=4 "$candidate" 2>&1 | sed -n 's/^Authority=//p' | head -1)
      [[ -n "$current" ]] || { echo "signed inner binary has no signing authority: $candidate" >&2; return 1; }
      if [[ -n "$signer" && "$current" != "$signer" ]]; then
        echo "inner binary signing identity mismatch: $candidate" >&2
        return 1
      fi
      signer=$current
    fi
  done < <(find "$directory" -type f -print0)
  [[ -n "$signer" ]] || { echo "package contains no signed Mach-O binaries" >&2; return 1; }
  printf '%s\n' "$signer"
}

status=unsigned-validation
artifact_signer=
installer_signer=
clean_result=incomplete
artifact_sha=$(shasum -a 256 "$artifact" | awk '{print $1}')

if [[ "$artifact" == *.dmg ]]; then
  if [[ "$mode" == release ]]; then
    spctl --assess --type open --context context:primary-signature -vv "$artifact"
  fi
  mount=$(hdiutil attach "$artifact" -readonly -nobrowse -plist | \
    python3 -c 'import plistlib,sys; print(next(x["mount-point"] for x in plistlib.load(sys.stdin.buffer)["system-entities"] if "mount-point" in x))')
  app=$(find "$mount" -maxdepth 2 -name '*.app' -type d -print -quit)
  [[ -n "$app" ]] || { echo "DMG contains no application" >&2; exit 65; }
  if [[ "$mode" == release ]]; then
    codesign --verify --deep --strict --verbose=2 "$app"
    spctl --assess --type execute -vv "$app"
    artifact_signer=$(verify_inner "$app")
    installed="/Applications/$(basename "$app")"
    sudo ditto "$app" "$installed"
    codesign --verify --deep --strict --verbose=2 "$installed"
    verify_inner "$installed" >/dev/null
    installer_signer=$artifact_signer
    status=verified
    clean_result=passed
  fi
elif [[ "$artifact" == *.pkg ]]; then
  pkgutil --expand-full "$artifact" "$work/expanded"
  if [[ "$mode" == release ]]; then
    spctl --assess --type install -vv "$artifact"
    signature=$(pkgutil --check-signature "$artifact")
    installer_signer=$(printf '%s\n' "$signature" | sed -n 's/^[[:space:]]*1\. //p' | head -1)
    [[ -n "$installer_signer" ]] || { echo "installer signing identity is missing" >&2; exit 65; }
    artifact_signer=$(verify_inner "$work/expanded")
    sudo installer -pkg "$artifact" -target /
    installed="/Library/Application Support/Private Network Node"
    verify_inner "$installed" >/dev/null
    status=verified
    clean_result=passed
  fi
else
  echo "unsupported macOS package type" >&2
  exit 64
fi

python3 - "$signature_output" "$target" "$(basename "$artifact")" "$artifact_sha" "$artifact_signer" "$installer_signer" "$status" <<'PY'
import json, pathlib, sys
path, target, artifact_name, artifact_sha256, artifact_signer, installer_signer, status = sys.argv[1:]
value = {
    "schemaVersion": 1,
    "kind": "signature-verification",
    "target": target,
    "artifact": {"name": artifact_name, "sha256": artifact_sha256},
    "artifactSigner": artifact_signer or None,
    "installerSigner": installer_signer or None,
    "status": status,
}
pathlib.Path(path).write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")
PY

python3 "$root/scripts/release/write-lifecycle-evidence.py" \
  --artifact "$artifact" \
  --target "$target" \
  --source-commit "${GITHUB_SHA:?GITHUB_SHA is required}" \
  --result "clean-install-signature=$clean_result" \
  --repository "${GITHUB_REPOSITORY:?GITHUB_REPOSITORY is required}" \
  --workflow "${GITHUB_WORKFLOW_REF:?GITHUB_WORKFLOW_REF is required}" \
  --run-id "${GITHUB_RUN_ID:?GITHUB_RUN_ID is required}" \
  --run-attempt "${GITHUB_RUN_ATTEMPT:?GITHUB_RUN_ATTEMPT is required}" \
  --job "artifact-lifecycle ($target)" \
  --output "$lifecycle_output"
