#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname "$0")/../../.." && pwd)
WORK=$(mktemp -d)
cleanup() {
  /bin/rm -rf "$WORK"
}
trap cleanup EXIT INT TERM

/bin/mkdir -p "$WORK/payload/usr/local/share/private-network-validation" "$WORK/fake-bin"
printf 'validation fixture\n' > "$WORK/payload/usr/local/share/private-network-validation/fixture.txt"
/usr/bin/pkgbuild \
  --root "$WORK/payload" \
  --identifier com.sky.private-network.validation \
  --version 0.0.0 \
  --install-location / \
  "$WORK/validation.pkg" >/dev/null

cat > "$WORK/fake-bin/sudo" <<'SH'
#!/bin/sh
printf 'sudo was invoked: %s\n' "$*" > "$PRIVILEGED_MARKER"
exit 99
SH
/bin/chmod 755 "$WORK/fake-bin/sudo"

PRIVILEGED_MARKER="$WORK/privileged-command"
export PRIVILEGED_MARKER
PATH="$WORK/fake-bin:$PATH" \
GITHUB_SHA=1111111111111111111111111111111111111111 \
GITHUB_REPOSITORY=example/private-network \
GITHUB_WORKFLOW_REF=example/private-network/.github/workflows/release-build.yml@refs/heads/main \
GITHUB_RUN_ID=1 \
GITHUB_RUN_ATTEMPT=1 \
  "$ROOT/scripts/smoke/run-macos-artifact-lifecycle.sh" \
    "$WORK/validation.pkg" \
    node-host-macos-aarch64 \
    validation \
    "$WORK/signature.json" \
    "$WORK/lifecycle.json"

[ ! -e "$PRIVILEGED_MARKER" ]
python3 - "$WORK/signature.json" "$WORK/lifecycle.json" <<'PY'
import json
import pathlib
import sys

signature = json.loads(pathlib.Path(sys.argv[1]).read_text())
lifecycle = json.loads(pathlib.Path(sys.argv[2]).read_text())
assert signature["status"] == "unsigned-validation"
assert lifecycle["evidenceType"] == "actual-package"
assert lifecycle["results"]["clean-install-signature"] == "incomplete"
assert lifecycle["results"]["uninstall-retention-choice"] == "incomplete"
PY

echo "validation lifecycle remained nonprivileged"
