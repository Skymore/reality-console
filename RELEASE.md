# Release And Installation Foundation

Status: Stage 6 release evidence and gating. This document describes executable build, lifecycle,
and candidate-bound evidence assets. It does not claim that unsigned validation artifacts are
production releases.

## Supported Build Matrix

The pinned matrix lives in `.github/workflows/release-build.yml` and `packaging/release-config.json`:

| Product | Platform | Architecture | CI output |
| --- | --- | --- | --- |
| Connect | macOS | Apple Silicon | `.dmg` |
| Connect | macOS | Intel | `.dmg` |
| Connect | Windows | x86_64 | NSIS `.exe` |
| Node Host | macOS | Apple Silicon | system-service `.pkg` |
| Node Host | macOS | Intel | system-service `.pkg` |

Node Host Windows and Linux service definitions are installation assets, not release-matrix
packages yet. Windows uses the pinned WinSW wrapper. Linux uses a hardened `systemd` unit.

Rust `1.88.0`, Node `22.17.0`, Tauri CLI `2.11.4`, Xray `26.3.27`, upstream archive SHA-256,
and extracted executable SHA-256 are fixed in release configuration or lock files. CI actions are
referenced by immutable commit SHA.

## Trust And Signing

`crates/release-manifest` is the authority for manifest fields, canonical transcripts, update
policy, byte verification, and separate rollback authorization. CI applies fmt, test, strict
Clippy, and strict Rustdoc gates to that crate and to `scripts/release-manifest-tool`.

`packaging/release-trust.json` is deliberately marked `productionReady: false`. Its current public
keys are non-production placeholders whose private keys were not retained. Before the first signed
release, replace them through review with real offline release and independently controlled
rollback public keys, then set `productionReady` to true. Never put either private key in this
repository.

The release manifest tool behaves as follows:

- `generate` computes package length/SHA-256 and SBOM SHA-256, builds the exact
  `ReleaseManifest`, and validates every package byte stream with `verify_artifact`.
- With a release private key, `generate` signs the crate-provided domain-separated transcript and
  immediately verifies it through the pinned `ReleaseTrustStore` before atomically writing output.
- `verify` independently calls `ReleaseTrustStore::verify_update` and `verify_artifact` for every
  emitted artifact.
- `authorize-rollback` uses the independent rollback transcript and key environment. Ordinary
  releases do not need or receive rollback authorization.
- With `REQUIRE_SIGNING=1`, missing keys, unpinned key IDs, placeholder trust, partial platform
  credentials, signature failure, or artifact mismatch removes/withholds final manifest output.
- Without signing credentials, validation emits a raw unsigned manifest plus evidence containing
  `signatureStatus: unsigned-validation`; it never emits an empty or fabricated signature.

Protected release environments provide these values:

- `RELEASE_SIGNING_KEY_ID`, `RELEASE_SIGNING_PRIVATE_KEY` (32-byte Ed25519 seed, unpadded base64url)
- `APPLE_CERTIFICATE`, `APPLE_CERTIFICATE_PASSWORD`, `APPLE_SIGNING_IDENTITY`
- `APPLE_ID`, `APPLE_PASSWORD`, `APPLE_TEAM_ID`
- `MACOS_INSTALLER_IDENTITY` for the Node Host system `.pkg`
- `WINDOWS_SIGNING_PFX_BASE64`, `WINDOWS_SIGNING_PFX_PASSWORD`
- `ROLLBACK_SIGNING_PRIVATE_KEY` only in the separately approved emergency rollback process

Tag builds require every applicable credential and notarization. Pull requests and branch builds
run the same config/build/SBOM pipeline but upload artifacts explicitly named
`unsigned-validation`. Validation always remains `incomplete`; it cannot be relabeled accepted. A
tag is published only after signed artifact metadata, the signed update manifest, post-generation
trust verification, checksums, and strict acceptance evidence all succeed. The publish job
re-downloads the component, lifecycle, manifest, and package evidence and fail-closed verifies the
same source commit, CI run/attempt, release ID, candidate digest, and package/SBOM/metadata SHA-256
values before creating a release.

## Sidecars And SBOM

Run the target-specific acquisition directly when debugging:

```sh
python3 scripts/release/acquire-sidecar.py \
  --target aarch64-apple-darwin \
  --output /tmp/xray
```

The extractor verifies the complete ZIP, extracts only the exact expected member, bounds its size,
then verifies the executable digest and version. `prepare-sidecars.sh` applies Tauri's target suffix
and records sidecar provenance. Node Host packages re-run this verification before `pkgbuild`.
Windows service packaging acquires WinSW through `acquire-windows-service-wrapper.py` with its own
pinned digest.

`generate-sbom.py` emits deterministic CycloneDX 1.5 JSON from committed Cargo/npm lock files plus
the exact Xray component digest. Each `ReleaseArtifact` carries the package and SBOM digests using
the field names and product/platform/architecture values accepted by `release-manifest`.

## Node Host Service Layout

macOS installs the setup/status app in `/Applications/Private Network Node.app` and immutable agent
releases under `/Library/Application Support/Private Network Node/releases/<version>`. A root-owned
`current` link selects one release. `com.sky.realitynode.agent` runs the fixed service wrapper as
`_privnetnode`; an unpaired installation exits successfully instead of entering a crash loop.
State and logs remain outside release directories. Package upgrade records one previous release
and stops launchd before replacement. The postinstall verifies the installed app, agent, and Xray
sidecar independently. If verification, ownership setup, or launchd bootstrap fails, its exit trap
atomically restores the retained previous `current` symlink before returning failure.

The Tauri app is intentionally a minimal native packaging shell. Its backend can retain a bounded
setup code in process for safe preview/cancel and report only fixed-path package/launchd status. It
does not expose arbitrary shell, path, or network operations. The existing Node Host crate has no
production privileged setup IPC yet, so the shell does not claim that GUI pairing can mutate the
root-owned system state.

Windows installs versioned payloads under `%ProgramFiles%\Private Network Node`, mutable state under
`%ProgramData%\Private Network Node`, and wraps the console agent with WinSW as `LocalService`.
Linux installs immutable payloads under `/opt/private-network-node`, state under
`/var/lib/private-network-node`, and runs as the locked `reality-node` account with a restricted
`systemd` sandbox.

Default uninstall preserves identity/state. Explicit purge removes it. Platform installers always
stop/disable their owned service before removing binaries.

## Local Validation

The macOS-safe validation sequence is:

```sh
python3 -m json.tool packaging/release-config.json >/dev/null
python3 -m json.tool packaging/release-trust.json >/dev/null
python3 -m json.tool packaging/release-acceptance-evidence.schema.json >/dev/null
python3 -m py_compile scripts/release/*.py scripts/release/tests/*.py
bash -n scripts/release/run-component-gate.sh scripts/smoke/run-macos-artifact-lifecycle.sh
find packaging scripts -type f -path '*/pkg-scripts/*' -exec sh -n {} \;
plutil -lint packaging/macos/com.sky.realitynode.agent.plist
scripts/smoke/run-unix-lifecycle.sh
scripts/smoke/release-manifest.sh
python3 -m unittest discover -s scripts/release/tests -v
cargo test --locked --manifest-path crates/release-manifest/Cargo.toml --all-targets
cargo test --locked --manifest-path scripts/release-manifest-tool/Cargo.toml --all-targets
cargo test --locked --manifest-path crates/relay-provisioning/Cargo.toml --all-targets
```

The simulated lifecycle scripts exercise clean install, state-preserving upgrade, bounded
rollback, state-preserving uninstall, and explicit purge in an isolated temporary root. They are
code-level regression tests only and never emit release evidence. The actual-artifact lifecycle
jobs download the produced packages, reject synthetic file bytes, verify installed nested
signatures, and emit candidate-bound evidence. A failed macOS Node Host postinstall restores the
saved `current` target and attempts to restart that restored service before returning failure.
Unexecuted scenarios remain `incomplete`; package switching does not substitute for a cryptographic
rollback grant or real topology evidence.

## Required Release-Lab Validation

The following cannot be proven on the current macOS development machine and remain release gates:

- Windows x86_64 Authenticode credentials and clean-machine NSIS install/upgrade/rollback,
  WinSW lifecycle, reboot recovery, and installed sidecar evidence;
- Linux `systemd` install/upgrade/rollback/uninstall on supported distributions;
- clean Intel macOS package lifecycle evidence on a matching runner or machine;
- Apple Silicon and Intel Developer ID signing, installer signing, notarization, stapling, clean
  install, launchd restart, sleep/wake, upgrade, rollback, and uninstall;
- production release/rollback trust roots and protected-environment key access;
- GUI-to-root privileged setup IPC, firewall mutation, and system-keychain service ACLs;
- end-to-end connection/recovery tests against a real Control Service and external network.

No artifact may be promoted while one of its required platform rows lacks signed release evidence.
