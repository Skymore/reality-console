# Release Acceptance

Status: authoritative evidence contract for the first complete private-network release.

This document turns the numbered acceptance criteria in `REQUIREMENTS.md` into reproducible
evidence. A green unit test, a successful local build, or an unsigned development bundle is not a
release by itself. The release is accepted only when one immutable source revision and one release
manifest satisfy every required row below.

## 1. Release Identity

Every candidate records:

- source commit and clean-tree state;
- Control, protocol, Xray runtime, Node Host, relay, relay provisioning, Connect, Control app,
  Node Host app, and probe worker versions;
- target OS, architecture, package digest, SBOM digest, and signing identity;
- update-manifest digest and signature;
- database schema and minimum compatible agent/client versions; and
- the CI run IDs and artifact names that produced the evidence.

The evidence manifest is machine-readable JSON, is retained with the release, and contains no
tokens, invitation material, device identifiers, member identifiers, node credentials, endpoint
secrets, REALITY private keys, or generated Xray configuration.

`packaging/release-acceptance-evidence.schema.json` is the closed schema for this record. Unknown
fields are rejected. `scripts/release/acceptance-evidence.py` binds its decision to a canonical
candidate digest over mode, source commit, clean-tree state, release ID, and Git ref. It also
records exact component checks, schema compatibility, release-manifest digest/status, signer
identities bound to the package name and SHA-256, CI run/attempt/job identities,
package/SBOM/metadata digests, and lifecycle matrix results. Evidence from another CI attempt,
partial lifecycle matrix, synthetic package, or mismatched manifest/package digest is rejected.

## 2. Mandatory Component Gates

Each Rust component must pass formatting, all-target tests, warnings-as-errors Clippy, and Rustdoc
warnings-as-errors using its committed lockfile. TypeScript components must pass their committed
test, typecheck, and production-build commands. Database migration tests must start from both an
empty database and the previous release schema.

The mandatory product component set is Control, protocol, Xray runtime, Node Host, relay,
relay provisioning, Connect, Control app, Node Host app, and probe worker. The release-manifest
crate and manifest CLI run the same Rust quality checks as separate release-tooling gates; they are
not mislabeled as shipped product components.

The release job additionally verifies:

1. every embedded Xray asset name, version, and SHA-256 against `client/xray-sidecar.json`;
2. generated packages contain the expected target-specific sidecar and no other executable payload;
   macOS package payloads also contain no AppleDouble metadata sidecars;
3. macOS code-sign verification covers nested executables before notarization and stapling;
4. Windows Authenticode verification covers the installer and installed executables;
5. the SBOM and update manifest describe the exact package digests;
6. missing signing or notarization credentials fail a release job rather than producing a release;
7. pull-request jobs never receive release signing credentials; and
8. logs and uploaded diagnostics pass the repository redaction scan.

Unsigned builds may be retained only as explicitly named development artifacts. They never satisfy
package acceptance and are never published through a production update channel.

Filesystem-only Unix and Windows lifecycle smoke scripts are regression tests, not package
evidence. Lifecycle evidence must identify `evidenceType: actual-package`, pass package-format
validation, and bind every result to the SHA-256 of the downloaded CI build artifact. Renaming or
writing text to `.dmg`, `.pkg`, or `.exe` cannot produce valid evidence.

## 3. End-to-End Topology

The acceptance environment uses one isolated Control instance, two independently enrolled Node
Hosts, one raw TCP relay, and clean Connect installations. At least one node is tested directly and
one through the relay. Tests use disposable accounts, devices, ports, databases, credential-store
namespaces, proxy settings, and service labels.

```text
Connect A ---- direct ----> Node A ----> test origin
Connect A ---- relay  ----> Node B ----> test origin
                   |
Control <----------+---- outbound-only node/control sessions
```

No acceptance step may read or mutate the operator's live Xray configuration, live router mapping,
normal Keychain namespace, normal system-proxy state, production Control database, or an existing
Node Host installation. Validation-mode artifact inspection must not invoke privileged install or
cleanup commands; release lifecycle jobs run only on disposable clean hosts.

## 4. Product Acceptance Matrix

| Requirement | Required evidence |
| --- | --- |
| Operator creates account and node invitation | Admin API integration test proves idempotent creation, one-time delivery, audit records, and no secret in ordinary list/status responses. |
| One-action clean Node Host enrollment | Package smoke test installs without Docker, consumes one setup link/code, verifies bundled Xray, enrolls through outbound HTTPS, applies the initial revision, and survives service restart. |
| Deterministic direct and relay readiness | Direct endpoint publication requires a successful protocol-aware VLESS + REALITY canary for the exact applied revision. Relay publication requires an authenticated active route. TCP-only success is retained as diagnostics but never marks either path shareable. |
| Connect receives at least two nodes | A clean activated Connect verifies and caches one signed encrypted bundle containing the direct and relay profiles, selects each path, and reaches the test origin without URI import. |
| Cross-node disable | Disabling the account atomically revokes sessions, publishes removal on both nodes, prevents bundle refresh, and leaves no accepted credential after both nodes converge. |
| Bad revision rollback | A deliberately invalid and a crash-after-activation candidate both preserve or restore the prior serving revision, report stable terminal results, and pause only the affected standard rollout. |
| Offline behavior | After Control is stopped, both nodes retain last-known-good service and Connect uses only its unexpired cache. Fresh activation and refresh fail closed. Expiry stops app-managed Xray and restores app-owned proxy state. |
| Idempotent multi-node usage | Retried and out-of-order telemetry batches never double count. Reconciliation of raw accepted sequences equals per-user, per-node, and time-bucket aggregates. Retention removes only records older than the configured class deadline. |
| Release packages | Signed macOS Apple Silicon and Intel Connect packages, signed Windows x64 Connect installer, and signed/notarized macOS Node Host package pass the lifecycle matrix in section 5. |

## 5. Package Lifecycle Matrix

Every supported package runs these isolated smoke scenarios:

| Scenario | Connect macOS arm64 | Connect macOS x64 | Connect Windows x64 | Node Host macOS arm64 | Node Host macOS x64 |
| --- | --- | --- | --- | --- | --- |
| clean install and signature verification | required | required | required | required | required |
| one-action activation/enrollment | required | required | required | required | required |
| direct path | required | required | required | required | required |
| relay path and independent failure | required | required | required | required | required |
| offline restart | required | required | required | required | required |
| sleep/wake or service restart | required | required | required | required | required |
| in-place upgrade with state preservation | required | required | required | required | required |
| failed update rollback | required | required | required | required | required |
| logout/removal and proxy/service cleanup | required | required | required | required | required |
| uninstall with explicit data-retention choice | required | required | required | required | required |

Windows and Intel macOS evidence must come from matching CI runners or matching clean machines. A
cross-compile check from Apple Silicon is useful compiler evidence but does not satisfy package,
signature, installation, proxy, service, sleep, or uninstall behavior.

Connect network evidence is collected from the installed executable with
`scripts/smoke/run-connect-network-scenario.py`. The coordinator prepares a disposable Control
instance, one direct node, one independently routed relay node, a fixed test origin, and a one-time
Connect setup code. It then runs `online`, stops Control and runs `offline`, restores Control,
independently withdraws the direct and relay paths for `direct-failed` and `relay-failed`, restores
both paths, and runs `logout`. The setup code is supplied only on stdin. Every other mode accepts
empty stdin.
Every proof binds the source commit, CI run attempt, release target, package SHA-256, and installed
binary SHA-256. `write-lifecycle-evidence.py --network-proof ...` rejects a proof from another
candidate, package, packaged main binary, target, CI job, or CI attempt. The platform lifecycle
recomputes the main-binary digest from the mounted DMG or installed Windows directory rather than
trusting the scenario command line. The current online proof satisfies activation/enrollment
and direct-path only; merely reaching a relay does not satisfy relay-path isolation because that row
also requires an independently injected route failure.

The five proof filenames are fixed as `<target>.<mode>.network.json` for `online`, `offline`,
`direct-failed`, `relay-failed`, and `logout`. After the coordinator restores a clean
installed-package state, it
sets `CONNECT_NETWORK_PROOF_DIR` when invoking the platform artifact lifecycle script. Supplying the
directory is all-or-nothing: a missing mode fails the job. The lifecycle script copies the proof
bytes into its uploaded evidence directory before importing them; the acceptance aggregator locates
those bytes again and independently verifies their digest and candidate identity.

`run-connect-network-acceptance.py` implements the coordinator sequence. Its hook file is a closed
schema of bounded argument arrays, never shell command strings, and contains no setup code. Hooks
must be idempotent release-lab controls for readiness, Control stop/start, direct disable/enable,
relay disable/enable, and final cleanup. Cleanup runs after success or failure; the setup code is
read once from stdin and forwarded only to the `online` child. The proof directory must be a new
absolute directory so a previous run cannot be mistaken for the current candidate.

Node Host packages use `run-node-host-network-acceptance.py` against the installed agent's closed
`system-control` interface. It consumes the invitation only on stdin, waits until the exact applied
revision has both direct and relay protocol-verification evidence and a registered relay, then
restarts the service with Control stopped and requires a new service-instance ID with the same node
and applied revision. Release-lab hooks independently withdraw and probe each path, restore both,
and final unpair must return an unpaired secret-free status. The four `online`, `offline-restart`,
`isolation`, and `logout` proof files contain no node ID, invitation, endpoint, or policy contents.
`NODE_HOST_NETWORK_PROOF_DIR` imports all four or fails; the package lifecycle recomputes the agent
SHA-256 from the installed `.pkg` payload before accepting them.

## 6. Failure Isolation

The matrix deliberately injects these failures and records only stable error codes and timing:

- Control unavailable during heartbeat, telemetry upload, activation, refresh, and logout;
- direct node unreachable while relay node remains healthy, and the inverse;
- relay route revoked while an unrelated route remains active;
- Xray validation failure, immediate exit, stabilization exit, and occupied public/listener port;
- duplicate, missing, stale, tampered, and wrong-node desired state;
- duplicate, stale, overlapping, and gapped telemetry batches;
- bundle signature, HPKE ciphertext, binding, generation, clock, and offline-expiry failures;
- credential-store denial, full disk, interrupted atomic rename, and crash during proxy mutation;
- update signature, product, platform, architecture, version, and digest mismatch; and
- backup corruption and restore to a controller instance with conflicting identity.

A failure in one direct node or relay route must not disable unrelated nodes. Control failure must
not terminate an established data plane. Security revocation may reduce access immediately and is
not rolled back by availability recovery.

## 7. Backup, Restore, And Rotation Evidence

Control backup evidence proves a transactionally consistent database plus separately encrypted
controller signing material can restore into a new empty data directory. Restore verifies schema,
manifest, digests, file ownership, controller instance intent, and an explicit rollback barrier
before opening network listeners.

Node backup evidence distinguishes recoverable operational state from the node-local REALITY
private key. A controller-only backup never claims it can reconstruct that key. Key or runtime
rotation uses an overlap window, publishes a new immutable revision/bundle, proves health, and only
then retires the predecessor. Interrupted rotation resumes from durable state.

Uninstall stops owned processes and services, releases owned router mappings, restores owned proxy
state, and removes executable/runtime files. Destructive identity or telemetry deletion requires a
separate explicit choice and is tested independently from ordinary uninstall.

The macOS Node Host artifact lifecycle writes service-owned sentinels after clean package install,
runs the packaged preserve-data uninstaller, reinstalls the exact same artifact and proves the
sentinels survived, then runs the explicit unpaired purge and proves application, runtime, state,
log, and receipt-owned paths were removed. Source-level tests separately prove exact-ID confirmation
for purging paired state and reject symlinked fixed paths before deletion.

## 8. Support Bundle Evidence

Support bundles are generated from an allowlist, are size bounded, and contain only versions,
stable error codes, state transitions, request IDs, revision numbers, safe timing, and redacted
health summaries. Tests seed every secret class and fail if the archive contains any raw token,
password, invitation, URI, UUID credential, private key, bundle payload, generated configuration,
full destination URL, or ordinary member/device identifier.

The operator previews the inventory before export. Collection never reads browser storage, the
system credential store, arbitrary files, payload logs, or live process memory.

## 9. Acceptance Decision

The release job emits one of three states:

- `accepted`: every required row has matching immutable evidence;
- `rejected`: one or more required checks failed; or
- `incomplete`: evidence is missing, skipped, unsigned, from the wrong platform, or cannot be tied
  to the candidate source and package digests.

`incomplete` is not success. Manual exceptions may document a private development build, but they
cannot relabel it as the first complete release.

Branch and pull-request validation runs preserve the complete build and evidence path but are
unconditionally `incomplete`, even if every locally available check passes. On a tag, `publish`
downloads the acceptance record, component/lifecycle records, manifest evidence, and package bytes
again, recomputes the candidate binding and all package/SBOM/metadata digests, requires `accepted`,
and verifies the source commit, CI attempt, and release ID. Missing, malformed, rejected,
incomplete, or byte-mismatched evidence fails before release creation.
