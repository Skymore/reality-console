# Node Host System Setup

Status: Stage 6 implementation contract.

## Problem

The packaged Node Host uses a dedicated `_privnetnode` LaunchDaemon and a `0700` system state
directory. The desktop application runs as the logged-in provider. It therefore cannot call the
current in-process `confirm_and_install` path or write the daemon state directly. Passing the setup
code to `sudo`, `osascript`, a command line, or a temporary invitation file would violate the secret
transport requirements.

## Ownership

- The signed package owns the agent, Xray sidecar, sidecar manifest, LaunchDaemon definition,
  service account, runtime directory, and system setup socket directory.
- The LaunchDaemon owns Node Host identity, database, runtime configuration, provider policy, and
  enrollment mutations.
- The desktop backend owns the process-local setup session and sends the bearer only over an
  authenticated local socket after renderer confirmation.
- The renderer receives a random session ID, safe preview, provider-policy DTOs, and safe progress.
  It never receives the invitation bearer, package paths, hashes, or persisted identity material.

## macOS Transport

The package starts the daemon in `system-service` mode even before enrollment. `postinstall` creates
`/Library/Application Support/Private Network Node/run` as `root:_privnetnode` with mode `0775`;
ordinary users can traverse it but cannot create or replace entries. Unlike `/var/run`, this
installer-owned namespace survives reboot so the unprivileged LaunchDaemon can always restart. The
`_privnetnode` daemon binds the fixed
`control.sock` path at mode `0666` and sets a bounded connection queue. Every accepted connection is
authorized with macOS `getpeereid`:

1. Read the peer UID from the accepted Unix stream.
2. Read the owner UID of `/dev/console` without invoking a shell.
3. Accept only root or the current non-root console UID.
4. The desktop client verifies the exact directory owner/group/mode, verifies that the socket is a
   non-symlink Unix socket owned by `_privnetnode` with exact mode `0666`, and uses `getpeereid` to
   require the service-side UID to equal the installed account.

The protocol is length-prefixed, strict JSON with a schema version, random request ID, bounded body,
bounded response, two-second frame I/O deadlines, a 45-second setup-operation deadline, an
eight-connection semaphore, and no generic command, executable, environment, or path field.
Supported methods are exactly `status`, `confirmSetup`, `updateProviderPolicy`, `pause`, `resume`,
`configureManualEndpoint`, `clearManualEndpoint`, and `unpair`. `unpair` requires the exact current
node ID. Request IDs are deduplicated in process, and all underlying setup/policy operations are
retry-safe and idempotent across daemon restarts.

`confirmSetup` carries the setup code only inside the authenticated socket. The desktop backend
removes it from the process-local store while the call is in flight, restores it after a retryable
failure while still valid, and zeroizes it after success or expiry. Serialized client/server frame
buffers are also explicitly zeroized. The value is never passed in `argv`, environment variables,
temporary files, package metadata, logs, or renderer-visible responses. The request also carries the
provider's explicit exit-IP, router-mapping, relay, and local-limit choices. The non-secret relay
consent is durably stored as owner-only `provider-setup.json` for the managed relay integration.

## Package Verification

The service, not the renderer, resolves the installed release directory. Every release contains
root-owned `sidecars.json` with a closed schema and the exact Node Host and Xray target, version,
size, and SHA-256. Before consuming an invitation, the daemon verifies:

- `current` is a root-owned symlink and resolves to a child below the canonical installer-owned
  releases directory;
- agent, Xray, and manifest are regular non-symlink files;
- the manifest target matches the current platform;
- both binary sizes/digests, the Node Host crate version, and a bounded Xray version probe match the
  signed package manifest;
- release files are root-owned and not group/world writable, while state and installation identity
  directories are `_privnetnode`-owned at mode `0700`;
- the running executable resolves to the manifest-selected `current/node-host` binary.

Enrollment is not attempted after any package-verification failure, preserving the single-use code.

## State Machine

```text
unpaired daemon
  -> setup socket ready
  -> request authenticated
  -> package verified
  -> provider policy persisted
  -> node identity created
  -> enrollment accepted
  -> initial desired revision fetched/applied
  -> direct/relay candidates reconciled
  -> externally protocol verified
```

The daemon continues serving status while unpaired or after a retryable setup failure. Successful
enrollment increments an internal service generation; the same process then starts the normal
resilient service loop. Policy and endpoint mutations cancel that loop cleanly and restart it from
durable state, making local pause effective without waiting for Control or the next heartbeat. No
privileged desktop process or second state owner is introduced. Restart recovers from the last
durable phase.

## Anti-Clone Binding

The request-signing and recipient-encryption seeds move to an installation identity directory owned
by the package outside the copyable Node Host state directory. Database registration stores the
installation-key fingerprint. Copying only `state/` to another host therefore lacks the private
installation identity and fails closed instead of recreating or silently replacing it. Recovery is
explicit re-enrollment; the Control Service never accepts a new public key for an existing node ID.

Development/tests may inject an explicit identity directory. Production always passes the fixed
`/Library/Application Support/Private Network Node/service-state/identity` path to
`bootstrap_with_identity_dir`; package paths cannot come from renderer or controller input.

## Installed Assets

| Path | Owner / mode | Purpose |
| --- | --- | --- |
| `/Applications/Private Network Node.app` | signed application | Console-user UI and Tauri backend |
| `/Library/Application Support/Private Network Node/releases/<version>` | `root:wheel`, no group/world write | Agent, Xray, and `sidecars.json` |
| `/Library/Application Support/Private Network Node/current` | root-owned symlink | Installer-selected release |
| `/Library/Application Support/Private Network Node/service-state` | `_privnetnode`, `0700` | Parent retained across unpair |
| `/Library/Application Support/Private Network Node/service-state/state` | `_privnetnode`, `0700` | Copyable operational state removed by unpair |
| `/Library/Application Support/Private Network Node/service-state/identity` | `_privnetnode`, `0700` | Non-copyable installation identity removed by unpair |
| `/Library/Application Support/Private Network Node/bin/private-network-node-uninstall` | `root:wheel`, `0755` | Fixed-path explicit preserve/purge uninstaller |
| `/Library/Application Support/Private Network Node/run` | `root:_privnetnode`, `0775` | Protected, reboot-persistent socket namespace |
| `/Library/LaunchDaemons/com.sky.realitynode.agent.plist` | `root:wheel`, `0644` | Dedicated-user LaunchDaemon |

The LaunchDaemon invokes only the root-owned wrapper, which invokes `node-host system-service`
without mutable arguments. The wrapper retains a fixed-path fallback only so package rollback can
restart the final pre-system-service release.

The same installed agent exposes `node-host system-control` for headless administration and release
acceptance. It is a client of the authenticated socket, not a second privileged implementation.
Its closed subcommands mirror status, setup, policy, pause/resume, manual endpoint, and unpair DTOs.
Setup invitation bytes are accepted only on stdin; there is no invitation argument, arbitrary RPC,
path mutation, shell, or raw Xray configuration option.

A finite manual endpoint remains provider-owned. When a later signed revision keeps the same local
forwarding port, Node Host carries the unexpired approval forward with a new endpoint ID and requires
the controller probe to verify it again. A port change or expiry still withdraws the endpoint and
requires explicit reconfiguration; automatic carry-forward never extends the provider's TTL.

The status response includes only safe acceptance evidence: current service-instance ID, runtime
and setup phases, direct/relay protocol-verification states, and whether the relay is registered.
Endpoint IDs, addresses, credentials, generated configuration, and invitation material remain
absent. Direct verification is a verified controller endpoint other than the current relay endpoint;
relay verification must match the exact assigned relay endpoint ID.

## Unpair Barrier

`unpair` is a supervisor handshake, not a direct filesystem delete:

1. IPC checks the exact current node ID locally; no Control request is made.
2. A `pending` marker is synced below `service-state` for crash recovery.
3. The supervisor cancels `run_until` and waits for its shutdown path to stop Xray, admission,
   router mapping, relay, and the live status socket and to release the data-directory lock.
4. Only a successful shutdown sends the ready acknowledgement. A cleanup error rejects unpair.
5. While the supervisor remains quiesced, `uninstall_local` atomically removes both `state` and
   `identity` child trees.
6. Empty `0700` children and a `complete` marker are created, then the supervisor is released into
   unpaired mode. The package, service account, socket, and LaunchDaemon remain installed.

A retry with the same exact node ID returns the completed unpaired state. A crash after deletion but
before the completion marker is recovered from the synced pending marker. A different confirmation
ID never quiesces the data plane and never mutates state.

## Package Upgrade Transaction

`preinstall` only records the previous `current` target. It deliberately leaves the old daemon
running while payload files are copied, so a payload failure cannot strand the previous service in
a stopped state. `postinstall` then owns the complete transition:

1. boot out the previous daemon;
2. snapshot legacy `state`, `identity`, `.state.installation-identity`, and `service-state` layouts,
   including SQLite WAL/SHM, modes, ownership, ACLs, and xattrs, below a root-owned `0700` rollback
   directory;
3. migrate into `service-state`, verify signed nested code, and rebind only an identity with the
   exact previously stored public fingerprint;
4. bootstrap the candidate and remove the validated snapshot on success;
5. on any failure, remove candidate-mutated state, restore the exact snapshot layout, switch
   `current` back, and only then bootstrap the previous release.

Stale, symlinked, duplicate, or unknown snapshot layouts fail closed. If state restoration fails,
the installer does not start the previous binary against a partially migrated schema.

## Failure Rules

- A malformed/oversized/unauthorized local request performs no mutation.
- A failed package check does not consume the invitation.
- Enrollment success followed by initial apply failure remains enrolled and retryable with the same
  identity; it is not shown as shareable.
- Provider pause is local authority and immediately withdraws admission, mappings, and relay while
  retaining enrollment and last-known-good revision.
- Unpair stops and acknowledges every live data path first, removes local credentials, state, and
  external identity, then returns the installed package to an empty unpaired mode.
- Package uninstall requires an explicit `--preserve-data` or `--purge-data` choice. Purging paired
  state additionally requires the exact node ID; purging an already unpaired installation requires
  `--confirm-unpaired`. The uninstaller refuses symlinked or unexpectedly owned fixed paths and
  preserves service state plus logs unless purge was explicitly selected.

## Required Tests

- wrong peer UID, symlink socket, wrong owner/mode, malformed/oversize frame, timeout, duplicate
  request ID;
- package digest/version/path mismatch before invitation consumption;
- renderer serialization and normal logs contain no setup code or private material;
- setup retry before and after enrollment commit;
- daemon restart and generation restart at each durable phase;
- copied state without the external installation identity cannot authenticate;
- wrong-ID unpair never requests shutdown or deletes state;
- unpair works with Control offline, waits for the no-live-path acknowledgement, deletes state and
  external identity, and retries from both pending and complete markers;
- preinstall payload failure leaves the previous service running;
- post-migration failure restores schema, WAL/SHM, seeds, modes, layout, and previous service.
- package uninstall proves both explicit data preservation and confirmed purge paths.
