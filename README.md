# Private Network Platform

Native tools for operating and sharing a small multi-node `Xray + REALITY` network. `REALITY` is a
protocol detail; the stable product component names are Control, Control Service, Node Host, and
Connect. The final public brand is intentionally not encoded into the protocol or database yet.

## Repository Components

- `src/` and `src-tauri/`: current macOS Control application and local-node management backend.
- `client/`: independent macOS/Windows Connect application with a bundled Xray supervisor.
- `control-server/`: standalone lightweight Control Service with authoritative SQLite storage.
- `node-host/`: headless Node Host core with local identity, state, and CLI foundations.
- `probe-worker/`: optional privacy-minimized Cloudflare Worker for external TCP preflight.
- `crates/`: shared versioned protocol/domain types plus the verified Xray runtime boundary.
- `docs/`: authoritative architecture, protocol, security, and component designs.

## Current Status

The local Control application manages a native Xray installation, users, configuration validation,
backups, diagnostics, quotas, and local telemetry. Connect can securely import a compatibility
profile and supervise a pinned Xray sidecar. Control Service now supports secure one-time node
invitations and proof-of-possession enrollment. Node Host has durable owner-only identities and a
headless `init`/`join`/`sync-once`/`status` flow that verifies the controller response before
persisting its registration. Authenticated heartbeat and empty desired-state polling are
implemented. Node Host can also verify and durably retain signed desired-state envelopes, render a
deterministic loopback-only Xray candidate, run the checksum-pinned binary's offline config test,
and acknowledge `received` plus `validated` or `rejected` without activating Xray. Control Service
exposes redacted node summaries plus
explicit approve, disable, and revoke operations; it can publish immutable signed revisions and
record monotonic receive/validate/apply/rollback results. Enrollment and heartbeat never activate
a node implicitly or overwrite controller-owned desired state. Heartbeat endpoints are retained as
revision-bound candidates only; Control owns a separate verification record that starts `pending`
and legacy node-asserted `verified` rows are discarded. Durable heartbeat generations make exact
retries idempotent and prevent delayed snapshots from withdrawing newer candidates. Node Host also
has a resilient outbound sync loop with jitter, bounded retry backoff, and graceful process
shutdown. Its installer integration can verify and pin an explicit Xray binary, probe its version, and create a separate
owner-only REALITY identity without starting the process. Candidate files are immutable,
owner-only, digest-checked on restart, and never replace a known-good configuration during
validation. A friend-facing backend bootstrap accepts invitation JSON directly from a desktop
wrapper, initializes stable local identity, verifies installer-bundled Xray before consuming the
invitation, and completes enrollment as one idempotent retryable operation. The long-running
`node-host run` service now owns both a checksum-revalidated Xray child and a byte-transparent IPv4
admission gate. It activates only controller-acknowledged candidates, requires the signed public
port to bind and reach Xray through a local canary before recording `applied`, and restores both
parts of a proven predecessor after failure. Bootstrap can now bind explicit automatic-mapping
consent into enrollment, provide a constrained finite-lease store, and publish only a current
revision-bound lease as an unverified candidate. The service now drives finite TCP mappings in
PCP, NAT-PMP, then UPnP order, renews and releases its owned lease, and withdraws it on topology
change. Control Service now has a durable, lease-based external TCP preflight queue and a
public-address-only executor with DNS pinning, bounded connection time, stale-candidate fencing,
signed-public-port binding, and append-only results. Bare TCP success deliberately leaves endpoint
verification `pending`. Control Service migration 9 now owns durable member accounts, atomic
multi-node assignments, per-node credential rotation, terminal account deletion, and node
disable/revoke cleanup without exposing VLESS UUIDs through administrator APIs. Account creation is
durably idempotent across concurrent retries and restarts, while assignment responses separate
authorization intent from `pending`/`applied`/`removalPending` evidence. Credentials remain
`pending` until automatic desired-state reconciliation and apply acknowledgement are built;
the VLESS + REALITY canary required for client publication also remains under implementation, along
with member sessions and signed bundles, signed system-service installers, relay reachability, and
the friend-facing setup UI/package.

The optional probe-worker contract is implemented and dry-run deployable. Control Service can now
invoke it in explicit `remote-http` mode. Node Host also has a macOS private-preview user
`LaunchAgent` lifecycle: setup can enroll and register the background process as one retryable
operation, service replacement rolls back on failure, and status/removal never expose or delete
node credentials. Its same-user, status-only Unix IPC lets the UI read live service, runtime,
revision, mapping, and stable error state without opening the service-owned database. This preview
path requires a logged-in user and does not prevent sleep; signed system packages and the
end-to-end VLESS + REALITY publication canary remain operational gaps.

## Authoritative Documentation

- [REQUIREMENTS.md](./REQUIREMENTS.md): product scope, personas, requirements, and release acceptance.
- [IMPLEMENTATION_PLAN.md](./IMPLEMENTATION_PLAN.md): dependency-ordered phases and commit gates.
- [docs/SYSTEM_ARCHITECTURE.md](./docs/SYSTEM_ARCHITECTURE.md): runtime boundaries, ownership, and deployment.
- [docs/CONTROL_PROTOCOL.md](./docs/CONTROL_PROTOCOL.md): versioned enrollment, sync, account, bundle, and telemetry APIs.
- [docs/NODE_HOST.md](./docs/NODE_HOST.md): provider UX, agent lifecycle, direct reachability, and relay fallback.
- [docs/DATA_MODEL.md](./docs/DATA_MODEL.md): controller and local persistence model.
- [docs/ROLLOUT_AND_RECOVERY.md](./docs/ROLLOUT_AND_RECOVERY.md): convergence, rollback, and recovery behavior.
- [docs/SECURITY.md](./docs/SECURITY.md): trust boundaries, credentials, privacy, and release security.
- [docs/client/REQUIREMENTS.md](./docs/client/REQUIREMENTS.md): account-first Connect behavior.
- [docs/client/ARCHITECTURE.md](./docs/client/ARCHITECTURE.md): Connect runtime and storage design.
- [DESIGN.md](./DESIGN.md): non-authoritative visual design reference.

`docs/MULTI_NODE_AND_ANALYTICS.md` remains supporting rationale. If it conflicts with the documents
above, the authoritative product, architecture, protocol, data, and security documents win.

## Stack

- Tauri 2, React, TypeScript, Vite, Tailwind CSS, shadcn/ui, and Radix UI for desktop applications.
- Rust for Control, Connect, Node Host, shared domain code, and the Control Service.
- SQLite for local and controller persistence at the initial private-network scale.
- Xray-core as a pinned, checksum-verified data-plane sidecar.

## Development

```bash
npm run build
cargo test --manifest-path src-tauri/Cargo.toml

npm --prefix client run build
cargo test --manifest-path client/src-tauri/Cargo.toml

cargo test --manifest-path crates/control-protocol/Cargo.toml
cargo test --manifest-path crates/xray-runtime/Cargo.toml --locked
cargo test --manifest-path control-server/Cargo.toml
cargo test --manifest-path node-host/Cargo.toml

npm --prefix probe-worker run check
npm --prefix probe-worker test
npm --prefix probe-worker run deploy -- --dry-run
```

Control Service defaults `CONTROL_PROBE_MODE` to `disabled`. `local-tcp` is a development or
external-controller mode only: the Control Service process must be outside the candidate node's
LAN, otherwise the result tests router hairpin behavior rather than Internet reachability. TCP
preflight records evidence but never marks an endpoint verified.

For a home-hosted controller, deploy `probe-worker/` and configure the same dedicated secret on
both sides:

```bash
CONTROL_PROBE_MODE=remote-http
CONTROL_TCP_PROBE_URL=https://private-network-tcp-probe.example.workers.dev/v1/tcp-probe
CONTROL_TCP_PROBE_TOKEN=unique-visible-ascii-secret-with-at-least-32-bytes
```

Remote mode requires all three values and accepts only HTTPS. The token is unrelated to the admin,
node, or member credentials. Control resolves candidate DNS itself and sends only pinned public
IPv4 literals plus the signed public port.

The installer-oriented Node Host bootstrap accepts the exact JSON returned by
`POST /v1/admin/node-invitations`. The signed installer supplies the Xray path and hash; these are
not friend-entered settings. Because the development CLI uses a file containing a one-time secret,
that file must be owner-only on Unix:

```bash
chmod 600 invitation.json
node-host bootstrap \
  --data-dir "$HOME/Library/Application Support/Private Network/Node Host/state" \
  --invitation-file ./invitation.json \
  --display-name "Friend Mac" \
  --xray-binary-path /absolute/path/to/bundled/xray \
  --xray-sha256 64-lowercase-hex-characters \
  --accept-host-owner \
  --accept-exit-ip \
  --install-user-service \
  --agent-binary-path /absolute/installed/path/to/node-host

# Safe registration state; this is not endpoint reachability status.
node-host service status

# Live local process/data-plane state; Control still owns approval and endpoint verification.
node-host service live-status \
  --data-dir "$HOME/Library/Application Support/Private Network/Node Host/state"
```

The backend `BootstrapRequest::from_invitation_json` path keeps the invitation in memory for a
QR/deep-link desktop wrapper. `bootstrap_and_install_user_service` then supplies the one-action
macOS preview boundary. The separate `init`, `join`, `configure-xray`, and `service` commands remain
diagnostic and packaging primitives; friends do not need to run them.

Each implementation phase must leave affected applications buildable, update its authoritative
documentation, and end in a focused commit.
