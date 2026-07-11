# Private Network Platform

Native tools for operating and sharing a small multi-node `Xray + REALITY` network. `REALITY` is a
protocol detail; the stable product component names are Control, Control Service, Node Host, and
Connect. The final public brand is intentionally not encoded into the protocol or database yet.

## Repository Components

- `src/` and `src-tauri/`: current macOS Control application and local-node management backend.
- `client/`: independent macOS/Windows Connect application with a bundled Xray supervisor.
- `control-server/`: standalone lightweight Control Service with authoritative SQLite storage.
- `node-host/`: headless Node Host core with local identity, state, and CLI foundations.
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
a node implicitly or overwrite controller-owned desired state. Node Host also has a resilient
outbound sync loop with jitter, bounded retry backoff, and graceful process shutdown. Its installer
integration can verify and pin an explicit Xray binary, probe its version, and create a separate
owner-only REALITY identity without starting the process. Candidate files are immutable,
owner-only, digest-checked on restart, and never replace a known-good configuration during
validation. A friend-facing backend bootstrap accepts invitation JSON directly from a desktop
wrapper, initializes stable local identity, verifies installer-bundled Xray before consuming the
invitation, and completes enrollment as one idempotent retryable operation. The long-running
`node-host run` service now owns both a checksum-revalidated Xray child and a byte-transparent IPv4
admission gate. It activates only controller-acknowledged candidates, requires the signed public
port to bind and reach Xray through a local canary before recording `applied`, and restores both
parts of a proven predecessor after failure. Native service installers, automatic router mapping,
controller-side external probes, relay reachability, account synchronization, and the friend-facing
setup UI/package are still under implementation.

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
```

The installer-oriented Node Host bootstrap accepts the exact JSON returned by
`POST /v1/admin/node-invitations`. The signed installer supplies the Xray path and hash; these are
not friend-entered settings. Because the development CLI uses a file containing a one-time secret,
that file must be owner-only on Unix:

```bash
chmod 600 invitation.json
node-host bootstrap \
  --data-dir ./node-state \
  --invitation-file ./invitation.json \
  --display-name "Friend Mac" \
  --xray-binary-path /absolute/path/to/bundled/xray \
  --xray-sha256 64-lowercase-hex-characters \
  --accept-host-owner \
  --accept-exit-ip

# Development foreground service; the installer will register this automatically.
node-host run --data-dir ./node-state
```

The backend `BootstrapRequest::from_invitation_json` path keeps the invitation in memory for a
QR/deep-link desktop wrapper. The separate `init`, `join`, and `configure-xray` commands remain
available as diagnostic and packaging primitives; friends do not need to run them.

Each implementation phase must leave affected applications buildable, update its authoritative
documentation, and end in a focused commit.
