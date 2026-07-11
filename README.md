# Private Network Platform

Native tools for operating and sharing a small multi-node `Xray + REALITY` network. `REALITY` is a
protocol detail; the stable product component names are Control, Control Service, Node Host, and
Connect. The final public brand is intentionally not encoded into the protocol or database yet.

## Repository Components

- `src/` and `src-tauri/`: current macOS Control application and local-node management backend.
- `client/`: independent macOS/Windows Connect application with a bundled Xray supervisor.
- `control-server/`: lightweight Control Service; introduced by the current delivery plan.
- `crates/`: shared domain and control-protocol crates; introduced by the current delivery plan.
- `docs/`: authoritative architecture, protocol, security, and component designs.

## Current Status

The local Control application manages a native Xray installation, users, configuration validation,
backups, diagnostics, quotas, and local telemetry. Connect can securely import a compatibility
profile and supervise a pinned Xray sidecar. Account synchronization, Node Host enrollment,
multi-node desired state, and relay fallback are under active implementation.

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
```

Each implementation phase must leave affected applications buildable, update its authoritative
documentation, and end in a focused commit.
