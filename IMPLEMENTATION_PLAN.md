# Private Network Delivery Plan

Each phase ends with a focused commit, tests, and a runnable state. Existing unrelated worktree
changes are not included in a phase commit until independently verified.

## Phase 0: Stabilize Existing Local Identity And Analytics

Deliverables:

- stable logical user ID separated from mutable labels and Xray email;
- local node ID and revision-safe metadata migration;
- local traffic deltas and connection events attributable by stable user ID;
- migration, parser, quota, and analytics tests.

Commit: `feat(server): stabilize user identity and local analytics`

## Phase 1: Authoritative Product And Protocol Design

Deliverables:

- product requirements and acceptance criteria;
- system architecture and trust boundaries;
- Node Host onboarding/reachability design;
- control protocol and security/privacy design;
- account-based Connect requirements and delivery sequence.

Commit: `docs: define private network platform architecture`

## Phase 2: Shared Protocol And Control Service Foundation

Deliverables:

- reusable Rust protocol crate with versioned DTOs and stable error codes;
- lightweight Rust HTTP service with SQLite migrations;
- health endpoint, admin bootstrap authentication, structured redacted logging;
- integration-test harness using an isolated temporary database.

Commit: `feat(control): add service and protocol foundation`

## Phase 3: Node Enrollment And Desired State

Deliverables:

- one-time node invitation creation and atomic consumption;
- unique node credentials with rotation and revocation;
- heartbeat, desired revision fetch, and apply-result APIs;
- idempotency, replay protection, stale-node detection, and audit events;
- Node Host headless agent scaffold with local durable state.

Commit: `feat(node): add secure enrollment and config sync`

## Phase 4: Node Xray Lifecycle And Reachability

Deliverables:

- pinned Xray install/bundle and supervisor;
- signed config validation, atomic activation, health check, and rollback;
- external endpoint probe and direct mode;
- consent-gated UPnP/NAT-PMP/PCP mapping;
- optional raw TCP relay adapter and relay assignment;
- local pause, schedule, transfer cap, and leave-network controls.

Commit: `feat(node): add managed xray and reachability modes`

## Phase 5: Member Accounts And Signed Bundles

Deliverables:

- account, activation, device session, reset, and revocation APIs;
- user/node assignment and per-node credential generation;
- immutable signed multi-node profile bundles with offline validity;
- audit events and cross-node disable/delete behavior.

Commit: `feat(control): add member accounts and profile bundles`

## Phase 6: Connect Account Experience

Deliverables:

- activation/login and refresh-token storage in OS credentials;
- signed bundle verification and atomic offline cache;
- manual, automatic, and fallback node selection;
- existing Xray supervisor integration;
- compatibility import retained outside the primary onboarding flow.

Commit: `feat(client): add account sync and multi-node selection`

## Phase 7: Telemetry Aggregation And Operations

Deliverables:

- node-local ordered usage batches and idempotent server ingestion;
- per-user/per-node aggregates, retention, purge, and data-quality state;
- backups, restore, schema upgrades, support bundle, and service installers;
- macOS/Windows/Linux and direct/relay failure-matrix tests.

Commit: `feat(platform): add telemetry and operational recovery`

## Engineering Rules

- Control plane and data plane remain independent; control outage does not stop valid data plane.
- Node Host receives declarative desired state, never shell commands.
- Every secret has a named owner, storage location, rotation path, and redaction test.
- Every retryable write has an idempotency key or monotonic sequence.
- Every config mutation validates, backs up, applies atomically, health-checks, and can roll back.
- Every background task has a timeout and cannot block the Tauri UI thread.
- Protocol changes are backward-compatible within a declared support window or require an explicit
  minimum-version response.
- Each phase updates the authoritative documentation before its implementation commit closes.
