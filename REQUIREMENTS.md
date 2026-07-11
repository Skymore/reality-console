# Private Network Product Requirements

Status: authoritative product requirements.

`REALITY` and `Xray` are implementation details, not the product brand. The stable component names
used by the code and documentation are **Control**, **Node Host**, **Connect**, and **Control
Service**. A later rebrand must not change protocol identifiers or stored data without a migration.

## 1. Product Goal

Provide a small, private multi-node network that one operator can share with a few friends without
requiring any participant to understand Xray JSON, UUIDs, router terminology, Docker, or shell
commands.

The operator manages people once. A person can use multiple nodes with one account. A friend who
contributes a machine can install Node Host, enter a one-time invitation, choose sharing limits,
and join the network with no administrative access.

## 2. Users

### Operator

- Runs Control on macOS and owns the network.
- Creates, disables, enables, and deletes member accounts.
- Approves nodes, assigns users to nodes, publishes configuration, and reviews health and usage.
- May run the Control Service and a local exit node on the same Mac.

### Member

- Installs Connect on macOS or Windows.
- Activates the app with an account or one-time invitation.
- Sees friendly node names and connection state, not VLESS or REALITY parameters.
- Can use cached nodes while the Control Service is temporarily unavailable.

### Node provider

- Installs Node Host on a contributed Mac, Windows machine, or Linux server.
- Joins with a short-lived one-time invitation and explicitly consents to provide an exit IP.
- Can pause sharing, set schedules and limits, inspect aggregate usage, and leave the network.
- Never receives member credentials, admin credentials, or arbitrary remote shell commands.

## 3. Product Components

- **Control**: native administrator UI. It remains useful for the local node when remote features are
  disabled.
- **Control Service**: lightweight HTTP service and SQLite database. It owns desired state, accounts,
  node enrollment, signed client bundles, telemetry ingestion, and audit events.
- **Node Host**: background agent plus a minimal owner UI. It manages a bundled Xray process,
  applies signed desired state, reports health/usage, and establishes optional relay connectivity.
- **Connect**: member client. It authenticates, caches a signed multi-node profile, selects a node,
  and supervises a bundled Xray client process.
- **Relay**: optional raw TCP forwarding service for nodes that cannot accept inbound traffic. It is
  not the control service and it cannot decrypt member traffic.

## 4. Primary Journeys

### 4.1 Create a member

1. The operator creates a member account and selects allowed nodes.
2. Control returns a short-lived activation link or code.
3. Connect activates the device, stores a refresh credential in the OS credential store, and
   downloads a signed profile bundle.
4. Connect selects a healthy node and connects without exposing protocol configuration.

### 4.2 Add a contributed node

1. The operator creates a short-lived node invitation.
2. The provider installs Node Host, enters the invitation, reviews the exit-IP disclosure, and sets
   local limits.
3. Node Host creates a device identity, enrolls over outbound HTTPS, downloads Xray, and receives
   desired state.
4. Node Host tests direct reachability. It attempts supported router mapping protocols only with
   explicit consent and uses an assigned relay when direct reachability is unavailable.
5. Control marks the node shareable only after an external probe succeeds.

### 4.3 Change or revoke access

1. The operator changes a user or node assignment once.
2. The Control Service creates an immutable monotonically increasing configuration revision.
3. Affected nodes fetch, validate, atomically apply, and report that revision.
4. Failure leaves the previous revision running and produces an actionable result in Control.
5. Connect receives the new signed bundle on its next refresh; revoked sessions cannot refresh.

## 5. Functional Requirements

### Accounts and devices

- `ACC-001`: one logical member account can own multiple independently revocable devices.
- `ACC-002`: passwords are optional after initial activation; refresh credentials provide automatic
  sign-in and are stored only in Keychain or Credential Manager.
- `ACC-003`: invitation and reset tokens are single-use, expire, and are stored hashed server-side.
- `ACC-004`: disabling a member prevents refresh immediately and removes that member from every
  node's next desired revision.
- `ACC-005`: manual VLESS invitation import remains available only as a compatibility path.

### Node enrollment and operation

- `NOD-001`: enrollment requires no inbound management port and uses an outbound HTTPS request.
- `NOD-002`: each node has a unique revocable identity; copying one node's state must not clone its
  identity successfully.
- `NOD-003`: the agent accepts a closed command/configuration schema and never arbitrary shell.
- `NOD-004`: Xray configuration is validated before activation, written atomically, backed up, and
  rolled back after failed startup or health check.
- `NOD-005`: the node continues the last successfully applied configuration when Control Service is
  offline.
- `NOD-006`: provider pause and removal take effect locally even when Control Service is offline.
- `NOD-007`: provider limits include schedule, monthly transfer cap, and an optional bandwidth or
  concurrent-session limit where the platform can enforce it safely.

### Reachability

- `NET-001`: a node is never advertised until a controller-side probe verifies its endpoint.
- `NET-002`: direct mode supports public endpoints and explicit router forwarding.
- `NET-003`: Node Host may attempt UPnP IGD, NAT-PMP, or PCP only after provider consent and must
  remove mappings when sharing is disabled.
- `NET-004`: relay mode forwards raw TCP without terminating VLESS/REALITY and preserves the node as
  the Internet exit.
- `NET-005`: Cloudflare Tunnel may expose account/configuration HTTP APIs but is not used for the
  Xray data path.

### Multi-node configuration

- `CFG-001`: users, nodes, assignments, credentials, and revisions use stable IDs; labels are never
  keys.
- `CFG-002`: a logical member receives a distinct VLESS UUID on every node.
- `CFG-003`: desired state is revisioned, immutable after publication, and idempotent to apply.
- `CFG-004`: Control shows desired, received, validated, applied, and failed revision state.
- `CFG-005`: operators can roll a node or all affected nodes back to a prior known-good revision.

### Connect

- `CLI-001`: activation requires at most account credentials or one invitation action.
- `CLI-002`: the client verifies bundle signatures before persisting or applying them.
- `CLI-003`: the client supports manual selection, automatic latency-based selection, and a pinned
  fallback order without rapid oscillation.
- `CLI-004`: the last valid bundle remains usable during a Control Service outage until its offline
  validity deadline.
- `CLI-005`: local HTTP and SOCKS listeners bind only to loopback.
- `CLI-006`: start, stop, crash recovery, and system proxy restoration are idempotent.

### Telemetry and audit

- `TEL-001`: nodes persist telemetry locally before sending bounded, ordered batches.
- `TEL-002`: ingestion is idempotent by node ID and sequence number.
- `TEL-003`: Control aggregates traffic by member, node, and time period without claiming per-
  destination byte accuracy that Xray does not provide.
- `TEL-004`: raw connection metadata is optional, excludes payloads and full URLs, and follows a
  configurable retention period.
- `TEL-005`: enrollment, account, assignment, revision, rollback, and revocation actions create
  audit events.

## 6. Quality Requirements

- A temporary control-plane outage must not terminate established data-plane service.
- Secret values must never appear in renderer state, normal logs, analytics, crash reports, or
  support bundles.
- Network mutations and filesystem writes must be bounded, cancelable where practical, and kept off
  the UI thread.
- API requests use stable error codes and versioned DTOs.
- Database migrations are transactional and covered by upgrade tests.
- Release artifacts pin and verify the Xray version and checksum.
- macOS is the first Control and Node Host platform; Connect targets macOS and Windows first. Linux
  Node Host follows through a service binary and installer.

## 7. Availability Semantics

High availability is not a product requirement for the initial private network.

- If Control Service is down, existing nodes keep serving and activated clients use cached bundles.
- New activation, bundle refresh, assignment changes, and aggregated telemetry are delayed.
- If the operator's Mac node is down, that node is unavailable; independent remote nodes continue.
- Telemetry and desired-state operations resume from cursors after recovery.

## 8. Explicit Non-Goals

- Commercial billing, payments, reseller hierarchies, or public signup.
- Arbitrary remote command execution or general remote desktop administration.
- Hiding node-provider consent or disguising that their public IP is used as an exit.
- Full packet inspection, payload logging, browser history collection, or destination byte claims.
- Multi-hop routing in the first multi-node release.
- Guaranteed direct reachability from CGNAT without a relay.
- Reimplementing every feature of Remnawave, Marzban, Hiddify, or 3x-ui.

## 9. Release Acceptance

The first complete private-network release is accepted only when:

1. An operator can create an account and node invitation from Control.
2. A clean Node Host installation can enroll without Docker, JSON, SSH, or an inbound management
   port.
3. Direct and relay endpoint probes produce deterministic shareable/not-shareable states.
4. An activated Connect installation automatically receives at least two node profiles and connects
   without manual URI import.
5. Cross-node disable removes a member from every assigned node and prevents profile refresh.
6. A bad revision is rejected or rolled back while the prior configuration continues serving.
7. Offline Control Service tests prove cached client and node behavior.
8. Per-user aggregate traffic from multiple nodes is idempotent and reconcilable.
9. macOS and Windows client packages and macOS Node Host packages pass install/connect/recovery
   smoke tests.
