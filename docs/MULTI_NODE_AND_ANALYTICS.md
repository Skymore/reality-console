# Multi-Node And User Analytics Architecture

Status: supporting rationale. The authoritative product, runtime, protocol, persistence, rollout,
and security contracts are `REQUIREMENTS.md`, `SYSTEM_ARCHITECTURE.md`, `CONTROL_PROTOCOL.md`,
`DATA_MODEL.md`, `ROLLOUT_AND_RECOVERY.md`, and `SECURITY.md`. Those documents win on conflict.

## Goals

The platform should support a small, reliable private network of always-on nodes while
remaining useful as a single-node local application. A user should be able to select a China,
United States, or United Kingdom destination without receiving administrative access.

Detailed user analytics must remain attributable after a label changes and must merge cleanly
across nodes.

## Reference Implementations

The design borrows proven concepts, not source code, from these projects:

- [Marzban](https://github.com/Gozargah/Marzban) separates the control panel from remote nodes,
  supports per-user limits and periodic usage, and authenticates node services with certificates.
- [Marzban Node](https://gozargah.github.io/marzban/en/docs/marzban-node) exposes a dedicated
  service and Xray API port, supports REST/RPyC transports, and requires client certificates.
- [Hiddify Manager](https://github.com/hiddify/Hiddify-Manager) aggregates user usage across a
  central panel and multiple servers, and treats automatic backup as a production feature.
- [sing-box Selector](https://sing-box.sagernet.org/configuration/outbound/selector/) models
  explicit user choice between outbounds.
- [sing-box URLTest](https://sing-box.sagernet.org/configuration/outbound/urltest/) models periodic
  latency testing, tolerance, and an automatic choice without constantly interrupting existing
  connections.

## Terminology

- **Controller**: the Control Service that owns desired state and the Control app that presents it.
- **Node agent**: a restricted service on each managed computer that applies configuration and
  reports health and telemetry.
- **Exit node**: a node exposed to clients as a selectable destination.
- **User**: a person managed once at controller scope.
- **Node credential**: one VLESS UUID for one user on one node.

## Why Credentials Are Per Node

The same person receives a distinct UUID on every node. The UI still presents one logical user.
This provides:

- accurate usage and revocation per destination;
- smaller blast radius if one invitation leaks;
- independent node rotation and maintenance;
- unambiguous `(node_id, user_id)` analytics.

Reusing one UUID everywhere is simpler initially but makes incident response and attribution
materially worse, so it is not the production model.

## Client Destination Selection

The client receives a signed profile bundle containing multiple node profiles. It offers:

1. **Manual**: China, United States, United Kingdom, or another named node.
2. **Auto**: periodic health/latency tests choose the best healthy node, with tolerance to avoid
   switching for insignificant differences.
3. **Pinned fallback**: if the selected node fails, the user may opt into a defined fallback list.

Changing the selected node starts a new Xray configuration. Existing connections are either
drained or interrupted based on an explicit client setting.

Each exit node must be reachable from the client through public IPv4, public IPv6, port
forwarding, or a separately operated relay. A management overlay alone does not make the node a
public client endpoint.

## Direct Selection Versus Multi-Hop

Direct selection means:

```text
Client -> selected US node -> Internet
Client -> selected UK node -> Internet
```

Multi-hop means:

```text
Client -> China ingress -> US or UK exit -> Internet
```

Multi-hop is a separate feature with different failure, latency, DNS, accounting, and abuse
considerations. It will not be hidden behind ordinary node selection. The first production
multi-node release implements direct selection; chained outbounds come later.

## Control Plane

### Connectivity

Home nodes are commonly behind NAT. The node agent therefore initiates an outbound persistent
connection to the controller or uses a private WireGuard/Tailscale-style overlay. We will not
invent a custom NAT traversal protocol.

### Authentication

- one-time pairing establishes a controller identity and a unique node certificate;
- all control traffic uses mutually authenticated TLS;
- node certificates are independently revocable;
- the agent accepts a narrow command schema, never arbitrary shell commands;
- node-local REALITY private keys never leave the node.

### Desired State

Every configuration update has a monotonically increasing revision and idempotency key. A node
reports `received_revision`, `validated_revision`, and `applied_revision`. It validates with Xray,
creates a backup, applies atomically, restarts, performs a health check, and rolls back on failure.

Nodes continue serving the last applied configuration while the controller is offline.

### Telemetry

Each node records telemetry locally first, then sends bounded batches with a sequence cursor. The
controller acknowledges committed sequence numbers. Retries are idempotent, and temporary network
loss does not create gaps or duplicates.

## Data Model

```text
nodes
  id, name, country_code, endpoint, status, last_seen_at, applied_revision

users
  id, label, note, status, created_at, expires_at, quota_policy

user_node_credentials
  user_id, node_id, xray_email, uuid_secret_ref, enabled, created_at

traffic_samples
  node_id, user_id, bucket_start, uplink_delta, downlink_delta

connection_events
  node_id, user_id, occurred_at, client_ip, network, destination_host, destination_port

user_daily_usage
  node_id, user_id, day, uplink_bytes, downlink_bytes, connection_count

audit_events
  node_id, actor, action, target_type, target_id, result, occurred_at, details
```

Labels are presentation data and are never database keys. Xray `email` values are mapped to stable
user IDs through a credential/alias table so renaming a user does not split history.

## Per-User Analytics Contract

For `24h`, `7d`, `30d`, `90d`, or an explicit interval, the backend returns:

- upload, download, total traffic, quota, and quota percentage;
- connection count, unique client IP count, first seen, and last seen;
- active days and recently-active state (not falsely labelled as currently online);
- daily traffic and connection trend;
- top client IPs with count and last-seen time;
- top destination hosts with count and last-seen time;
- recent connection events with network and destination port;
- per-node breakdown and aggregate totals;
- data-quality status: last traffic poll, last access-log import, and collection errors.

Xray cumulative counters are sampled into deltas. Raw access logs provide connection metadata but
not exact bytes per connection, so the UI must not imply that destination-level traffic bytes are
known.

## Retention And Privacy

- raw connection events: 30 days by default, configurable from 1 to 90 days;
- hourly traffic samples: 90 days;
- daily aggregates and audit events: 365 days;
- destination data stores host and port only, never URLs or payloads;
- export and purge are explicit operations;
- analytics collection can be disabled while aggregate quota accounting remains enabled.

Retention is time-based and per node. A global `LIMIT 5000` is not acceptable because one busy
user can erase every other user's history.

## Delivery Phases

1. Stabilize single-node identities and analytics with `node_id = local-node`.
2. Add multi-profile bundles and manual node selection to the client.
3. Add node records, pairing identities, desired-state revisions, and agent protocol.
4. Add telemetry synchronization and controller aggregation.
5. Add automatic node selection and health history.
6. Add optional multi-hop routes only after direct multi-node operation is stable.
