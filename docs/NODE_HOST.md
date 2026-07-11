# Easy Node Host Product And Technical Design

## 1. Purpose

Easy Node Host turns a trusted friend's macOS, Windows, or Linux computer into a managed Reality
Console exit node without requiring that person to edit Xray JSON, open an administrative port, or
understand router configuration.

The product is for a small, noncommercial friend network, not a public proxy marketplace. The
expected deployment is 2-20 nodes, 2-50 invited users, one controller, and one clearly identified
human owner per node. Defaults favor consent, predictable resource use, and recovery over maximum
throughput or fully unattended fleet management.

The host experience is:

1. Install Node Host from a signed package.
2. Open a short-lived pairing link or enter a one-time code supplied by the controller owner.
3. Review what hosting permits and set bandwidth, traffic, schedule, and relay limits.
4. Approve installation as a background service.
5. See a simple state: `Online - Direct`, `Online - Relayed`, `Offline`, `Paused`, or `Needs
   attention`.

After pairing, all management traffic is initiated by the node. The controller never receives a
shell, filesystem API, generic process launcher, or inbound management port.

## 2. Goals

- Pair a node once without manually transferring certificates or secrets.
- Keep the management plane outbound-only so a home router needs no administrative port mapping.
- Converge controller desired state and node applied state with monotonic, auditable revisions.
- Install, validate, supervise, update, and recover Xray without exposing Xray administration.
- Determine direct client reachability from outside the node's LAN.
- Attempt safe TCP port mapping through PCP, NAT-PMP, and UPnP IGD before asking for manual router
  changes.
- Offer an optional raw-TCP relay when direct reachability is impossible.
- Give the computer owner durable consent controls and enforce hard local resource limits.
- Continue serving the last known-good configuration through controller outages.
- Produce enough redacted diagnostics to support a small network without enterprise operations
  infrastructure.

## 3. Non-Goals

- Public discovery, open registration, paid hosting, revenue sharing, or anonymous providers.
- Arbitrary remote command execution, remote desktop, or general device management.
- Using a management overlay as a client endpoint.
- A custom peer-to-peer NAT traversal or UDP hole-punching protocol.
- UDP relay, generic VPN tunneling, multi-hop routing, or traffic inspection at the relay.
- High-availability controller clustering or operation at commercial proxy scale.
- Hiding bandwidth use, public-IP exposure, or legal responsibility from the node owner.
- Continuing new service after the owner pauses, unpairs, or reaches a local hard limit.

## 4. Terminology And Ownership

- **Controller**: the Control Service instance that owns users, desired node state, invitations,
  controller audit history, and client profile publication.
- **Node Host**: the installed product, consisting of the node agent, Xray sidecar, and optional
  setup/status UI.
- **Node agent**: the privileged, narrow background service that syncs with the controller and
  supervises Xray.
- **Provider**: the human who owns or controls the node computer and internet connection.
- **Client**: an invited friend's Connect application connecting to an exit node.
- **Direct endpoint**: a public IPv4, IPv6, or mapped TCP address proven reachable by an external
  verifier.
- **Relay**: an optional public service that forwards opaque TCP byte streams between clients and a
  node-created outbound tunnel.
- **Desired revision**: an immutable controller snapshot the node should run.
- **Applied revision**: the last desired revision that passed local validation, activation, and
  health verification.

The controller chooses users and logical policy. The provider chooses whether this computer may
host at all and sets local ceilings that the controller cannot raise. The node owns its REALITY
private key, local service credentials, runtime files, and last-known-good state. The relay owns
only stream routing, connection accounting, and abuse controls; it never owns Xray user credentials
or REALITY private keys.

## 5. System Architecture

```text
                                      management: node-initiated HTTPS/WSS
  +----------------+             +------------------------------------------+
  | Reality        |<------------| Node agent                               |
  | Controller     |             | - pairing identity and sync              |
  |                |             | - desired-state reconciler               |
  | - desired      |             | - Xray supervisor                        |
  | - profiles     |             | - reachability and router mapper         |
  | - probe API    |             | - telemetry and optional relay connector |
  +-------+--------+             +------------------------------------------+
          |
          | external direct/relay probe
          v
  client TCP --------direct---------+
          |                          |
          +--> TCP relay             |
               |                     v
               +--node outbound--> TCP admission gate --> Xray --> Internet
                   tunnel           (public + local)      (loopback)
```

The controller and relay may be deployed together for convenience, but they are separate trust
roles and protocols. A relay compromise can observe source/destination IPs, timing, and byte counts
and can disrupt streams. It must not be able to decrypt a correctly configured VLESS + REALITY
session.

### 5.1 Node Components

- `reality-node-agent`: the service process and only component permitted to write runtime state.
- TCP admission gate: a small agent-owned listener that enforces provider aggregate byte, rate,
  concurrency, and schedule limits before forwarding unchanged streams to loopback-only Xray. It
  has no protocol credentials or destination API.
- `xray`: a version-pinned sidecar executed directly, never through a shell.
- Setup/status UI: an unprivileged native or Tauri UI that communicates over an authenticated local
  IPC endpoint. It cannot submit raw Xray config or invoke arbitrary service methods.
- Local state store: SQLite plus owner-only files for revisions, event spool, leases, and recovery.
- OS secret store adapter: Keychain on macOS, DPAPI-backed machine secrets on Windows, and an
  owner-only root file or system credential facility on Linux.

### 5.2 Network Surfaces

The node may open only these surfaces:

- The admission gate's configured public TCP data port. Xray's corresponding inbound binds to
  loopback so direct and relayed streams cross the same local enforcement boundary.
- A loopback-only local IPC endpoint for setup and status.
- Outbound TLS connections to the controller, reachability service, update service, and optional
  relay.
- Local-LAN discovery messages to a router for PCP, NAT-PMP, and UPnP while mapping is enabled.

The Xray API and metrics listeners bind to loopback or a private inherited socket. The agent has no
public HTTP server, SSH server, or inbound control endpoint. The public data listener and external
reachability probe are data-plane surfaces and do not violate the outbound-only management rule.

## 6. One-Time Pairing

### 6.1 Pairing Artifact

The controller creates a single-use invitation containing:

```text
controller_url
controller_instance_id
pairing_id
pairing_secret (at least 192 random bits)
expires_at (15 minutes by default, 60 minutes maximum)
expected_controller_public_key_hash
```

It is encoded as a custom URL and as a human-enterable code. The URL may contain the secret in the
fragment so a web redirect does not send it in an HTTP request. The controller stores only a hash
of the pairing secret. Invitations are invalid after first successful use, expiration, explicit
cancellation, or five failed attempts.

The controller UI displays the intended node name and provider name. The code is shared through an
already trusted conversation between friends; it is not posted publicly.

### 6.2 Pairing Flow

1. The setup UI parses the invitation and shows the controller host, controller display name, and a
   short fingerprint derived from the pinned controller key.
2. The provider reviews the consent disclosure and chooses initial local limits before continuing.
3. The agent generates a non-exportable node signing key and a separate TLS key locally.
4. The agent opens TLS to `controller_url`, requires normal public PKI validation, and additionally
   verifies `expected_controller_public_key_hash`. A private controller deployment may instead use
   a pinned self-signed key supplied in the invitation.
5. The agent sends `pairing_id`, the pairing secret, public keys, agent version, OS/architecture,
   and a random request nonce. It sends no stable hardware identifier.
6. The controller atomically consumes the invitation, creates a random `node_id`, and returns a
   node certificate, controller trust bundle, controller-signed node metadata, and sync endpoints.
7. Both UIs show the same four-word confirmation phrase derived from the transcript hash. The
   provider confirms it locally; the controller owner confirms it in Control. Neither
   confirmation alone activates hosting.
8. After both confirmations, the controller emits desired revision 1. The node stores credentials
   in the OS secret store and erases the pairing secret.

Pairing is transactional. If confirmation is not completed within 15 minutes, the pending node is
deleted and the invitation remains consumed. Re-pairing requires a new invitation.

### 6.3 Ongoing Authentication And Unpairing

- Normal sync uses TLS 1.3 with mutual authentication. Each node certificate is unique and scoped
  to one `controller_instance_id` and `node_id`.
- Certificates rotate automatically over the authenticated channel before expiration. Rotation
  changes transport identity, not `node_id`.
- The agent validates controller-signed response envelopes in addition to TLS so a proxy or relay
  cannot manufacture desired state.
- Controller revocation prevents future sync and relay admission, but cannot instantly stop a node
  that is offline. The UI must state this limitation.
- Provider unpairing is authoritative locally: stop Xray, release router mappings, close relay
  tunnels, delete node credentials and desired state, retain a redacted audit record, and require a
  new invitation to reconnect.
- Controller-initiated removal is delivered as a signed tombstone. On receipt, the node performs
  the same local teardown and acknowledges with the tombstone ID.

### 6.4 Headless Development Flow

The current headless implementation exposes `init`, `join`, `sync-once`, and `status`. `join`
consumes the exact
JSON invitation returned by Control Service, requires both provider-consent flags, reuses the
installation's owner-only Ed25519/X25519 identities, and persists registration only after verifying
the controller fingerprint and signed response. On Unix, the invitation file must be a regular
non-symlink file inaccessible to group and other users. Repeating `join` with the same invitation
and local identity safely recovers a lost success response without creating another node.

This CLI is a development and service integration surface, not the intended friend-facing UX. The
desktop wrapper will receive the invitation in memory through a QR code or deep link and present
the provider disclosures as explicit checkboxes. Registration creates a pending node; operator
approval and activation remain separate control-plane steps.

`sync-once` performs one outbound signed heartbeat and one signed desired-state fetch. It records
heartbeat and complete-cycle timestamps locally, uses a fresh nonce for every request, and accepts
only the empty `204` desired-state response in the current slice. A later service loop will run the
same operation with jitter and backoff after signed desired-state apply is complete.

## 7. Outbound-Only Control Sync

### 7.1 Transport

The agent maintains one outbound WebSocket over HTTPS where possible. If WebSocket upgrade fails,
it uses bounded HTTPS long polling. No behavior depends on unsolicited controller-to-node traffic.

- Heartbeat interval: 30 seconds while connected, with server-provided jitter.
- Reconnect: exponential backoff from 1 second to 5 minutes, full jitter, reset after 10 stable
  minutes.
- Every request carries `node_id`, node session ID, monotonically increasing request sequence,
  agent capabilities, current state summary, and an idempotency key.
- Every response is signed, bounded in size, has an expiry, and is tied to the requesting node and
  session nonce.
- Clock skew is reported but revision ordering never relies on wall-clock time.

The message schema is versioned. Unknown optional fields are ignored; unknown required
capabilities cause a `desired_unsupported` rejection rather than a partial apply.

### 7.2 Sync Exchange

On connect and after each state transition, the node sends:

```text
node_id
agent_version / xray_version
received_revision / validated_revision / applied_revision
applied_hash
apply_state / last_apply_error_code
provider_state and effective local limits
endpoint candidates and mapping lease status
relay status
health summary
telemetry high-water mark
```

The controller returns, as needed:

- the latest complete desired snapshot or `not_modified`;
- certificate/update metadata;
- reachability probe requests and results;
- acknowledged telemetry sequence;
- a signed removal tombstone.

The node never accepts a shell command, URL to execute, arbitrary file write, or arbitrary process
arguments. Controller actions map to a closed, versioned domain schema.

### 7.3 Desired Snapshot

A desired snapshot is immutable and contains:

```text
node_id
revision (unsigned 64-bit, strictly increasing)
schema_version
created_at
previous_applied_hash (optional convergence guard)
logical Xray inbound and routing policy
per-node user credentials and statuses
public REALITY material and references to node-local private material
requested listen port
reachability policy: auto-map / manual / relay allowed
telemetry policy within product privacy bounds
minimum compatible agent and Xray versions
snapshot_hash
controller_signature
```

It is a full snapshot rather than an ordered patch series. This makes recovery after long offline
periods independent of missed intermediate revisions. Secrets intended for the node are encrypted
to the node key as well as protected by mTLS. The controller never requests or receives a node's
REALITY private key.

## 8. Desired/Applied Revision State Machine

### 8.1 Persisted Revision Fields

- `desired_revision`: latest revision advertised by the controller.
- `received_revision`: latest snapshot durably stored with a valid signature and hash.
- `validated_revision`: latest received snapshot that passed schema, policy, generated-config, and
  `xray run -test` validation.
- `applied_revision`: latest revision activated and proven healthy.
- `applied_hash`: hash of the exact generated runtime config, excluding ephemeral paths.
- `failed_revision`: latest revision rejected or rolled back, with stable error code.
- `last_known_good_revision`: revision whose files and node-local secret references are retained for
  rollback.

These values are committed to SQLite before an acknowledgement is sent. `applied_revision` never
advances merely because Xray started.

### 8.2 States And Transitions

```text
             newer signed snapshot
  ACTIVE ------------------------------> RECEIVED
    ^                                      |
    |                                      v
    |                                  VALIDATING
    |                                  /        \
    |                                 v          v
    |                              STAGED     REJECTED
    |                                 |
    |                                 v
    |                              APPLYING
    |                              /      \
    |                             v        v
    +------------------------ VERIFYING  ROLLING_BACK
                                  |             |
                                  v             v
                               ACTIVE       DEGRADED
```

- `ACTIVE`: Xray is healthy on `applied_revision`, or hosting is intentionally paused.
- `RECEIVED`: a newer full snapshot is fsynced and signature-verified.
- `VALIDATING`: logical policy and generated Xray config are being checked without changing the
  running process.
- `STAGED`: candidate files are complete, owner-only, and ready for one serialized apply.
- `APPLYING`: the supervisor activates the candidate.
- `VERIFYING`: local process health and the configured reachability policy are being evaluated.
- `REJECTED`: the candidate was never activated; the last-known-good revision keeps serving.
- `ROLLING_BACK`: candidate activation failed after touching runtime state.
- `DEGRADED`: rollback did not restore healthy service or local prerequisites are missing.

`REJECTED` is revision-specific, not terminal. A higher revision can be accepted. The controller
may resubmit the same revision only if its hash is identical; a revision/hash mismatch is a
security error. Older revisions are ignored unless they are the node's locally retained rollback
target. The controller cannot order a downgrade by reusing an old number; it must publish a new
revision whose content intentionally reverts policy.

### 8.3 Apply Algorithm

1. Verify node/controller IDs, signature, schema version, revision ordering, size limits, and hash.
2. Apply provider ceilings to requested policy and calculate the effective policy. Reject any
   prohibited feature; clamp ordinary resource requests and report the clamp.
3. Resolve references to node-local key material. Generate missing REALITY keys locally and return
   only public material in the next sync. A revision waiting on newly generated public material is
   `blocked_local_material`, not partially applied.
4. Generate deterministic Xray JSON in a private staging directory.
5. Run the pinned Xray binary's config test with a timeout and bounded, redacted output.
6. Persist `validated_revision`, candidate hash, and a recovery journal. Retain the current config,
   binary reference, and secret references as last known good.
7. Stop accepting concurrent apply operations. Start or restart Xray with the candidate, then
   atomically point the admission gate at the candidate's loopback port.
8. Confirm process stability, Xray's loopback sockets, the public admission socket, loopback API
   health, and a local protocol canary. Then run or request the applicable external reachability
   test.
9. Commit `applied_revision` only after required local checks pass. External unreachability may
   yield `ACTIVE_NOT_REACHABLE` without rolling back a locally valid Xray config because router
   state is independent of config correctness.
10. On process/config failure, restore the previous files and binary reference, restart, and verify
    them. Report the candidate as failed while leaving `applied_revision` unchanged.

Only one candidate may apply at a time. If revisions 12 and 13 arrive while 11 is applying, the
agent completes or rolls back 11, discards unvalidated 12, and reconciles directly to full snapshot
13. User removal and provider pause are exceptions: local pause stops service immediately, while an
urgent signed removal is processed before ordinary later snapshots.

## 9. Xray Lifecycle

### 9.1 Binary Supply And Validation

- Agent releases pin an approved Xray version and SHA-256 checksum per OS/architecture.
- Release packaging embeds Xray or downloads it only from the signed Reality Node update manifest,
  verifies checksum and publisher signature, and stages it without executing from a temporary
  user-writable path.
- The controller may require a minimum approved version but cannot provide an arbitrary binary or
  download URL.
- The service executes Xray directly under a dedicated low-privilege identity. No config value is
  interpolated into a shell command.
- Binary rollback is retained alongside config rollback for one previous successful release.

### 9.2 Runtime Files

- Config and key files are readable only by the service identity and administrators.
- Xray's managed inbound listens on loopback. The admission gate owns the public port and copies
  byte streams without parsing VLESS or REALITY.
- Candidate config, active config, and one last-known-good config use atomic rename on the same
  filesystem.
- Logs are bounded and rotated. Access logging is disabled by default; if analytics is enabled,
  connection metadata follows the retention rules in `MULTI_NODE_AND_ANALYTICS.md`.
- Generated config and invitations never appear in diagnostic bundles.

### 9.3 Process Supervision

- Start Xray automatically only when pairing is active, provider consent is enabled, schedule and
  hard limits permit service, and a valid applied revision exists.
- Use an OS service manager for agent restart, but let the agent be the sole Xray supervisor.
- Require the process to remain alive for 10 seconds and expose all expected sockets before local
  health succeeds.
- On unexpected exit, capture a redacted reason and restart with exponential backoff: 1, 2, 5, 15,
  30, then 60 seconds. More than five exits in 10 minutes opens a circuit breaker for 15 minutes.
- If the new revision crashes repeatedly, roll back automatically. If last known good also fails,
  stop restart looping and enter `DEGRADED`.
- Graceful apply sends the supported termination signal and waits up to 10 seconds, then force
  terminates. A revision that changes inbound credentials or port may interrupt existing sessions;
  the controller UI must show this before publishing.
- OS shutdown stops Xray, flushes the journal and telemetry cursor, and preserves applied state for
  boot recovery.

### 9.4 Local Provider Actions

The setup/status UI exposes `Pause`, `Resume`, `Run diagnostics`, `Change limits`, `Release router
mapping`, `Unpair`, and `Uninstall`. Pause is local and immediate. The controller can see that the
node is provider-paused but cannot remotely override it. Resume restores service only if a valid
applied revision and all local limits allow it.

## 10. Endpoint Discovery And Direct Reachability

### 10.1 Candidate Discovery

The agent builds candidates from:

- globally routable IPv6 addresses on eligible interfaces;
- controller-observed public IPv4 for the node's control connection;
- external addresses returned by PCP, NAT-PMP, or UPnP;
- a provider-entered hostname or manual port-forward endpoint.

Private, loopback, link-local, carrier-grade NAT, documentation, and multicast addresses are never
published as direct endpoints. Interface changes, resume from sleep, public-IP changes, mapping
renewal, and applied port changes invalidate previous reachability.

Discovery alone does not mark an endpoint healthy. Only an external test can set `direct_verified`.

### 10.2 Test Protocol

1. After local Xray checks pass, the node asks the controller for a probe and reports candidate
   endpoints plus a random test nonce.
2. The controller selects a short-lived canary VLESS credential that is already present in the
   applied node config and binds the request to `node_id`, `applied_revision`, endpoint, and nonce.
3. A probe runner outside the node's LAN first attempts a TCP connection with a 5-second timeout.
4. If TCP connects, the runner uses a pinned Xray probe client to complete a VLESS + REALITY session
   and fetch a fixed small HTTPS canary through the node. This proves the listener is the intended
   node and that forwarding works; a bare open TCP port is not enough.
5. The controller signs the result. The node and controller store phase, latency, observed address,
   error code, and time, but never the canary credential in logs.
6. Canary credentials rotate at least daily, are accepted only for the probe's constrained routing
   target where supported, and are never published to end users.

A direct endpoint becomes publishable after one successful end-to-end probe for the current
`applied_revision` and listen port. It remains healthy with a successful test every 15 minutes.
After two failures it becomes `suspect`; after three consecutive failures or 45 minutes without a
successful probe it becomes `unreachable` and is removed from new client bundles. Existing clients
may retain cached profiles but are warned by normal health selection.

The probe service applies per-node and global rate limits and cannot be used to scan arbitrary
hosts: it connects only to candidates recently reported by the same authenticated node, only to the
desired Xray port, and only with a controller-issued nonce.

## 11. Automatic Router Mapping

### 11.1 User Experience

`Automatically configure my router` is offered during setup with a plain-language disclosure that
the product will request one public TCP port. It is enabled only by explicit provider consent. The
UI distinguishes `Mapped and externally verified`, `Mapped but not reachable`, `Router mapping not
supported`, and `Mapping disabled`.

Failure never weakens the host firewall or enables a broad router setting. The product does not ask
the provider to enable DMZ, expose Xray's API, or disable the firewall.

### 11.2 Mapping Strategy

For each active default route, the agent attempts standards in this order:

1. PCP, preferring an explicit lifetime and the requested external port.
2. NAT-PMP if PCP is unavailable on an IPv4 gateway.
3. UPnP IGD v2/v1 after constrained SSDP discovery on the local interface.

Only TCP is requested. The internal client is the node's current LAN address and the internal port
is the admission gate's applied public listen port. The external port defaults to the same value;
if unavailable, the agent may accept a router-selected high port only when the controller can
publish the resulting port. Mappings use a description containing the product name and abbreviated
node ID.

Attempts are serialized, bounded to 10 seconds per protocol, and repeated only after topology
change or backoff. A timeout or malformed router response is failure, not permission to broaden the
request.

### 11.3 Lease Lifecycle

- Request a 60-minute lease where supported and renew at 50% of lifetime with jitter.
- UPnP devices that permit only permanent mappings are used only after a second explicit consent
  disclosure; otherwise UPnP permanent mapping is skipped.
- Persist protocol, gateway, internal/external address and port, lease epoch, and mapping ID so a
  restarted agent can renew or remove its own mapping.
- Delete the mapping on provider pause, unpair, uninstall, port change, or clean shutdown. A crash
  may leave it until lease expiry, which is why finite leases are preferred.
- Never delete or modify a mapping not proven to have been created by this node.
- Re-run external reachability after every creation or renewal that changes endpoint data.

### 11.4 Firewall Handling

The installer may add one narrowly scoped inbound TCP firewall rule for the admission-gate
executable or configured port, with provider approval and a stable product identifier. It must not
disable the firewall. The rule is updated transactionally when the port changes and removed on
uninstall. On Linux, automatic firewall changes are optional and distribution-specific; otherwise
the installer prints and records the exact administrator action required.

## 12. Optional Raw-TCP Relay Fallback

### 12.1 When Relay Is Used

Relay is offered only when direct reachability fails or the provider explicitly prefers not to
expose a home IP. It requires all of:

- controller owner enables a configured relay service;
- provider explicitly consents to relayed traffic and sets relay limits;
- desired state allows relay for this node;
- the relay authenticates the current node certificate and policy grant.

Relay is never silently enabled after a failed mapping attempt. The UI explains that relay hides
the node endpoint from clients but exposes metadata and bandwidth to the relay operator and may be
slower.

### 12.2 Data Path

The node opens an outbound authenticated TLS connection to the relay and registers an opaque
`relay_endpoint_id`. The relay exposes a public TCP port. For each client connection it opens a
logical stream over the existing node tunnel and copies bytes in both directions without parsing,
terminating, or modifying VLESS + REALITY. On the node, relayed streams enter the same admission
gate as direct streams before reaching Xray, so provider limits apply to both paths.

```text
Connect -- VLESS + REALITY bytes --> public relay TCP port
               -- opaque framed stream --> node outbound tunnel
               --> local admission gate --> loopback Xray TCP port
```

Framing contains only stream ID, open/close, flow-control window, and byte payload. It supports
backpressure, half-close, idle timeout, and bounded per-stream buffers. There is no SOCKS API,
destination selection API, UDP association, or generic port registration.

The relay sees client IP, node relay ID, connection time, duration, and bytes. Xray still performs
client authentication and encryption at the node. The relay must not receive user UUID lists,
REALITY private keys, destinations, plaintext, or generated Xray config.

### 12.3 Relay Admission And Limits

- One public relay endpoint maps to exactly one paired node and its current Xray port.
- A controller-signed, short-lived grant binds node ID, relay ID, expiry, concurrency, bandwidth,
  and monthly byte ceiling.
- The relay enforces the lower of controller policy, provider local limit, and relay operator cap.
- Default friend-network limits are 16 concurrent streams, 20 Mbit/s aggregate, a 2-minute
  no-payload timeout, a 30-minute idle timeout, and 100 GiB per calendar month. All are configurable
  downward by the provider; deployments may configure different upper bounds.
- On limit exhaustion, existing streams may drain for up to 5 minutes, then close. New streams are
  refused with no protocol-specific response.
- Tunnel reconnect uses exponential backoff. Public relay health is verified through the same
  end-to-end canary, targeting the relay endpoint.
- Relay logs are metadata-only, retained 14 days by default, and deletable by node ID.

Direct is preferred when both paths are healthy unless the provider selects `Relay only`. Client
bundles publish one active endpoint per node at first; automatic per-connection direct/relay
failover is deferred to avoid ambiguous accounting and behavior.

## 13. Provider Consent, Policy, And Limits

### 13.1 Consent Record

Before activation, the provider sees and accepts a versioned disclosure covering:

- invited friends will route internet traffic through this computer and public IP;
- the connection may consume bandwidth, power, disk, and router resources;
- the provider or relay operator may see connection metadata but not encrypted payload contents;
- local law, ISP terms, data caps, and responsibility remain the provider's concern;
- controller revocation cannot affect a currently offline node until it reconnects;
- pause and unpair are always locally available.

The signed local consent record contains disclosure version, accepted time, selected capabilities,
limits, and a random receipt ID. The controller receives the receipt ID and effective settings, not
an assertion that replaces local enforcement. Materially broader capabilities require new local
consent.

### 13.2 Local Hard Limits

The provider can configure:

- hosting enabled/paused;
- direct mapping allowed, manual direct only, relay allowed, or relay only;
- monthly upload + download allowance;
- aggregate bandwidth ceiling;
- maximum concurrent client connections;
- permitted days and hours, with an optional `finish existing connections` grace period;
- metered-network behavior and laptop/battery behavior;
- analytics level: aggregate only or connection metadata;
- automatic security updates and maintenance window.

Safe defaults are 100 GiB/month, 20 Mbit/s, 16 concurrent connections, no service on a metered
network, pause below 20% laptop battery, aggregate analytics only, and automatic signed security
updates. The setup UI makes these values visible; no default is described as unlimited.

The effective value is always `min(controller request, provider limit, product safety maximum)`.
The controller may request less but cannot raise or disable a provider limit. Usage enforcement is
local and survives controller loss. The admission gate uses a token bucket for aggregate bandwidth,
an exact active-stream counter for concurrency, and monotonic byte counters for provider quota.
When a schedule or hard byte limit closes, it refuses new streams and either drains or closes
existing streams according to provider policy. These counters measure provider link bytes,
including transport overhead, and are deliberately separate from Xray's per-user payload usage.
Month boundaries use the provider's configured timezone, and clock rollback never restores
consumed quota; usage checkpoints are monotonic and reconciled after reboot.

Because a byte-transparent gate cannot infer the encrypted Xray user, it enforces aggregate
provider limits only. Xray remains the source for per-user counters. Client source-IP-to-user
correlation is published only if the pinned Xray transport has a tested, authenticated way to
preserve original source metadata; otherwise the UI labels source-IP analytics unavailable rather
than joining data heuristically.

### 13.3 Small-Network Guardrails

- No public listing or self-service client signup.
- Maximum 50 enabled users and 20 paired nodes per controller in the initial product.
- Each user has a distinct UUID per node, consistent with `MULTI_NODE_AND_ANALYTICS.md`.
- Invitations and client profiles are created by the controller owner and shared privately.
- The provider can see user labels and aggregate per-user usage for their node, but not controller
  notes or data from other nodes.
- There is no payment, SLA, traffic resale, or provider reputation system.

## 14. Offline And Failure Behavior

### 14.1 Controller Offline

- Continue serving the last applied revision subject to local consent, schedule, and limits.
- Buffer bounded telemetry locally and retry idempotently after reconnect.
- Keep renewing an existing finite router lease if the gateway remains available.
- Keep a relay tunnel only if the relay grant remains valid; refresh cannot bypass grant expiry.
- Do not expire Xray user access solely because the controller is unreachable unless the user has
  an explicit controller-authored expiration already present in applied state.
- Display `Controller offline - serving revision N`, last successful sync time, and whether direct
  or relay endpoint health can still be independently checked.

After seven days without controller contact, show a provider warning but do not stop direct service
by default. A provider may choose a local fail-closed duration. Relay grants should be valid for no
more than 24 hours, so relayed service eventually fails closed if controller authorization cannot
be renewed.

### 14.2 Node Offline

The controller marks a node:

- `online` while heartbeats are current;
- `stale` after 90 seconds;
- `offline` after 5 minutes;
- `extended_offline` after 24 hours.

Offline nodes are excluded from newly generated Auto selections after 5 minutes. The controller
retains only the latest desired full snapshot. On reconnect, the node reports its durable applied
state and converges directly to the latest compatible revision.

### 14.3 Network And Router Changes

- Loss of internet does not stop healthy local Xray immediately; endpoint status becomes unknown.
- A default-route, address, gateway, or network-category change invalidates mapping and probe state.
- On an untrusted/public network, auto-mapping and public listening are disabled by default pending
  provider approval.
- Sleep closes transient control and relay sessions. On wake, the agent rechecks limits, local
  listener health, router mapping, public address, and external reachability before advertising.

### 14.4 Disk, Clock, And Corruption

- Reserve space for state and reject new telemetry before config/recovery writes can exhaust disk.
- Cap telemetry spool at 100 MiB or seven days, whichever comes first; coalesce aggregate samples
  before dropping oldest data and report the gap.
- Use database transactions, WAL, checksums, and a startup recovery journal. If active state is
  corrupt, attempt last known good; otherwise remain stopped and report `local_state_corrupt`.
- Wall-clock anomalies affect timestamps and schedules conservatively but never revision ordering,
  usage counters, invitation single-use state, or idempotency.

### 14.5 Revocation And Emergency Stop

A controller cannot guarantee immediate revocation while a node is offline. User expiration and
revocation already included in applied state continue locally. For urgent provider action, `Pause`
stops new service locally without controller contact. `Unpair` additionally deletes credentials
and mappings. The installer registers a documented administrator command to stop and disable the
service if the UI is unavailable.

## 15. Service Packaging

### 15.1 Common Packaging Requirements

- Publish signed, versioned installers and per-platform checksums.
- Bundle or securely stage the matching pinned Xray binary.
- Install the agent as a dedicated service identity with least privilege.
- Keep the status UI unprivileged; elevation occurs only for install, firewall, service, update,
  and uninstall operations.
- Use a stable private local IPC protocol with peer identity checks and restrictive filesystem or
  named-pipe ACLs.
- Support clean upgrade without losing node ID, pairing identity, consent, limits, revisions,
  usage counters, or mapping ownership records.
- An uninstall flow asks whether to remove identity and history, but always stops Xray and removes
  product-owned firewall rules and router mappings first.
- Automatic updates accept only signed release manifests and packages, use staged replacement, and
  roll back if the new agent fails readiness. Xray cannot update independently from an approved
  Node Host release.

### 15.2 macOS

- Distribute a notarized universal `.pkg` containing a signed app for setup/status and a signed
  agent/Xray payload.
- Install the agent under `/Library/Application Support/Reality Node/` and register a root-owned
  `LaunchDaemon`. The UI remains in `/Applications` and communicates through a root-owned Unix
  socket.
- Run Xray as a dedicated `_realitynode` user where installer support permits. The agent retains
  only privileges required to manage that child and approved firewall/service state.
- Store node private credentials in the System Keychain with service-only ACLs. Store SQLite and
  logs under `/Library/Application Support/Reality Node/` and `/Library/Logs/Reality Node/` with
  restrictive ownership.
- Use a signed privileged helper or installer-managed rules for firewall changes; never invoke an
  arbitrary command supplied by the UI.
- LaunchDaemon `KeepAlive` restarts the agent, while the agent's own circuit breaker governs Xray.

### 15.3 Windows

- Distribute a signed x64/arm64 MSI or signed bootstrapper with explicit install scope and upgrade
  code.
- Install under `%ProgramFiles%\Reality Node\`; store mutable state under
  `%ProgramData%\Reality Node\`.
- Register `RealityNodeAgent` with the Service Control Manager using a virtual service account or
  least-privilege dedicated account. Do not run the status UI as `LocalSystem`.
- Protect private keys with machine-scope DPAPI and ACL them to the service SID and
  administrators.
- Use a service-SID-restricted named pipe for local IPC.
- Add one Windows Defender Firewall rule scoped to the admission-gate executable and TCP port,
  tagged with a stable rule group for transactional updates and uninstall cleanup.
- Configure SCM recovery for agent restart; application-level crash-loop handling remains in the
  agent.

### 15.4 Linux

- Provide signed `.deb` and `.rpm` packages for x86_64 and arm64. A tarball may be offered for
  advanced users but is not the easy-host path.
- Install binaries under `/opt/reality-node/` or distribution-appropriate immutable paths,
  configuration under `/etc/reality-node/`, state under `/var/lib/reality-node/`, and logs under
  the journal or `/var/log/reality-node/`.
- Create a locked `reality-node` system user and a hardened `systemd` unit with a private temp
  directory, no new privileges, protected home/system paths, bounded capabilities, restart limits,
  and explicit writable paths.
- Store private keys in root/service-readable files with mode `0600`, or use the distribution's
  system credential facility when available.
- Use a mode `0660` Unix socket owned by a dedicated local group for status UI/CLI access.
- Detect `firewalld`, `ufw`, or `nftables` but change rules only with explicit administrator
  approval. Unsupported firewall setups receive exact manual guidance and remain unverified until
  the external probe succeeds.
- Support headless pairing and consent through `reality-node setup` with the same disclosure and
  local-limit requirements as the graphical flow.

### 15.5 Upgrade Compatibility

The agent advertises protocol, desired-schema, state-schema, and Xray-config capabilities. An agent
must understand both its current state schema and the immediately previous schema during upgrade.
Database migrations are transactional and backed up before mutation. A controller never sends a
desired schema above the node's advertised maximum; instead it reports `upgrade_required`.

## 16. Security And Privacy Model

### 16.1 Threats Addressed

- Stolen or replayed pairing code: short expiry, one-time atomic consumption, attempt limit, TLS
  pinning, and two-party transcript confirmation.
- Controller account compromise: narrow signed desired schema, local provider ceilings, no remote
  shell, no arbitrary binary, and local pause/unpair.
- Node credential theft: OS secret storage, least-privilege identity, rotation, per-node revocation,
  and no reusable hardware identity.
- Malicious desired config: deterministic generation from a validated logical model, product-owned
  routing invariants, Xray validation, and rollback.
- Relay compromise: end-to-end VLESS + REALITY remains terminated at Xray on the node; relay is
  metadata-visible but payload-opaque.
- Router exposure: one consented TCP mapping, external verification, finite lease, and cleanup.
- Diagnostic leakage: structured redaction and no invitation, UUID, private key, full config, or
  payload logging.

### 16.2 Explicit Residual Risks

- A malicious or compromised node can observe traffic after Xray decrypts it and before it exits to
  the internet.
- A controller owner controls which friends receive credentials and can direct permitted policy
  within provider ceilings.
- A relay can correlate client and node timing and byte counts, refuse service, or corrupt streams.
- Home public IPs and traffic patterns are visible to direct clients and internet observers.
- Automatic port mapping depends on router implementations that may be buggy or insecure.
- Offline nodes cannot receive immediate controller revocation or policy changes.

These risks are shown in setup/help material rather than implied away by the easy-host experience.

## 17. Observability

### 17.1 Structured Events

The node emits locally sequenced events with stable codes:

- pairing started, confirmed, failed, certificate rotated, and unpaired;
- control connected/disconnected and sync rejected;
- desired received, validated, applied, rejected, rolled back, and rollback failed;
- Xray started, ready, exited, restart throttled, and stopped;
- endpoint discovered, mapping created/renewed/released, and mapping failed;
- direct/relay probe phase and result;
- provider paused/resumed, schedule transition, and limit reached;
- telemetry gap, disk pressure, update staged/applied/rolled back.

Each event includes node ID, local sequence, UTC time, monotonic uptime, revision where applicable,
agent/Xray version, result, duration, and a stable error code. Free-form strings are redacted and
bounded.

### 17.2 Metrics And Health

The controller receives low-cardinality summaries:

- last heartbeat and sync duration;
- control reconnect count;
- desired/applied revision lag and apply duration;
- Xray uptime, restart count, listener health, admission-gate streams, and current connections;
- direct and relay probe success/latency;
- mapping protocol, lease time remaining, and renewal failures;
- bytes/connections against provider limits;
- telemetry spool bytes/oldest age;
- agent/Xray version and update status.

Health is computed, not guessed from one heartbeat:

- `healthy`: applied revision current, Xray healthy, and selected endpoint recently verified;
- `syncing`: healthy service on an older revision while a newer revision is processing;
- `not_reachable`: local Xray healthy but no externally verified endpoint;
- `provider_paused` or `limit_reached`: intentional local stop;
- `degraded`: apply/rollback/runtime failure requiring attention;
- `offline`: heartbeat threshold exceeded.

### 17.3 Logs And Support Bundle

Local structured logs rotate at 10 MiB, retain five files, and default to informational level.
Verbose logging automatically expires after one hour. The provider can preview and export a
support bundle containing redacted logs, version/platform data, state-machine history, current
revision numbers and hashes, health summaries, and router/probe error codes.

The bundle excludes pairing artifacts, certificates, private keys, UUIDs, user labels, public IPs
unless separately approved, destinations, generated config, and traffic payloads. Upload is never
automatic. Controller-side event retention defaults to 30 days for node health and follows the
separate analytics policy for user traffic data.

### 17.4 Alerts

For a small friend network, alerts stay actionable and rate-limited. Notify the controller owner
and, where locally enabled, the provider when:

- a node remains offline or unreachable for 15 minutes;
- desired state remains unapplied for 10 minutes;
- rollback or repeated Xray crashes occur;
- a mapping lease cannot renew;
- 80% or 100% of a provider limit is reached;
- certificates or mandatory security updates approach expiry.

Repeated identical alerts collapse into one incident with recovery notification.

## 18. Controller And Node Data Model

Controller additions:

```text
nodes
  id, controller_instance_id, name, provider_label, pairing_state,
  certificate_status, desired_revision, applied_revision, health, last_seen_at

node_desired_snapshots
  node_id, revision, schema_version, snapshot_hash, signed_payload, created_at

node_endpoints
  node_id, kind, host, port, applied_revision, verification_state,
  last_probe_at, last_success_at, latency_ms

node_consent_receipts
  node_id, receipt_id, disclosure_version, capabilities, effective_limits, accepted_at

node_events
  node_id, sequence, code, revision, occurred_at, details
```

Node-local additions:

```text
identity
  node_id, controller_instance_id, certificate_ref, signing_key_ref

revision_state
  desired, received, validated, applied, applied_hash, failed, last_known_good

desired_snapshots
  revision, snapshot_hash, signed_payload, state, error_code

provider_policy
  consent_version, receipt_id, capabilities, limits, schedule, timezone

mapping_state
  interface_id, protocol, gateway, internal_port, external_host, external_port,
  lease_expires_at, ownership_token

telemetry_spool
  local_sequence, event_type, payload, occurred_at, acknowledged_at
```

Only the current received candidate, active revision, and last known good revision need complete
payload retention on the node. The controller may retain revision metadata for audit while pruning
superseded encrypted snapshots according to policy.

## 19. API Error Contract

Errors use stable machine codes, a safe provider message, retryability, and optional remediation.
Minimum codes include:

```text
pairing_expired
pairing_consumed
pairing_confirmation_mismatch
controller_identity_mismatch
certificate_revoked
desired_signature_invalid
desired_revision_conflict
desired_schema_unsupported
desired_policy_prohibited
xray_config_invalid
xray_start_failed
xray_unhealthy
rollback_failed
mapping_not_supported
mapping_conflict
mapping_lease_lost
direct_tcp_unreachable
direct_protocol_probe_failed
relay_not_consented
relay_grant_expired
relay_limit_reached
provider_paused
provider_limit_reached
local_state_corrupt
upgrade_required
```

Raw Xray/router/TLS errors remain in redacted local diagnostics and are not used as UI contracts.

## 20. Delivery Plan

1. Build the cross-platform service skeleton, local state/recovery journal, status UI/CLI, and
   signed package pipeline with Xray supervision.
2. Add one-time pairing, mTLS identity rotation, outbound sync, full desired snapshots, and the
   revision reconciler.
3. Add direct candidate discovery, external TCP and end-to-end probes, endpoint publication, and
   health history.
4. Add provider consent/limits, PCP/NAT-PMP/UPnP mapping, firewall integration, and offline quota
   enforcement.
5. Add bounded telemetry sync and redacted support bundles.
6. Add the optional opaque TCP relay behind explicit deployment, controller, and provider feature
   flags.
7. Run signed installer, upgrade, rollback, sleep/wake, NAT, and controller-outage matrices before
   calling the easy-host flow generally available.

Direct operation is the first release target. Relay must not delay a usable direct/manual-port-
forward host and must not be enabled until independent security review of tunnel admission and
flow-control behavior.

## 21. Acceptance Criteria

### 21.1 Pairing And Control Security

- A fresh installation pairs from link/code to confirmed node without manual certificate or JSON
  handling in under five minutes on a normal home connection.
- A pairing artifact succeeds once only, expires on schedule, rejects a sixth attempt, and cannot
  pair to a controller whose pinned identity differs.
- Hosting does not start until both provider and controller confirmations complete.
- Packet capture and socket inspection show no inbound node management listener.
- The controller cannot invoke an arbitrary command, write an arbitrary path, install an arbitrary
  binary, retrieve a REALITY private key, or raise a local provider ceiling.
- Pause and unpair work with the controller disconnected; unpair prevents reconnection with the old
  certificate.

### 21.2 Revision Convergence And Recovery

- Given applied revision N, a valid N+1 snapshot advances received, validated, and applied fields in
  order and acknowledgements survive process or OS restart.
- Duplicate delivery of the same revision/hash is idempotent; the same revision with a different
  hash is rejected and audited.
- Missing intermediate revisions do not block convergence to the latest full snapshot.
- Invalid Xray config never replaces the active config or interrupts the last-known-good process.
- A candidate that starts but fails health checks rolls back automatically and leaves
  `applied_revision` unchanged.
- Power loss at every journaled apply step recovers to either the prior applied revision or the
  fully committed candidate, never a mixed config/secret state.
- Controller loss for seven days leaves the last applied direct service operational while local
  schedule and quota enforcement continue.

### 21.3 Xray Lifecycle

- Packages execute only the pinned, checksum-verified Xray binary with owner-only config files.
- Start, stop, restart, boot recovery, crash backoff, circuit breaker, config rollback, and binary
  rollback pass automated integration tests.
- Xray API, Xray's direct inbound, and local IPC are unreachable from a second machine on the LAN;
  only the admission gate is public.
- Unexpected Xray exit is visible locally and at the controller with a stable redacted error code.
- No secret, invitation, generated config, user UUID, or payload appears in normal logs or support
  bundles.

### 21.4 Direct Reachability And Mapping

- A LAN-only listening socket never produces a publishable direct endpoint.
- A successful status requires both external TCP connection and end-to-end VLESS + REALITY canary
  traffic for the current revision and port.
- PCP, NAT-PMP, and UPnP test routers each create only one TCP mapping, renew it, recover after
  agent restart, and remove it on pause/unpair/uninstall where the protocol permits.
- Unsupported, conflicting, malformed, and permanent-only router behavior fails safely without
  deleting unrelated mappings or disabling a firewall.
- Public IP, gateway, interface, port, sleep/wake, and lease changes invalidate and retest the
  endpoint before publication.
- Three consecutive external failures remove the direct endpoint from new client bundles.

### 21.5 Relay

- Relay remains disabled after direct failure until provider consent is recorded.
- Relay can forward an unmodified end-to-end Xray session through a node-originated tunnel when the
  node has no inbound reachability.
- The relay cannot register arbitrary destination ports, authenticate an Xray user, or decrypt a
  captured session with the data it stores.
- Concurrency, rate, idle, and monthly byte limits are enforced at both node and relay; the lower
  limit wins.
- Backpressure tests with slow clients remain within configured per-stream and process memory
  bounds, and tunnel loss closes streams without cross-stream data leakage.
- Expired/revoked grants and unpaired node certificates cannot open or resume a tunnel.

### 21.6 Consent, Limits, And Offline Behavior

- The provider sees the required disclosure and explicit mapping/relay choices before activation.
- Provider pause takes effect locally within five seconds and cannot be overridden remotely.
- Schedule, metered-network, battery, admission-gate bandwidth/concurrency, and monthly-byte limits
  work while the controller is unavailable and survive reboot and clock rollback.
- Reaching a hard limit refuses new connections and reports a clear local/controller state without
  corrupting usage totals.
- A stale/offline node is removed from new Auto selections at the documented thresholds and
  reconciles to the latest full snapshot after reconnect.
- Telemetry retries create no duplicates; spool overflow reports a gap and never exhausts space
  reserved for config recovery.

### 21.7 Packaging And Operations

- Signed clean-install, upgrade, rollback, unpair, and uninstall tests pass on the two latest major
  macOS versions, supported Windows 10/11 editions, and current Ubuntu/Debian plus one RPM-based
  distribution on x86_64 and arm64 where supported.
- Reboot and user logout do not require the status UI or an interactive user session for service.
- Service identities cannot write outside documented state/log/runtime paths in platform security
  tests.
- Upgrade preserves identity, consent, limits, counters, desired/applied state, and mapping
  ownership; failed upgrade restores the prior working agent.
- A provider can generate a useful redacted support bundle and diagnose controller offline, Xray
  failure, router mapping failure, direct probe failure, relay limit, and provider pause without
  exposing secrets.
- A controller managing 20 nodes and 50 users remains responsive with 30-second jittered heartbeats,
  bounded telemetry batches, and simultaneous node reconnect after a one-hour outage.

## 22. Product Readiness Decision

Node Host is ready for a private friend network when direct hosting is reliable on all supported
platforms, provider controls remain authoritative offline, revision rollback survives forced power
loss, and diagnostics identify failures without exposing credentials. Relay is a separately gated
capability and is ready only after its consent, metadata disclosure, admission, limits, and
backpressure criteria pass. Neither successful local Xray startup nor a successful router API call
alone is sufficient evidence that a node is usable; only the external end-to-end reachability test
makes an endpoint publishable.
