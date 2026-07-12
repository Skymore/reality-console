# Control Protocol

Status: authoritative initial HTTP contract. Field additions are backward-compatible; removals or
semantic changes require a new API version.

## 1. Transport And Conventions

- Base path: `/v1`; one-action Node Host enrollment uses `/v2/nodes/enroll` because its signed
  transcript adds node-local public REALITY material.
- JSON request and response bodies use `camelCase`.
- HTTPS is mandatory outside loopback development.
- IDs are lowercase UUID strings. Time values are RFC 3339 UTC strings unless a field explicitly
  uses Unix seconds.
- Mutating requests carry `Idempotency-Key` when retry is possible.
- Responses carry `X-Request-Id`; clients include it in diagnostics.
- Secrets are returned only at creation or rotation time and never by list/get endpoints.

## 2. Authentication Classes

### Administrator

Initial bootstrap uses an operator-provided high-entropy token. The production flow exchanges an
admin credential for a bounded session. Admin sessions authorize user, node, invitation,
assignment, and revision operations.

### Node

Enrollment consumes a one-time invitation and binds a node-generated asymmetric identity to a
unique `nodeId`. Subsequent requests prove possession of that identity, bind to `nodeId`, and are
rejected after revocation. Direct deployments may use a short-lived client certificate; requests
that cross an HTTP tunnel retain end-to-end application signatures because the tunnel cannot be
trusted to assert node identity. Credential rotation overlaps old/new credentials for a bounded
period.

### Member device

Activation or login creates a device-scoped refresh session. Short-lived access tokens authorize
only the current account, device, bundle, and logout operations. Device sessions are independently
revocable.

### Public probe

TCP preflight jobs use an unguessable finite claim token between Control Service and the selected
runner, send no application bytes to the candidate, and return no control-plane data. A later
protocol-aware probe additionally uses a bounded canary credential/challenge. Neither credential is
available from ordinary node or member read APIs.

The optional external TCP executor uses schema 1 with an unrelated request UUID, one to six unique
controller-resolved public IPv4 literals, the public port from the node's signed applied revision,
and a timeout from 100 to 10,000 milliseconds. It receives no node/member identity, hostname,
REALITY material, VLESS credential, or durable database claim token. Its response echoes the
request UUID and returns only `connected`, `unreachable`, `timedOut`, or `executorFailed`; a
connected address must be one of the exact requested literals. Unknown fields and non-public,
duplicate, non-canonical, port-25, oversized, or unsupported-schema requests fail closed.

## 3. Stable Error Envelope

```json
{
  "error": {
    "code": "invitation_expired",
    "message": "The invitation has expired.",
    "requestId": "2f55c837-7be6-4752-b58a-a7f51401bd89",
    "retryable": false,
    "details": {}
  }
}
```

Renderers translate `code`; server messages are safe diagnostics without secrets. Unknown codes
fall back to a generic localized error.

## 4. Node Enrollment API

### Create invitation

`POST /v1/admin/node-invitations`

Requires `Idempotency-Key`. An exact retry returns the identical invitation delivery without
storing its plaintext secret; reusing the key with another request returns
`idempotency_key_conflict`.

```json
{
  "displayName": "Friend Mac mini",
  "expiresInSeconds": 900,
  "initialConfiguration": {
    "minAgentVersion": "0.1.0",
    "xray": {
      "listenPort": 10443,
      "publicPort": 8443,
      "serverNames": ["www.microsoft.com"],
      "target": "www.microsoft.com:443"
    }
  }
}
```

```json
{
  "displayName": "Friend Mac mini",
  "expiresAt": "2026-07-11T20:15:00Z",
  "setupCode": "pn-node-v1.base64url-payload",
  "setupLink": "https://control.example/join/node#pn-node-v1.base64url-payload"
}
```

The response deliberately omits raw invitation fields. `setupCode` and the fragment portion of
`setupLink` are the same 256-bit one-time bearer material and must be shown only at creation. The
fragment is not sent in an HTTP request or Referer. Node Host accepts either value, verifies that a
link origin exactly matches the invitation's pinned controller origin, and keeps the material in
memory. The code is intentionally long; a human-short code would require a separate rendezvous
service, online lookup, attempt throttling, and abuse controls.

`initialConfiguration` is optional only for diagnostic/manual enrollment. Its presence records the
administrator's explicit pre-approval. A successful compatible enrollment then activates the node
and publishes revision 1 atomically; it never makes the node member-shareable without later
protocol verification.

### Enroll

`POST /v1/nodes/enroll` is the legacy/manual flow without `publicMaterial`.

`POST /v2/nodes/enroll` is the one-action flow and requires node-local public REALITY material.

```json
{
  "invitationSecret": "single-use-secret",
  "agentVersion": "0.1.0",
  "platform": "macos-arm64",
  "displayName": "Friend Mac mini",
  "capabilities": ["xray", "direct-tcp", "pcp", "nat-pmp", "upnp"],
  "identityPublicKey": "base64url-ed25519-public-key",
  "encryptionPublicKey": "base64url-x25519-public-key",
  "publicMaterial": {
    "realityPublicKey": "base64url-x25519-public-key",
    "realityShortId": "0123456789abcdef"
  },
  "nonce": "base64url-random-nonce",
  "proof": "base64url-signature-over-enrollment-transcript",
  "providerConsent": {
    "policyVersion": "2026-07-11",
    "hostOwnerConsented": true,
    "exitIpDisclosureAccepted": true,
    "routerMappingAccepted": true,
    "acceptedAt": "2026-07-11T20:00:00Z"
  }
}
```

The transaction verifies the invitation-bound display name, consumes the invitation, creates
`nodeId`, issues the first node credential, and writes an audit event. Concurrent consumption has
exactly one winner. A preconfigured invitation additionally requires `xray`, `direct-tcp`, and
public REALITY material, then activates the new node and publishes the complete initial revision in
that same transaction. Any insert, activation, publication, or audit failure rolls back the node,
revision, and invitation consumption together.

The REALITY private key never leaves Node Host. Public material is generated only after the signed
installer's Xray binary passes checksum and version verification, and is covered by the node's
enrollment proof. Administrator node summaries expose only `publicMaterialReady`, never the public
key or short ID; those values are read internally when building a verified member profile.
PCP, NAT-PMP, or UPnP capabilities require `direct-tcp` and
`providerConsent.routerMappingAccepted=true`; a node cannot advertise router-changing behavior
without binding the provider's choice into its proof.

The enrollment proof uses a deterministic binary transcript. Every field is encoded as
`u16be(labelLength) || labelUtf8 || u32be(valueLength) || valueBytes`. The request domain is
`control/node-enrollment/request/v1` for a request without public material and
`control/node-enrollment/request/v2` when public material is present. Fields are purpose,
controller origin and fingerprint,
invitation ID and expiry, both node public keys, nonce, agent version, platform, display name,
sorted capabilities, optional REALITY public material, and every provider-consent field. The
response domain is
`control/node-enrollment/response/v1` and binds the request-transcript SHA-256 digest, network,
node and controller identities, issued credential, controller signing public key, and controller
nonce. The shared protocol crate is the only implementation of this encoding.

If the first success response is lost, repeating the exact signed enrollment returns `200 OK` with
the existing node and credential identity. Recovery compares node keys, public REALITY material,
platform, capabilities, consent version/choices/time, and invitation-bound display name. Changing
one of those fields returns `409 Conflict`; it is never silently accepted as the original attempt.
A first successful enrollment returns `201 Created`.

Node Host migration 12 persists the complete consent receipt before network I/O, so retry uses the
same `acceptedAt` and choices rather than manufacturing a new ceremony. A new invitation may
replace that receipt only while the installation is still unenrolled and the provider confirms the
choices again.

Administrator node summaries include one conservative `onboardingState`:
`awaitingApproval`, `awaitingHeartbeat`, `awaitingConfiguration`, `applyingConfiguration`,
`awaitingEndpoint`, `checkingEndpoint`, `ready`, `paused`, `needsAttention`, or `unavailable`.
`ready` requires a current controller-owned protocol verification. Enrollment, background-service
registration, Xray startup, and bare TCP reachability cannot produce it.

### Authenticated node requests

Every node request uses either mutually authenticated TLS or these end-to-end headers:

- `X-Node-Id`
- `X-Node-Key-Id`
- `X-Node-Timestamp`
- `X-Node-Nonce`
- `X-Node-Signature`

The signature covers method, normalized path and query, timestamp, nonce, SHA-256 body digest, and
controller instance ID. The service rejects revoked keys, clock skew outside the configured
window, repeated nonces, path/body substitution, and a node ID that does not own the key. Nonces
are retained for at least the accepted clock-skew window.

Version 1 uses the same labeled length-prefix encoding as enrollment, with domain
`control/node-request/v1`. Fields are uppercase method, canonical origin-form path and raw query,
canonical RFC 3339 UTC timestamp, unpadded base64url nonce, raw 32-byte body SHA-256 digest, and
controller instance ID. The shared protocol rejects absolute URLs, fragments, dot or repeated path
segments, ambiguous percent encoding, oversized request targets, unsupported methods, and
non-canonical header values before signature verification.

### Heartbeat

`POST /v1/nodes/{nodeId}/heartbeat`

```json
{
  "heartbeatGeneration": 184,
  "agentVersion": "0.1.0",
  "xrayVersion": "26.3.27",
  "state": "serving",
  "desiredRevision": 12,
  "receivedRevision": 12,
  "validatedRevision": 12,
  "appliedRevision": 12,
  "providerPaused": false,
  "endpoints": [
    {
      "endpointId": "6e005b7a-531b-4e92-a11d-39f47d12e461",
      "mode": "direct",
      "source": "pcp",
      "address": "node.example.com",
      "port": 443,
      "appliedRevision": 12,
      "observedAt": "2026-07-11T20:00:00Z",
      "expiresAt": "2026-07-11T21:00:00Z"
    }
  ],
  "telemetryCursor": 820
}
```

Heartbeat is a current-state report, not a command channel. The response may include polling and
minimum-version hints but not arbitrary executable instructions.

`heartbeatGeneration` is a positive, durable sequence allocated before network I/O and is
independent from `telemetryCursor`. Control accepts only a generation newer than the durable one.
An older generation returns `state_stale`; an exact retry of the same generation and canonical
snapshot is an idempotent success; reusing one generation for different state returns
`state_conflict`. Gaps after failed requests or crashes are valid.

Heartbeat endpoints are unverified candidates, not probe results. Each candidate identity binds
one exact mode, source, address, port, applied revision, observation time, and optional manual or
required finite mapping/relay lease. A withdrawn identity cannot be reused for changed endpoint
state. Nodes never send `status`; the closed candidate schema rejects a forged `verified` field.
Only controller-owned external probe state can make a candidate eligible for a profile bundle.

After durably accepting a heartbeat, Control returns `200 OK` with a controller-signed, redacted
self-status bound to that exact heartbeat generation:

```json
{
  "document": {
    "schemaVersion": 1,
    "nodeId": "uuid",
    "heartbeatGeneration": 184,
    "observedAt": "2026-07-11T20:00:01Z",
    "lifecycle": "active",
    "endpoints": [
      {
        "endpointId": "6e005b7a-531b-4e92-a11d-39f47d12e461",
        "readiness": "tcpReachable",
        "lastCheckedAt": "2026-07-11T20:00:01Z",
        "errorCode": null
      }
    ],
    "signingKeyId": "uuid",
    "controllerInstanceId": "uuid"
  },
  "signature": "base64url-signature"
}
```

The closed response schema exposes only `pending` or `active` lifecycle and current candidate IDs.
Endpoint readiness is one of `pending`, `checking`, `tcpReachable`, `tcpUnreachable`, or
`verified`. `tcpReachable` proves only that an external runner completed a TCP connection;
`verified` requires current end-to-end protocol-canary evidence. A failed check includes only a
bounded stable `errorCode`, never an address, probe token, raw error, or credential.

The canonical signature transcript uses domain `control/node-heartbeat-status/v1` and binds the
schema, node ID, exact heartbeat generation, observation time, lifecycle, uniquely sorted endpoint
records, signing-key ID, and controller-instance ID. The node verifies the closed schema, all
identity bindings, and the signature against the controller key pinned at enrollment before it
persists or displays the status. A legacy `204 No Content` remains a successful heartbeat with
controller status unknown; it is never interpreted as approval or reachability. A heartbeat never
approves a pending node, and revision, heartbeat, plus telemetry cursors cannot move backward.

### Operator node lifecycle

All operator endpoints require administrator authentication:

- `GET /v1/admin/nodes` returns node identity, status, consent, version, runtime, revision, and
  telemetry summaries. It never returns node public keys, credential identifiers, or secret
  material.
- `POST /v1/admin/nodes/{nodeId}/approve` changes `pending` to `active`; approving an already
  active node is idempotent.
- `POST /v1/admin/nodes/{nodeId}/disable` changes `pending` or `active` to `disabled`; disabling an
  already disabled node is idempotent.
- `POST /v1/admin/nodes/{nodeId}/revoke` changes any non-revoked node to `revoked` and atomically
  revokes every node authentication credential; repeating it is idempotent.

Unknown or non-canonical node IDs return `404 Not Found`. Disallowed transitions return
`409 Conflict`. Disabled and revoked nodes cannot authenticate control requests. Every accepted,
idempotent, or rejected transition for a known node writes a redacted audit event. The current API
does not reactivate a disabled node; that requires a future explicit credential-recovery flow.

## 5. Desired State API

### Publish

`POST /v1/admin/nodes/{nodeId}/desired-state`

```json
{
  "minAgentVersion": "0.1.0",
  "xray": {
    "listenPort": 10443,
    "publicPort": 443,
    "serverNames": ["www.microsoft.com"],
    "target": "www.microsoft.com:443"
  }
}
```

The administrator supplies only closed Xray settings. A caller-provided `users` field is rejected;
Control Service compiles the complete member list from active accounts, enabled assignments, and
pending/active per-node credentials. Only an `active` node can receive a revision. Publication
canonicalizes ordered fields, allocates the next network revision, signs the exact node document,
stores its artifact and member snapshot immutably, updates that node's authoritative desired
revision, and writes a secret-free audit event in one transaction.

The `201 Created` administrator response is redacted and contains only `nodeId`, `revision`,
`schemaVersion`, `createdAt`, `userCount`, and `created: true`. The signed artifact and member UUIDs
are returned only from the node-authenticated fetch route.

### Reconcile

`PUT /v1/admin/nodes/{nodeId}/reconcile`

Recompiles the authoritative member set while preserving the latest verified Xray settings. It
returns `200 OK` with the same redacted revision when the latest target already matches and is not
terminally failed. It publishes and returns `201 Created` only after `rejected`/`rolledBack` or when
the immutable member snapshot differs. Repeating a successful retry before another state change is
therefore naturally idempotent.

### Fetch

`GET /v1/nodes/{nodeId}/desired?afterRevision=11`

- `204 No Content`: no newer revision.
- `200 OK`: immutable signed desired-state envelope.
- `409 Conflict`: node has an unresolved newer local result that must be reconciled.
- `426 Upgrade Required`: agent cannot safely interpret current schema.

```json
{
  "document": {
    "schemaVersion": 2,
    "networkId": "uuid",
    "nodeId": "uuid",
    "revision": 12,
    "createdAt": "2026-07-11T20:00:00Z",
    "minAgentVersion": "0.1.0",
    "users": [
      {"userId": "uuid", "credentialId": "uuid", "vlessUuid": "secret", "enabled": true}
    ],
    "xray": {
      "listenPort": 10443,
      "publicPort": 443,
      "serverNames": ["www.microsoft.com"],
      "target": "www.microsoft.com:443"
    },
    "signingKeyId": "uuid",
    "controllerInstanceId": "uuid"
  },
  "signature": "base64url-signature"
}
```

Node-local REALITY private keys are referenced or generated locally and are not transported in the
ordinary desired-state document. The canonical signature transcript binds the exact network, node,
controller epoch, revision, publication time, agent floor, ordered users, ordered server names,
closed Xray fields, and signing-key ID. Changing or reordering any covered value invalidates the
signature.

Desired-state schema version 1 remains readable only for rollback compatibility and has no public
admission port. Version 2 defines `listenPort` as the unprivileged loopback-only Xray port and
requires a distinct non-zero `publicPort` owned by the admission gate. Controllers publish only
version 2; Node Host verifies both versions while retained version-1 artifacts exist.

Node Host accepts `200` only as JSON matching the closed schema and only after exact network, node,
controller epoch, monotonic revision, and controller-signature verification. It atomically stores
the immutable envelope plus envelope/transcript digests, advances its durable cursor, and reports
`received`. Receipt does not imply validation or Xray activation.

### Report result

`PUT /v1/nodes/{nodeId}/revisions/{revision}/result`

```json
{
  "state": "applied",
  "configDigest": "sha256:...",
  "startedAt": "2026-07-11T20:00:02Z",
  "completedAt": "2026-07-11T20:00:04Z",
  "errorCode": null,
  "rollbackRevision": null
}
```

Valid states are `received`, `validated`, `applied`, `rejected`, and `rolledBack`. State transitions
are monotonic for a `(nodeId, revision)` result. Repeating the same result is idempotent. If a
result request fails after local receipt, Node Host retains it and retries it before sending a
heartbeat that advertises the new revision. `applied` must use the digest reported by `validated`.
`rolledBack` requires the failed revision to have reached `validated` and the restored earlier
revision to have reached `applied` with the same restored-config digest.

## 6. Member And Bundle API

### Administrator account management

- `POST /v1/admin/accounts` creates one logical account from a bounded display name and requires a
  bounded `Idempotency-Key`. An exact retry returns the original `201` body; reusing the key with a
  different request returns `idempotency_key_conflict`. It returns no password, VLESS UUID,
  refresh credential, or device key.
- `GET /v1/admin/accounts` returns safe account metadata and complete assignments sorted by node
  ID.
- `PUT /v1/admin/accounts/{userId}/nodes` atomically replaces the enabled node set. The request is
  a duplicate-free list of at most 100 node IDs; clients never submit assignment IDs or VLESS
  credentials. Omitted existing assignments become disabled, newly requested nodes receive stable
  assignments and distinct controller-generated credentials, and unchanged entries remain
  idempotent. Every changed active node receives a complete signed target in the same database
  transaction; a missing baseline Xray configuration rolls back the whole multi-node mutation.
- `PUT /v1/admin/accounts/{userId}/status` explicitly changes `active` or `disabled`, or applies the
  terminal `deleted` tombstone. Account status gates every session and desired-state credential
  independently of cached assignment state.

Account mutations require administrator authentication, use canonical UUID paths, and write
redacted audit events. A safe account summary contains only account identity, display name,
lifecycle, assignment identity/node/status, provisioning state, and timestamps. Assignment status
is authorization intent; `provisioningState` independently reports `pending`, `applied`,
`removalPending`, `removed`, or `notProvisioned` and must drive operator UI claims. `applied` and
`removed` require exact revision-result evidence, not heartbeat freshness or a database status flag.

### Activate device

`POST /v1/admin/accounts/{userId}/device-activations` requires administrator authentication and a
bounded `Idempotency-Key`. Its `201` response contains only `displayName`, `expiresAt`, `setupCode`,
and `setupLink`. The `pn-member-v1` code binds the account/network/activation IDs, strict Control
origin, controller instance, bundle-signing public key, expiry, and one-time secret. The HTTPS link
uses `/join/connect#setup-code`, so the bearer fragment is not sent in an HTTP request. Raw
activation fields are not returned as parallel JSON properties, and the secret is never stored in
plaintext.

`POST /v1/device-activations/consume`

Consumes a one-time activation secret plus a device-generated Ed25519/X25519 identity and signed
proof. It returns account metadata, device ID, short-lived access token, and rotating refresh
credential. An exact retry with the same device request reconstructs the same response after a lost
HTTP response; changed device material after consumption is rejected.

### Login

`POST /v1/sessions` accepts account credentials when password login is enabled and requires an
`Idempotency-Key`. The key and canonical request identify one crash-recoverable device enrollment;
an exact concurrent or post-restart retry returns byte-identical credentials without storing raw
tokens. Reusing the key for changed credentials or device proof is an idempotency conflict. Generic
authentication failures prevent account enumeration.

### Refresh

`POST /v1/sessions/refresh` also requires an `Idempotency-Key`. The replay scope is the refresh
family and source generation. The same key and current request reconstruct the same replacement
credentials after response loss; using the prior token with a different key is reuse and revokes
the complete session family. Connect persists the pending key beside the source refresh generation
before network I/O and clears it only after the replacement is durable in the OS credential store.

### Fetch profile bundle

`GET /v1/me/profile-bundle`

Supports `If-None-Match`. Each immutable response is signed by the pinned controller identity and
encrypts every node profile to the exact device X25519 key using HPKE base mode with X25519,
HKDF-SHA256, and ChaCha20-Poly1305. It includes bundle/generation identity,
issue/refresh/offline-expiry times, complete account state, selection hints, and the complete
permitted node set. A node is included only when the exact assignment credential appears in its
last applied snapshot and its endpoint has current controller-owned protocol verification. Desired,
TCP-only, stale, disabled, or removed candidates never enter a bundle. Node management credentials
and REALITY private keys are never present.

### Logout

`DELETE /v1/me/devices/{deviceId}/session` revokes the current device session. Admin revocation and
member logout are separate audit actions. `POST /v1/admin/devices/{deviceId}/revoke` additionally
rotates the account's credentials on every enabled node and publishes replacement revisions, so a
lost device's cached profile converges to data-plane invalidity. Password/session reset applies the
same cross-node rotation fence.

## 7. Telemetry Protocol

`POST /v1/nodes/{nodeId}/telemetry-batches`

Each batch has `firstSequence`, `lastSequence`, and ordered events. The server transaction accepts a
new contiguous suffix, ignores exact duplicates, and rejects gaps with `expectedSequence`.

Traffic events contain deltas, never cumulative values after normalization. Connection events are
optional and exclude payloads and full URLs. The response acknowledges the highest durably
committed sequence so the node can delete its local prefix.

## 8. Polling And Backoff

- Desired state: 15 seconds while pending, 60 seconds while stable, plus bounded jitter.
- Heartbeat: 30 seconds while serving; immediate on important state transitions.
- Telemetry: every 60 seconds or when a bounded batch fills.
- Client bundle: startup, explicit refresh, and every 6 hours while active.
- Retry: exponential backoff with jitter and a maximum interval; authentication and schema errors do
  not retry indefinitely.

Server-provided intervals are hints within client safety bounds. Polling resumes from durable local
revision and telemetry cursors after restart.

## 9. Compatibility

Every agent/client sends its semantic version and supported schema versions. The service maintains
at least one previous schema during rolling upgrades. A node never applies unknown fields whose
semantics affect security; it rejects incompatible required features with a stable error code.

## 10. Current Implementation Slice

The executable Control Service includes health, node invitation/enrollment, replay-resistant node
authentication, signed heartbeat status, immutable signed desired revisions, monotonic rollout
results, node lifecycle controls, and controller-owned TCP preflight state. Account migrations 9
and 10 implement administrator account creation/listing, terminal account lifecycle, atomic
multi-node target compilation, stable assignments, durable account-creation idempotency, immutable
per-revision member snapshots, apply-driven credential activation/removal, explicit provisioning
state, and distinct per-node VLESS credentials.

Control migration 11 and Node Host migration 12 implement idempotent setup-code/link delivery,
strict v2 enrollment with node public REALITY material, invitation-bound consent replay,
pre-approved initial revision publication, and conservative onboarding progress. A real
Control-to-Node Host integration test covers creation through initial revision validation.

Control migration 12 implements idempotent member setup delivery, activation/password device
sessions, refresh-family replay/reuse handling, member authentication, device revoke/reset, and
signed per-device HPKE bundles. Connect implements process-local setup handles, native credential
storage, an authenticated two-generation offline cache, bounded node probes, selection policy, the
existing Xray supervisor path, automatic six-hour sync, and offline registry reconstruction. The
production protocol-aware endpoint canary, relay, telemetry aggregation, system-proxy recovery,
and signed packages remain later work. An `applied` assignment still cannot enter a Connect bundle
until that endpoint is controller-verified.
