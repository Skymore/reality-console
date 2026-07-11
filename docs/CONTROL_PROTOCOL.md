# Control Protocol

Status: authoritative initial HTTP contract. Field additions are backward-compatible; removals or
semantic changes require a new API version.

## 1. Transport And Conventions

- Base path: `/v1`.
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

Endpoint probes use an unguessable bounded challenge and return no control-plane data.

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

```json
{
  "displayName": "Friend Mac mini",
  "expiresInSeconds": 900
}
```

The response contains an invitation ID, expiry, and a single-use high-entropy enrollment secret.
The UI may encode it as a QR/deep link. A human-entered short code requires server-side rate limits
and is resolved to the high-entropy secret; six decimal digits alone are not a node credential.

### Enroll

`POST /v1/nodes/enroll`

```json
{
  "invitationSecret": "single-use-secret",
  "agentVersion": "0.1.0",
  "platform": "macos-arm64",
  "displayName": "Living room Mac",
  "capabilities": ["xray", "direct-tcp", "upnp", "relay-tcp"],
  "identityPublicKey": "base64url-ed25519-public-key",
  "encryptionPublicKey": "base64url-x25519-public-key",
  "nonce": "base64url-random-nonce",
  "proof": "base64url-signature-over-enrollment-transcript"
}
```

The transaction verifies and consumes the invitation, creates `nodeId`, issues the first node
credential, and writes an audit event. Concurrent consumption has exactly one winner. The proof
covers invitation purpose, controller origin, both public keys, nonce, software version, and
capabilities so it cannot be replayed for a different identity.

The enrollment proof uses a deterministic binary transcript. Every field is encoded as
`u16be(labelLength) || labelUtf8 || u32be(valueLength) || valueBytes`. The request domain is
`control/node-enrollment/request/v1`; fields are purpose, controller origin and fingerprint,
invitation ID and expiry, both node public keys, nonce, agent version, platform, display name,
sorted capabilities, and every provider-consent field. The response domain is
`control/node-enrollment/response/v1` and binds the request-transcript SHA-256 digest, network,
node and controller identities, issued credential, controller signing public key, and controller
nonce. The shared protocol crate is the only implementation of this encoding.

If the first success response is lost, repeating the exact signed enrollment with the same
invitation and node key pair returns `200 OK` with the existing node and credential identity. A
first successful enrollment returns `201 Created`. Reusing the invitation with a different key
pair returns `409 Conflict`; retry recovery never creates a second node or credential.

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

### Heartbeat

`POST /v1/nodes/{nodeId}/heartbeat`

```json
{
  "agentVersion": "0.1.0",
  "xrayVersion": "26.3.27",
  "state": "serving",
  "desiredRevision": 12,
  "receivedRevision": 12,
  "validatedRevision": 12,
  "appliedRevision": 12,
  "providerPaused": false,
  "endpoints": [
    {"mode": "direct", "address": "node.example.com", "port": 443, "status": "verified"}
  ],
  "telemetryCursor": 820
}
```

Heartbeat is a current-state report, not a command channel. The response may include polling and
minimum-version hints but not arbitrary executable instructions.

## 5. Desired State API

### Fetch

`GET /v1/nodes/{nodeId}/desired?afterRevision=11`

- `204 No Content`: no newer revision.
- `200 OK`: immutable signed desired-state envelope.
- `409 Conflict`: node has an unresolved newer local result that must be reconciled.
- `426 Upgrade Required`: agent cannot safely interpret current schema.

```json
{
  "schemaVersion": 1,
  "nodeId": "uuid",
  "revision": 12,
  "createdAt": "2026-07-11T20:00:00Z",
  "minAgentVersion": "0.1.0",
  "users": [
    {"userId": "uuid", "credentialId": "uuid", "vlessUuid": "secret", "enabled": true}
  ],
  "xray": {
    "listenPort": 443,
    "serverNames": ["www.microsoft.com"],
    "target": "www.microsoft.com:443"
  },
  "signature": "base64url-signature"
}
```

Node-local REALITY private keys are referenced or generated locally and are not transported in the
ordinary desired-state document.

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
are monotonic for a `(nodeId, revision)` result. Repeating the same result is idempotent.

## 6. Member And Bundle API

### Activate device

`POST /v1/device-activations/consume`

Consumes a one-time activation secret and returns account metadata, device ID, short-lived access
token, and a refresh credential. The refresh credential is shown once.

### Login

`POST /v1/sessions` accepts account credentials when password login is enabled. Rate limiting and
generic authentication failures prevent account enumeration.

### Refresh

`POST /v1/sessions/refresh` rotates the refresh credential. Reuse of an invalidated rotated token
revokes the session family.

### Fetch profile bundle

`GET /v1/me/profile-bundle`

Supports `If-None-Match`. The response includes bundle ID, issue/refresh/offline-expiry times,
account status, node profiles, selection hints, and a signature. It never includes node management
credentials or REALITY private keys.

### Logout

`DELETE /v1/me/devices/{deviceId}/session` revokes the current device session. Admin revocation and
member logout are separate audit actions.

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

## 10. Initial Implementation Slice

The first executable slice implements:

1. `GET /healthz`.
2. Admin-authenticated node invitation creation.
3. Atomic invitation consumption with proof-of-possession and node credential issuance.
4. Authenticated, replay-resistant heartbeat.
5. Desired-state fetch with `204` behavior.
6. Temporary-database integration tests for expiry, one-time use, auth, and idempotency.

Member accounts, bundles, telemetry, reachability, and relay are added in later phases without
changing the enrollment ownership model.
