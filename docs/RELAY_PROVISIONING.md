# Controller-Driven Relay Provisioning

Status: Stage 6 implementation contract.

## Product Contract

The operator configures a Relay service once. A provider may consent to relay use and choose local
limits during the ordinary Node Host setup. After that, Control and Node Host converge automatically.
The provider never enters a relay hostname, port, route ID, token, certificate, key, hash, JSON path,
or shell command. Its signed ensure request contains only finite local policy ceilings; Control
intersects them with static operator ceilings before issuing a grant.

The Relay remains a separate least-privileged raw-TCP process. It cannot call Control APIs, select a
node-local destination, read member credentials, or terminate VLESS/REALITY.

## Static Relay Configuration

One operator-owned static config defines:

- relay identity and public hostname;
- node-tunnel listen address and TLS server identity;
- public route port range with at least two ports for N/N+1 overlap, and operator maximum limits;
- a root-owned managed-route directory;
- a distinct owner-only monthly-quota state directory;
- reload interval and loopback metrics listener.

Control receives only the corresponding provisioning profile: relay ID, public/tunnel endpoints,
route directory, port range, client CA certificate/key location, and policy ceilings. These values
come from local process configuration, never an admin HTTP request.
The operator reserves at least two public ports per concurrently active relay node so one
generation can remain live while its successor registers; exhaustion rejects issuance without
revoking an existing route.

## Durable Grant

A relay grant is a monotonic controller record bound to:

- network, node, relay, route, endpoint, and generation IDs;
- node enrollment identity and current relay consent version;
- public endpoint and node-tunnel endpoint;
- issue/not-before/expiry timestamps no longer than 24 hours;
- concurrent stream, aggregate bandwidth, per-connection bytes, and monthly-byte ceilings;
- SHA-256 of the route token and exact relay client certificate;
- status `pending`, `published`, `revoking`, `revoked`, or `expired`.

Raw route tokens and relay TLS private keys are generated in bounded memory, encrypted immediately
to the enrolled node's X25519 key with grant-bound HPKE AAD, and zeroized. Control persists only the
authenticated ciphertext and non-secret hashes/metadata. Central backup cannot decrypt a node's
grant without that node's installation identity.

## Relay Route Publication

Control writes one strict, non-secret route document per active generation to the root-owned managed
route directory. The document contains only the route ID, node ID, public listener, expiry, limits,
token digest, and client-certificate digest. It is signed by the controller and written with
create-new temporary file, `fsync`, atomic rename, and parent-directory `fsync`.

The logical `routeId` remains stable across credential rotation. The exact `grantId` is the route
registration ID used on the Node Host/Relay tunnel and the managed filename is exactly
`<grantId>.relay-route.json`. This lets generations N and N+1 coexist on distinct public ports while
the new path is registered and canaried; removing N revokes only N.

The Relay watches both static config and managed-route directory. It validates every signature and
closed field before replacing its route map. Invalid or partial updates preserve the last-known-good
map. Removal/replacement cancels the old tunnel and streams. Static TLS/listener changes still
require service restart.

Relay enforces each generation's monthly-byte ceiling across both directions before forwarding
bytes. Reservations are persisted with an owner-only atomic state file, so restart and hot reload
cannot reset usage; the final allowed frame is truncated at the exact boundary and later streams
are refused. UTC month rollover is monotonic across clock rollback, and corrupt or unwritable quota
state fails closed. Because accounting keys use `grantId`, N and N+1 retain independent finite
allowances during rotation.

Database state is authoritative and route publication is a replayable outbox:

1. Commit `pending` grant and encrypted node assignment.
2. Reconciler atomically writes the route document.
3. Observe the exact document digest from the managed directory.
4. Mark the generation `published`.
5. Only then return it to Node Host.

Publishing N+1 does not revoke N. After Node Host has durably installed N+1 and the connector has
actually reached `Registered`, it sends a signed acknowledgement containing the exact `grantId`
and generation to `POST /v1/nodes/{nodeId}/relay-assignment/acknowledge`. Control rejects stale,
wrong-node, expired, or non-current acknowledgements, then queues only older published generations
of that logical route for revocation. Exact retries are idempotent.

Revocation is fail closed: mark `revoking`, remove the route document, observe its absence, then mark
`revoked`. Startup reconciliation repairs every intermediate state.

## Node Assignment Sync

An authenticated node fetches its signed encrypted assignment using the existing signed-request
identity. The response is cacheable only by generation and never returned to admin/member APIs.
Node Host verifies the controller signature and binding, decrypts with its installation X25519 key,
validates the relay TLS material and policy ceilings, then installs an owner-only material generation
atomically. The current manual assignment-file command remains a development/recovery tool and is
not part of the provider journey.

The local managed state contains only signed encrypted assignment artifacts, non-secret metadata,
digests, and generation pointers. Decrypted route tokens and private keys exist only in owner-only
runtime generation files and are never stored in SQLite or logs. On restart, Node Host revalidates
the signed artifact and material digest before reconnecting. A successor is not acknowledgement-
eligible merely because it was registered before a crash; the new service process must observe it
as `Registered` again.

No relay candidate is reported until all are true:

- provider relay consent and local policy permit sharing now;
- grant is unexpired and `published`;
- exact desired revision is applied and local admission is healthy;
- connector mTLS and route registration reach `Registered`.

Control applies the ordinary TCP plus VLESS/REALITY canary to that exact endpoint/revision before any
member bundle includes it.

## Rotation And Outage

Control creates generation N+1 alongside N, publishes N+1, lets the node acknowledge successful
registration, then revokes N. The Relay never accepts two active tunnels for one generation. Expiry fails closed.
Control outage leaves an already installed grant usable only until expiry; it cannot extend itself.
Relay outage affects no direct candidate. Provider pause withdraws the connector immediately even
when Control is unavailable. Transport failure retains current and successor generations for safe
retry, while an authenticated `204`, explicit authentication denial, consent withdrawal, or local
expiry removes the managed candidate fail closed. Heartbeat checks the latest durable pointer, so a
connector being asynchronously stopped can never republish a withdrawn endpoint.

Relay assignment reconciliation is not a prerequisite for ordinary Control sync. A missing relay
profile (`404`), Relay/Control provisioning `5xx`, network failure, DNS failure, or invalid relay
artifact emits only the stable local `relay_assignment_sync_failed` condition; Node Host continues
telemetry, heartbeat, desired-state fetch, direct mapping, and direct service. Authentication denial
withdraws only relay state first, then ordinary signed heartbeat determines whether the node
credential itself has actually been revoked. Response bodies and secret material are never logged.

## Required Tests

- no grant without node capability plus current provider consent;
- HPKE wrong-node, wrong-generation, replay, tamper, and expiry rejection;
- crash/restart at every outbox and node-install phase;
- route file symlink/owner/signature/partial-write rejection;
- published assignment -> registered connector -> real opaque stream -> protocol canary;
- direct failure leaves relay healthy and relay failure leaves direct healthy;
- pause, rotation, revocation, node disable, node removal, and grant expiry withdraw only the exact
  route and never expose raw secret material.
