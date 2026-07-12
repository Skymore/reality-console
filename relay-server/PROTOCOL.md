# Relay Tunnel Protocol v1

`pn-relay-v1` multiplexes fixed-route raw TCP streams over one node-originated mTLS connection. It
is not VLESS, SOCKS, HTTP CONNECT, a generic reverse proxy, or a destination-selection protocol.
Payloads are opaque VLESS + REALITY bytes; TLS/VLESS/REALITY still terminate only at node Xray.

## Controller-Managed Route Registry

The optional managed registry consumes exactly the shared protocol `SignedRelayRoute` JSON schema.
It does not accept unsigned route fragments or derive trust from filenames. One static relay config
pins the relay ID, controller Ed25519 public key, local public-listen IP, public-port range, and route
ceilings. A document is accepted only when all of these checks succeed:

- the JSON has no unknown fields and the shared schema/header validation succeeds;
- `signingKeyId` matches the pinned key and the controller signature verifies;
- the relay ID matches this relay; valid but not-yet-active or expired documents remain in the
  authenticated snapshot but do not create a listener;
- the public port is in the configured range and all signed limits are at or below local ceilings;
- grant/generation identities and public ports are unique across the active managed plus static
  route set.

The route directory and every file are bounded and owner-only. Filenames are exactly
`<grantId>.relay-route.json` and must match the signed `grantId`; symlinks, other file names/types,
owner or mode mismatches, empty/oversized files, and files changed while opening are rejected. The
directory fingerprint hashes sorted names, exact file bytes, and each document's current active bit,
so it changes at `notBefore` and `expiresAt` without requiring a file mutation.

Startup fails closed if the complete directory is invalid. During polling, parsing and validation
are transactional: one invalid, partial, conflicting, or unverifiable entry preserves the entire
last-known-good map. A valid removal or replacement updates the complete map and cancels the exact
old listener, tunnel, and streams before the replacement becomes authoritative.

## Transport And Authentication

- Node Host connects outbound to the configured relay TCP address using TLS 1.2 or newer.
- ALPN is exactly `pn-relay-v1`.
- Relay verifies the client certificate against its configured CA and then binds the leaf
  certificate SHA-256 fingerprint to one route.
- The first application frame supplies the generation-scoped opaque `grantId` plus a high-entropy
  route token. Logical `routeId` remains stable, while predecessor and successor grants can coexist
  during rotation.
  Relay stores only the token SHA-256 and compares both digests in constant time.
- A route grant has a fixed public listener, expiry, concurrency, rate, and per-connection byte
  limit. A valid reconnect replaces the prior tunnel for that route.

## Managed Monthly Quota

Each controller-managed grant carries a finite `monthlyByteLimit`. Relay counts opaque payload bytes
in both directions against that generation-scoped grant ID. Before forwarding a payload chunk, it
atomically reserves up to the remaining allowance in an owner-only crash-safe local ledger. A
partial final chunk is truncated to the exact remaining allowance and then the stream closes with
`relay_limit_reached`; subsequent member streams are refused before `OPEN`.

The accounting period is the UTC calendar month. A persisted clock high-watermark prevents a wall
clock rollback from returning a route to an earlier month's allowance. Route reloads reuse the same
record, restarts reload it, and N/N+1 grant IDs have independent records. Retired records are kept
for 62 days, then removed subject to a fixed hard record ceiling. Invalid permissions, malformed or
oversized JSON, a leftover interrupted-write file, record-capacity exhaustion, or a persistence
error fails managed quota admission closed. The ledger contains only opaque grant IDs, month,
aggregate bytes, and retirement time; no token, certificate, member, destination, or payload data.

The public member listener does not add a relay handshake because doing so would modify bytes seen
by Xray. Possession of a profile selects the dedicated route endpoint; the node's VLESS inbound
performs member authentication. The relay never receives member UUIDs.

## Frame Encoding

Every frame is a 4-byte big-endian body length followed by:

```text
u8 protocol_version = 1
u8 kind
u64 stream_id, big endian
u8 payload[body_length - 10]
```

The configured maximum is checked before allocation. Stream `0` is tunnel control. Relay-created
logical streams use nonzero odd IDs. Frames with the wrong direction, ID class, payload length, or
version close the tunnel with a stable protocol error.

| Kind | Value | Direction | Payload |
| --- | ---: | --- | --- |
| `REGISTER` | 1 | node to relay, first only | `u16 route_len`, route UTF-8, `u16 token_len`, token |
| `REGISTER_OK` | 2 | relay to node | configured heartbeat seconds as `u32` |
| `ERROR` | 3 | either terminal direction | stable ASCII error code |
| `OPEN` | 10 | relay to node | relay receive window as `u32` |
| `OPEN_OK` | 11 | node to relay | node receive window as `u32` |
| `OPEN_ERROR` | 12 | node to relay | stable ASCII error code |
| `DATA` | 13 | either stream direction | opaque bytes |
| `FIN` | 14 | either stream direction | empty; half-closes that direction |
| `CLOSE` | 15 | either stream direction | optional stable ASCII reason |
| `WINDOW_UPDATE` | 16 | either stream direction | consumed byte count as nonzero `u32` |
| `PING` | 20 | either control direction | opaque 8-byte sequence |
| `PONG` | 21 | either control direction | exact 8-byte sequence |

`OPEN` never contains a host, port, path, protocol, or command. `RelayNodeConnector` always opens
the one loopback `local_target` from its local configuration.

## Flow Control And Backpressure

Each side grants an initial per-stream receive window. A sender must debit credit before sending
`DATA`; the receiver sends `WINDOW_UPDATE` only after bytes have been written to the next TCP
socket. Per-stream incoming queues and the shared tunnel writer queue are bounded. A peer that
exceeds credit is a protocol violation; a full bounded stream queue closes that stream rather than
allocating more memory or leaking data into another stream.

TCP EOF sends `FIN` and preserves the other direction. `CLOSE`, route revocation, grant expiry,
heartbeat timeout, or tunnel loss cancels both pumps and all associated local sockets.

## Stable Errors

The wire and operational contracts use only:

```text
relay_protocol_invalid
relay_frame_too_large
relay_auth_failed
relay_route_unknown
relay_grant_expired
relay_route_unavailable
relay_limit_reached
relay_open_timeout
relay_idle_timeout
relay_tunnel_lost
relay_route_revoked
relay_internal
```

Detailed TLS, socket, and parser messages are local diagnostics and are never sent to members.
