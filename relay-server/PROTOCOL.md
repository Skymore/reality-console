# Relay Tunnel Protocol v1

`pn-relay-v1` multiplexes fixed-route raw TCP streams over one node-originated mTLS connection. It
is not VLESS, SOCKS, HTTP CONNECT, a generic reverse proxy, or a destination-selection protocol.
Payloads are opaque VLESS + REALITY bytes; TLS/VLESS/REALITY still terminate only at node Xray.

## Transport And Authentication

- Node Host connects outbound to the configured relay TCP address using TLS 1.2 or newer.
- ALPN is exactly `pn-relay-v1`.
- Relay verifies the client certificate against its configured CA and then binds the leaf
  certificate SHA-256 fingerprint to one route.
- The first application frame supplies the same opaque route ID plus a high-entropy route token.
  Relay stores only the token SHA-256 and compares both digests in constant time.
- A route grant has a fixed public listener, expiry, concurrency, rate, and per-connection byte
  limit. A valid reconnect replaces the prior tunnel for that route.

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
