# Raw TCP Relay

The production Node Host consumer is documented in
[`../node-host/RELAY.md`](../node-host/RELAY.md). Node Host derives the local
target from its applied Xray/admission runtime; operators cannot use the
assignment document to select an arbitrary target.

This independent Rust service provides the optional reachability fallback for nodes that cannot
accept inbound Internet TCP. A member connects to a route's dedicated public port; the relay opens
a logical stream over the authenticated node-originated tunnel; `RelayNodeConnector` connects that
stream only to the configured loopback Xray listener.

```text
Connect Xray -- opaque VLESS + REALITY --> relay public route port
              -- bounded framed stream --> node RelayNodeConnector
              -- unchanged TCP bytes --> 127.0.0.1:<Xray inbound>
```

The relay does not terminate, inspect, or synthesize TLS, VLESS, or REALITY. It has no SOCKS,
HTTP CONNECT, UDP, command execution, arbitrary destination, or dynamic port-registration API.

## Components

- `relay-server serve`: public route listeners, node mTLS listener, route admission, limits,
  revocation/reload, metadata-only metrics.
- `RelayNodeConnector`: reusable library API composed into the Node Host service lifecycle.
- `relay-server relay-node`: standalone connector runner using the same library API.
- [`PROTOCOL.md`](./PROTOCOL.md): exact frame, state, flow-control, and stable-error contract.

The relay remains deployable as an independent service. Node Host depends only on its connector
library API; Control and Connect do not link the relay crate.

## Build And Test

Rust 1.88 or newer is required.

```bash
cargo build --release --manifest-path relay-server/Cargo.toml
cargo test --manifest-path relay-server/Cargo.toml --all-targets --locked
cargo clippy --manifest-path relay-server/Cargo.toml --all-targets --all-features -- -D warnings
RUSTDOCFLAGS="-D warnings" cargo doc --manifest-path relay-server/Cargo.toml --no-deps
```

## Example Setup

These commands create a development CA, relay server certificate, one node client certificate,
and a 256-bit route token. Use a real private CA or managed PKI in production.

```bash
cd relay-server
chmod +x scripts/generate-example-pki.sh
./scripts/generate-example-pki.sh relay.example.com
cp config.example.toml config.toml
cp node.example.toml node.toml
```

Put the printed token and certificate hashes into `config.toml`, choose one opaque route ID in both
files, set a future expiry, and set `node.toml`'s relay address and fixed loopback Xray target.

The server requires owner-only permissions on its private key. The connector requires owner-only
permissions on its private key and route token.

```bash
chmod 600 pki/relay-server-key.pem pki/node-key.pem pki/route-token
cargo run --release -- serve --config config.toml
```

On the node host, after Xray is listening only on the configured loopback port:

```bash
cargo run --release -- relay-node --config node.toml
```

Open the node tunnel port and each configured route port in the relay host firewall. Do not expose
the metrics port; configuration validation requires it to bind loopback. Relative certificate and
token paths are resolved against the corresponding TOML file's directory.

## Node Host Library API

Node Host can own the lifecycle without spawning the CLI:

```rust,no_run
use std::sync::Arc;
use relay_server::{NodeConnectorConfig, RelayNodeConnector};
use tokio_util::sync::CancellationToken;

# async fn example() -> relay_server::Result<()> {
let config = NodeConnectorConfig::load(
    std::path::Path::new("/etc/private-network/relay-node.toml"),
).await?;
let connector = Arc::new(RelayNodeConnector::new(config).await?);
let mut status = connector.subscribe();
let shutdown = CancellationToken::new();

let task_connector = connector.clone();
let task_shutdown = shutdown.clone();
tokio::spawn(async move { task_connector.run(task_shutdown).await });
status.changed().await.ok();
# Ok(())
# }
```

`ConnectorStatus` contains only `Disconnected`, `Connecting`, `Registered`, bounded backoff delay,
or `Stopped`; it contains no route token, certificate, target traffic, or peer address.

## Configuration And Reload

Server TOML rejects unknown fields. Queue sizes, frame sizes, route count, node connection count,
stream concurrency, rate, byte limits, and timeouts are all finite and validated. Each route maps
exactly one public listener to exactly one authenticated node tunnel.

The server checks its TOML file on the configured interval. Added routes bind new listeners;
disabled, removed, expired, or changed routes close their tunnel and active streams. Static server
listener/TLS changes require restart. A malformed reload leaves the active configuration intact.

The connector retries relay TCP/TLS/registration loss with capped exponential backoff. Heartbeats
run in both directions. A valid new tunnel replaces the stale tunnel for the same route.

## Metrics And Logs

Loopback HTTP exposes `GET /healthz` and Prometheus text at `GET /metrics`. Metrics contain only an
opaque route ID, tunnel/stream counts, refusal/auth/protocol counters, byte totals by direction, and
tunnel replacements. Logs contain stable errors and opaque route IDs only. Member IPs, tokens,
certificates, payload bytes, VLESS UUIDs, REALITY keys, SNI, and destinations are not logged.

## Security Properties

- Node authentication is mTLS CA validation plus exact leaf-certificate fingerprint and route
  token SHA-256 binding. Raw route tokens are never stored by the server.
- The member stream is byte-for-byte transparent. Relay-level member authentication cannot be
  prepended without breaking Xray; the dedicated route selects the node and node Xray authenticates
  VLESS users.
- The connector rejects every non-loopback target and the protocol has no target field, preventing
  conversion into a generic TCP proxy.
- Length is validated before allocation. Connection tasks, frame queues, per-stream queues,
  flow-control windows, rates, byte totals, handshakes, open time, idle time, and heartbeats are
  bounded.
- Route expiry and config revocation fail closed. Tunnel loss cancels every logical stream without
  reusing its stream ID or queue.

## Current Integration Risks

- Control does not yet issue signed relay grants or write this service's route config. Provisioning,
  token/certificate rotation, and policy reconciliation remain mainline integration work.
- Node Host does not yet instantiate `RelayNodeConnector`; the standalone `relay-node` runner and
  library API are ready for that wiring.
- Rate and per-connection byte limits are enforced in memory. Persistent calendar-month quota and
  restart-safe accounting are not implemented in this isolated slice.
- Dedicated public route ports can be scanned or denial-of-service targeted even though attackers
  still cannot pass node Xray authentication. Production deployment needs host firewall limits and
  external abuse monitoring.
- TLS certificate/CA changes require process restart. Route-only reload is supported.
- This implementation has automated protocol and end-to-end tests but has not yet had independent
  security review, long-duration soak testing, or production Internet load testing.
