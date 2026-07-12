# Node Host Relay Integration

Node Host owns one optional controller-issued relay assignment. The relay is an
alternative endpoint for the same managed VLESS/REALITY inbound; it is not a
general-purpose port forward.

## Install or rotate

The controller produces an owner-only JSON assignment (`schemaVersion: 1`) that
references owner-only route-token and client-key files. Install it before
starting the background service:

```bash
node-host configure-relay \
  --data-dir "$NODE_DATA" \
  --assignment-file relay-assignment.json \
  --accept-relay
```

Use `--replace` only for an intentional route or credential rotation. Existing
host-owner and exit-IP consent from enrollment must still be present. The
additional relay consent is retained separately and is not removed by route
revocation.

Node Host copies token, client certificate/private key, and relay CA into a new
owner-only generation directory. SQLite stores only non-secret assignment
metadata and a combined digest. Assignment input never accepts a local target:
the service derives `127.0.0.1:<admission-port>` from the currently running,
applied Xray revision.

## Runtime

`node-host run` starts the connector only after the managed Xray/admission
runtime is serving. A relay candidate is included in heartbeat only while the
connector reports `Registered`, and it is always bound to that applied
revision. Connector backoff or route loss withdraws only the relay candidate;
direct mapping failure withdraws only the direct candidate.

Shutdown cancels and joins the connector before Xray exits. Restart loads the
current assignment and reconnects automatically.

## Revoke

```bash
node-host revoke-relay \
  --data-dir "$NODE_DATA" \
  --confirm-endpoint-id "$RELAY_ENDPOINT_ID"
```

Revocation requires the exact stored endpoint ID, commits the route withdrawal,
then removes the credential generation. Stop the background service before a
configuration mutation because the Node Host data-directory lock is exclusive.

`node-host status` and `node-host service live-status` expose only redacted
assignment and connector state. They never print route tokens, certificate
contents, private-key paths, relay management addresses, or material digests.
