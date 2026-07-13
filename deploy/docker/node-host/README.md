# Docker Node Host

This is the advanced Linux/VPS Node Host path. It runs the same Node Host and pinned Xray data
plane as the desktop product. Kubernetes is intentionally not required for one process, one public
port, and one persistent state volume.

## Requirements

- Linux VPS with a dedicated public IPv4 address.
- Docker Engine with Compose v2.
- Inbound TCP `443` allowed by the VPS firewall and provider security group.
- A Control Service node setup code whose `publicPort` matches `PUBLIC_PORT`.
- A stable public HTTPS Control origin reachable from the VPS.

## Build and Enroll

Copy `.env.example` to `.env` and replace `PUBLIC_ADDRESS` with the VPS public IPv4 address. Build
the image before consuming a setup code:

```bash
docker compose build node
```

Pipe the one-time code over stdin. It never enters the Compose environment, image, shell history,
or process arguments:

```bash
printf '%s\n' "$NODE_SETUP_CODE" | docker compose run --rm -T node setup
unset NODE_SETUP_CODE
```

The setup container verifies the pinned Xray archive and executable, enrolls the node, receives and
validates its initial revision, and publishes the VPS address as a finite manual endpoint. Start
the durable service only after setup succeeds:

```bash
docker compose up -d node
docker compose logs -f node
```

The container uses host networking because the admission gate and Xray loopback backend are one
data plane. It runs as UID/GID `10001`, drops every capability except binding a privileged port,
uses a read-only root filesystem, and persists only `/var/lib/private-network-node`.

## Status and Cleanup

Stop the service before opening the state database through the status command:

```bash
docker compose stop node
docker compose run --rm node status
docker compose start node
```

`docker compose down` retains enrollment. `docker compose down --volumes` irreversibly removes the
local node identity and must be paired with controller-side node revocation.
