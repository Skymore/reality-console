# Vultr TCP Relay

This deployment keeps Xray on the home Mac as the exit node while a Vultr VPS
provides a stable public TCP endpoint:

```text
friend -> Vultr:443 -> FRP tunnel -> Mac:10443 -> managed Xray -> internet
```

The VPS runs `frps`; the Mac runs `frpc`. FRP forwards raw TCP, so existing
VLESS/REALITY UUIDs, public keys, short IDs, and SNI values remain unchanged.
Only the client endpoint IP changes to the VPS public IP. Port 10443 is the
Node Host-managed loopback listener; it is not exposed directly on the LAN.

The same outbound FRP connection can carry the loopback-only Control Service to
VPS port 18080. Caddy exposes it as valid HTTPS on port 8443 while UFW keeps
18080 private.

## VPS

Copy this directory to an Ubuntu VPS and run as root:

```bash
./install-vps.sh
./install-control-proxy.sh control.example.com
```

The installer pins and verifies FRP, creates a random token when needed,
enables `frps`, allows TCP ports 443 and 7000 through UFW, and disables SSH
password authentication after validating the SSH configuration.

## macOS

Install the client and create its local-only configuration:

```bash
brew install frpc
sudo install -d -m 0750 /opt/homebrew/etc/frp
sudo install -m 0600 /path/to/token /opt/homebrew/etc/frp/token
sudo install -m 0644 frpc.toml /opt/homebrew/etc/frp/frpc.toml
printf '%s\n' 'VPS_PUBLIC_IPV4' > /opt/homebrew/etc/frp/public-ipv4
brew services start frpc
```

Use `frpc.example.toml` as the configuration template. Do not commit the token.
The `public-ipv4` file makes generated client links use the relay endpoint rather
than the Mac's residential address.
