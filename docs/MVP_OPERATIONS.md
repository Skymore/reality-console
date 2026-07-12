# MVP Operations

This document is the executable product path for the small friends-and-family deployment. It is
intentionally narrower than the full architecture and release documentation.

## 1. Install the Control Service on macOS

Prerequisites:

- macOS with Command Line Tools and Rust installed.
- Xray installed at `/opt/homebrew/bin/xray`, `/usr/local/bin/xray`, or another explicit path.
- The Mac remains powered and awake when the network must be available.

From the repository root:

```bash
python3 scripts/product/control-service.py install \
  --network-name "Friends Network" \
  --xray-path /opt/homebrew/bin/xray
```

The command performs the whole local bootstrap: release build, private configuration creation,
SQLite initialization, LaunchAgent registration, startup, and health verification. Re-running it
updates the installed binary and configuration without rotating the administrator token.

## 2. Check and Control the Service

```bash
python3 scripts/product/control-service.py status
python3 scripts/product/control-service.py stop
python3 scripts/product/control-service.py start
```

`status` exits unsuccessfully when the process is missing or unhealthy. The local health endpoint
is `http://127.0.0.1:8787/healthz` by default.

The administrator token is stored only in the owner-readable service configuration. Reveal it only
when an administrative client needs to be configured:

```bash
python3 scripts/product/control-service.py admin-token
```

## 3. Files and Security Boundary

The default service directory is:

```text
~/Library/Application Support/Private Network/Control Service/
```

It contains the installed binary, `control-service.json`, logs, and SQLite state. The directory,
configuration, database, and installed binary are private to the current user. The LaunchAgent at
`~/Library/LaunchAgents/com.private-network.control-service.plist` contains only paths and lifecycle
settings; it does not contain the administrator token.

The service listens on loopback only. Do not expose port 8787 directly on the router.

## 4. Public HTTPS Origin

The default origin is local and is suitable only for installing and testing the controller on the
same Mac. Node Host and Connect setup codes embed the configured controller origin, so setup codes
must not be issued to other machines until the controller has a stable public HTTPS origin.

After an authenticated reverse tunnel or reverse proxy is available, re-run installation with its
clean origin:

```bash
python3 scripts/product/control-service.py install \
  --network-name "Friends Network" \
  --xray-path /opt/homebrew/bin/xray \
  --public-origin https://control.example.com
```

The reverse tunnel must forward only to `http://127.0.0.1:8787`. The service remains loopback-only,
and reconfiguration preserves the existing database, controller identity, and administrator token.

## 5. Remaining Product Stages

The next product stages build on this running controller:

1. Install Node Host and join it with one setup code.
2. Create a friend account and assign one or more ready nodes.
3. Activate Connect with one account setup code and automatically receive the node list.
4. Prove a real client connection through the complete installed path.
