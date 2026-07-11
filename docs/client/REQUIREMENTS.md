# Reality Client Requirements

## 1. Product Goal

Reality Client is the companion desktop app for friends who receive a connection from
Reality Console. It turns one VLESS + REALITY invitation into a reliable local proxy without
exposing server administration or requiring the user to edit Xray JSON.

The first supported platforms are macOS (Apple Silicon and Intel) and Windows x64.

## 2. User Model

- The server operator creates one UUID per friend in Reality Console.
- The friend imports one `vless://` invitation by paste, QR scan, or file handoff.
- The client owns no server credentials beyond that friend's connection parameters.
- There is no shared account, cloud control plane, or remote administration API.

An invitation is a secret. Anyone holding it can use that friend's quota until the operator
revokes the corresponding UUID.

## 3. MVP Experience

1. Import and validate a VLESS + REALITY invitation.
2. Save the profile locally with a user-editable display name.
3. Start and stop the bundled Xray core.
4. Expose local SOCKS5 and HTTP proxy endpoints on loopback only.
5. Show connecting, connected, disconnected, and failed states with useful errors.
6. Copy local proxy settings for applications that use a manual proxy.
7. Optionally enable the operating system proxy and restore its previous state on disconnect.
8. Start at login and reconnect when explicitly enabled by the user.

## 4. Supported Invitation Shape

MVP accepts only the server shape produced by Reality Console:

- scheme: `vless`
- security: `reality`
- transport: `tcp` or `raw`
- encryption: `none`
- flow: `xtls-rprx-vision` or `xtls-rprx-vision-udp443`
- required parameters: UUID, host, port, SNI, fingerprint, REALITY password/public key
- optional parameters: short ID, display name, spider path

Unsupported transports and missing security parameters are rejected before anything is saved.

## 5. Security Requirements

- Bind local proxy listeners to `127.0.0.1`, never `0.0.0.0`.
- Store the imported URI in macOS Keychain or Windows Credential Manager.
- Store only non-secret profile metadata in the app data file.
- Generate runtime Xray config with owner-only permissions and remove it after a clean stop.
- Never log UUIDs, REALITY passwords/public keys, full invitation URIs, or generated config.
- Validate the bundled Xray process arguments; never execute invitation data through a shell.
- Restore system proxy settings after stop, app exit, failed startup, and next-launch recovery.

## 6. Networking Modes

### Manual proxy

Always available. Xray listens on:

- SOCKS5: `127.0.0.1:10808`
- HTTP: `127.0.0.1:10809`

The ports are configurable and must be checked for availability before startup.

### System proxy

MVP follow-up. The app configures HTTP and HTTPS proxy settings for applications that respect
the operating system proxy. It does not require packet interception.

### TUN

Not part of MVP. TUN requires elevated privileges, platform-specific routing and DNS handling,
and a substantially larger support surface. It should be implemented only after the proxy-mode
client is stable.

## 7. Explicit Non-Goals

- Server user management
- Reading server logs or quotas remotely
- Shared invitations between friends
- Account registration or cloud synchronization
- Mobile clients
- Traffic obfuscation beyond the imported Xray parameters
- Auto-updating Xray independently from a signed app release

## 8. Acceptance Criteria

- A Reality Console invitation imports without manual JSON editing.
- Invalid or incompatible invitations produce field-specific errors.
- Starting a profile launches exactly one managed Xray process.
- Stopping the profile terminates Xray and restores the prior system proxy state.
- Repeated start/stop operations do not leave stale processes or proxy settings.
- Unit tests cover URI parsing, validation, redaction, and config generation.
- macOS and Windows release builds bundle the matching Xray executable.
