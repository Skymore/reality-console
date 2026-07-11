# Connect Requirements

Status: authoritative Connect product requirements.

Connect is the member desktop application for the private network. Account activation and signed
profile synchronization are the primary experience. Manual `vless://` import is retained only for
compatibility and must not shape the account-first information architecture.

The first supported platforms are macOS (Apple Silicon and Intel) and Windows x64.

## 1. Product Goal

Connect lets a member activate one or more independently revocable devices, receive every assigned
node without handling protocol configuration, and connect through a healthy node while preserving
service during a temporary Control Service outage.

The member sees account, device, node, reachability mode, freshness, and connection state. Xray,
VLESS, REALITY, UUIDs, and generated configuration remain implementation details.

## 2. Account-First Experience

### Activation

1. The member opens an activation link, scans a code, or enters a one-time activation secret.
2. Connect consumes the secret over HTTPS and creates a new `device_id` scoped to the member.
3. The Control Service returns account metadata, a short-lived access token, and a rotating refresh
   credential.
4. Connect stores the refresh credential in the operating-system credential store, obtains the
   current signed bundle, selects a node, and is ready to connect.

Activation secrets are single-use and expire. Failed activation must not create a local signed-in
state or reveal whether an unrelated account exists.

### Login and session restoration

- Password login is available only when enabled by the operator. Authentication failures are
  generic and rate-limit compatible.
- A successful login creates a device-scoped refresh session; it does not create an account-wide
  bearer credential.
- On launch, Connect uses the stored refresh credential to obtain a short-lived access token and
  rotates the refresh credential when the server requires it.
- Access tokens remain in memory. Refresh credentials are never exposed to the renderer.
- Each installation has a stable local installation identity and one server-issued `device_id` per
  activated account. Devices can be revoked independently.
- Logout stops the connection, restores proxy settings, revokes the current device session when the
  service is reachable, and removes local account credentials and cached connection secrets.
- Remote device or account revocation prevents refresh. Connect enters a signed-out or
  access-revoked state at the next authenticated request and must not silently fall back to an
  imported profile.

## 3. Signed Multi-Node Bundles

The Control Service returns an immutable bundle containing:

- `bundle_id`, schema version, account and device binding, and signing key identifier;
- issue time, recommended refresh time, and hard offline-validity deadline;
- member/account status and minimum supported Connect version;
- all assigned node profiles, each with stable `node_id`, friendly label, region, endpoint,
  per-node member credential, and Xray connection parameters;
- endpoint mode (`direct` or `relay`) and selection hints;
- a signature covering the complete canonical bundle payload.

Connect must:

- verify the signature, schema, account/device binding, time bounds, and supported protocol shape
  before persisting or applying a bundle;
- trust only configured or activation-bootstrapped Control Service signing keys and handle key
  rotation through an authenticated, signed transition;
- treat a bundle as immutable by `bundle_id`; conflicting bytes for the same ID are an integrity
  failure;
- activate a newly verified bundle atomically so a crash cannot expose a partially updated node
  set;
- retain the previous valid bundle until the replacement is durably committed and usable;
- use `ETag`/`If-None-Match` and refresh at startup, on explicit request, and approximately every
  six hours while active, subject to bounded server hints and exponential backoff with jitter;
- never accept an unsigned node, merge node fields from different bundle versions, or extend an
  offline deadline locally.

## 4. Offline Behavior

- Connect may start and continue using the last verified cached bundle while the Control Service is
  unavailable, but only before that bundle's hard offline-validity deadline.
- A failed refresh does not disconnect a working data-plane session while the cached bundle remains
  valid.
- The UI shows whether data is current, refresh is delayed, or the app is operating from cache, and
  displays the offline expiry without exposing secrets.
- After offline validity expires, Connect must not start a new Xray session from that bundle. It
  stops an app-managed active session, restores system proxy state, and requires successful refresh
  or reactivation.
- Clock rollback or implausible time changes cannot be used to extend offline validity. Connect
  records last trusted server time and evaluates expiry conservatively.
- First activation, login, assignment changes, and bundle refresh require the Control Service;
  existing valid data-plane operation does not.

## 5. Node Selection

### Manual

The member selects a named assigned node. Connect keeps that node selected until the member changes
it, it disappears from a verified bundle, or an enabled fallback policy is triggered.

### Automatic

Connect performs bounded, privacy-preserving availability and latency probes against bundle-defined
endpoints. It selects the best healthy node using server hints, recent health, latency tolerance,
and a minimum hold-down period so insignificant changes do not cause rapid switching. Automatic
selection never probes arbitrary addresses supplied by the renderer.

### Pinned fallback

The member may define an ordered subset of assigned nodes. When the active node fails after bounded
retries, Connect advances through the pinned order. Recovery of a higher-priority node does not
immediately preempt a healthy connection unless the configured hold-down policy permits it.

Every selection decision has a safe reason code. Node changes regenerate configuration and restart
the managed Xray session. The UI states whether existing application connections may be
interrupted; silent multi-hop routing is not permitted.

## 6. Direct and Relay Transparency

- Every node is marked as `direct` or `relay` by the signed bundle; the renderer cannot override
  that mode or endpoint.
- Connect displays the selected node and path mode before and during connection.
- Direct mode connects to the node's externally verified endpoint.
- Relay mode connects to an assigned raw TCP relay that forwards encrypted VLESS/REALITY traffic
  to the selected node. The relay does not terminate or decrypt member traffic, and the selected
  node remains the Internet exit.
- Relay outage affects relay-backed nodes only. Direct nodes and other healthy nodes remain
  selectable.
- Relay is a reachability mode, not a second exit or a hidden multi-hop feature. The initial release
  does not chain nodes.

## 7. Local Networking and Xray Lifecycle

- Reuse and extend the existing bundled `XraySupervisor`; do not build a parallel process manager.
- Generate one runtime configuration for the selected verified bundle node or compatibility
  profile, and launch exactly one app-managed Xray sidecar.
- Bind local SOCKS5 and HTTP listeners to loopback only. Defaults are `127.0.0.1:10808` and
  `127.0.0.1:10809`; configured ports are checked before startup.
- Manual proxy mode is always available. System proxy mode captures the prior OS state, records
  recovery intent before mutation, and restores the exact prior state after stop, logout, app exit,
  failed startup, expired offline access, and next-launch crash recovery.
- Start, stop, restart, and selection transitions are serialized and idempotent. An unexpected Xray
  exit marks the session failed, removes the ephemeral config, and restores system proxy state.
- Runtime configuration is written atomically with owner-only access where supported, passed to the
  sidecar without a shell, and deleted after use or crash recovery.
- Sidecar diagnostics are bounded and redacted. The renderer receives typed state and stable error
  codes, never generated Xray JSON or connection credentials.

TUN mode is outside the initial release. It requires separate platform privilege, DNS, routing,
installer, and recovery design.

## 8. Credential and Local Data Security

- Store refresh credentials, imported URIs, per-node UUIDs, REALITY connection secrets, and any key
  that decrypts a cached bundle only in macOS Keychain or Windows Credential Manager.
- Ordinary app-data files may contain account display metadata, device ID, bundle ID and timing,
  node presentation data, health history, selection policy, and proxy recovery state. They must not
  contain plaintext connection credentials or bearer tokens.
- If the full signed envelope is cached in an app-data file, its secret-bearing payload is encrypted
  with a random key held by the OS credential store and authenticated before parsing.
- Persist replacement credentials before retiring rotated credentials. A crash during rotation must
  leave the new credential recoverable and must never restore a server-invalidated predecessor or
  write plaintext secrets.
- Never log activation secrets, passwords, access or refresh tokens, imported URIs, member UUIDs,
  REALITY secrets, complete bundle payloads, or generated configurations.
- TLS certificate validation is mandatory. Development trust overrides are explicit, local-only,
  and excluded from release builds.
- Support and crash diagnostics contain request IDs, bundle IDs, node IDs, path modes, versions,
  state transitions, and redacted error codes only.

## 9. Compatibility URI Import

- `vless://` import remains available under an explicit compatibility or advanced action, not the
  primary onboarding screen.
- It accepts only the VLESS + REALITY TCP/RAW shape already supported by the client and rejects
  missing or unsupported fields before storage.
- Imported profiles are local-only, are not associated with an account or device, do not receive
  updates, and do not participate in automatic multi-node selection.
- The full URI is stored in the OS credential store; only non-secret display metadata is stored in
  app data.
- Compatibility mode is visibly labeled, and the app never falls back from a revoked or expired
  account bundle to an imported profile without an explicit member action.

## 10. Packaging and Updates

- Produce signed and notarized macOS packages for Apple Silicon and Intel, and a signed Windows x64
  installer.
- Each package includes the target-matching Xray sidecar through Tauri `externalBin`.
- Xray version, official asset name, and SHA-256 are pinned in the sidecar manifest. CI verifies the
  downloaded asset before packaging.
- The app never downloads and executes an unverified Xray binary at runtime and never updates Xray
  independently of a signed Connect release.
- Release builds use production identifiers, credential-store namespaces, Control Service trust
  configuration, and restricted Tauri capabilities.
- Installer upgrades preserve valid account sessions and caches. Uninstall and explicit account
  removal clean app-owned credentials and recover app-owned system proxy settings.

## 11. Explicit Non-Goals

- Public signup, billing, or account administration inside Connect
- Node enrollment, node-provider controls, server logs, or quota administration
- Exposing raw Xray configuration as the normal user experience
- Hidden node chaining or multi-hop routing
- General packet interception or TUN in the initial release
- Treating a relay as a trusted TLS/VLESS termination point
- Cloud synchronization outside the authoritative Control Service account and bundle APIs

## 12. Acceptance Criteria

1. A clean macOS or Windows installation can activate with one invitation action, persists a
   device-scoped session securely, and restores sign-in after restart without displaying secrets.
2. Password login, refresh rotation, logout, independent device revocation, disabled-account, and
   expired-activation paths return stable, non-enumerating UI states.
3. A valid signed bundle containing at least two nodes is verified, atomically cached, and rendered
   without exposing connection credentials; tampered, replayed, wrong-device, expired, and
   unsupported-schema bundles are rejected while the prior valid cache remains intact.
4. With Control Service unavailable, a fresh installation cannot activate, while an activated
   installation can connect from an unexpired cache and is blocked after the offline deadline.
5. Manual, automatic, and pinned-fallback selection pass deterministic tests for health failures,
   latency tolerance, hold-down behavior, node removal, and no rapid oscillation.
6. The UI identifies the selected node and whether its path is direct or relay. Direct and relay
   failure tests prove that one path's outage does not incorrectly disable unrelated nodes.
7. Account bundles and compatibility imports both feed the existing Xray supervisor. Repeated
   connect, switch, stop, crash, logout, and restart operations leave no duplicate child process,
   plaintext runtime config, occupied listener, or stale system proxy state.
8. Local HTTP and SOCKS listeners bind only to loopback, and the renderer and normal logs never
   receive refresh tokens, node credentials, complete bundle payloads, imported URIs, or generated
   Xray config.
9. Compatibility URI import still accepts valid existing VLESS + REALITY invitations and rejects
   incompatible shapes with field-specific errors, while remaining outside primary onboarding and
   automatic selection.
10. Signed/notarized macOS Apple Silicon and Intel packages and a signed Windows x64 installer each
    include the pinned, checksum-verified Xray sidecar and pass install, upgrade, activate, offline,
    direct, relay, connect, disconnect, crash-recovery, and uninstall smoke tests.
