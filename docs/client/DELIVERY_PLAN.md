# Connect Delivery Plan

Status: authoritative phased delivery for the account-first Connect client.

These phases are engineering checkpoints inside the larger product stages. They do not require one
Git commit each: Stage 4 ships the complete account/session/bundle/selection backend as one reviewed
commit, and Stage 5 groups proxy recovery, packaging, and release evidence. Work extends the
application in `client/`, preserves compatibility import until migration is complete, and leaves
the separate Control app buildable. Account-first UI does not ship against mock-only contracts as a
production feature.

## Phase 0: Baseline and Contract Lock

Deliverables:

- inventory and characterize the existing compatibility parser, credential-backed profile store,
  deterministic config generator, bundled sidecar preparation, and `XraySupervisor` lifecycle;
- add regression tests for current URI import, loopback listeners, redaction, atomic runtime config,
  one-child enforcement, start/stop idempotency, and sidecar version/checksum handling;
- define versioned member/bundle DTOs and stable error codes matching the Control Protocol;
- document ownership boundaries for session, bundle, selection, proxy recovery, and supervisor state.

Exit criteria:

- the current compatibility connection flow passes on macOS without behavior regressions;
- backend contract fixtures parse independently of renderer code;
- no production code path requires invitation-only assumptions in shared DTO names.

## Phase 1: Secure Account and Device Sessions

Deliverables:

- Control Service client with HTTPS validation, bounded requests, request IDs, stable error
  envelopes, cancellation, and retry classification;
- one-time activation and optional password-login flows;
- device-scoped refresh session restoration and serialized refresh-token rotation;
- owner-only macOS/Linux file storage and Windows Credential Manager adapters with account/device
  namespaces;
- in-memory access tokens, logout, local credential cleanup, and revocation/disabled-account states;
- activation, login, refresh rotation, crash-during-rotation, logout, rate-limit, and generic-auth-
  failure tests.

Exit criteria:

- a clean macOS and Windows test installation can activate and restore a device session;
- refresh and activation secrets never enter renderer state, files, logs, or crash fixtures;
- independent device revocation prevents further authenticated refresh.

## Phase 2: Signed Bundle Verification and Offline Cache

Deliverables:

- canonical signed-envelope verification using production-configured trust roots;
- schema, version, network/account/device binding, bundle identity, time-bound, account-state, node,
  endpoint-mode, and connection-shape validation;
- authenticated encrypted two-generation cache with its encryption key in OS credentials and an
  atomic active pointer;
- startup, explicit, and six-hour conditional refresh with `ETag`, bounded server hints, and
  exponential backoff with jitter;
- trusted-time tracking and hard offline-expiry enforcement;
- fixtures for valid, tampered, replayed/conflicting-ID, wrong-device, expired, future-dated,
  unsupported-schema, interrupted-write, missing-key, and corrupt-cache cases.

Exit criteria:

- only a completely verified bundle can become active;
- interrupted updates recover the current or previous complete generation;
- an unexpired cache works with the Control Service unavailable, and expiry reliably prevents a new
  connection and stops an app-managed active session;
- ordinary app-data inspection reveals no plaintext node credential or bearer token.

## Phase 3: Account-First UI and Manual Multi-Node Connection

Deliverables:

- activation/login as primary onboarding, with account, device, refresh, and offline-freshness UI;
- friendly assigned-node list built from safe views of the verified bundle;
- explicit manual node selection and node-change interruption disclosure;
- direct/relay badges and explanations that identify the selected exit and opaque relay path;
- normalized connection profile shared by verified bundle nodes and compatibility imports;
- adaptation of the existing config generator and `XraySupervisor`, without a second process
  manager;
- safe Tauri commands and renderer DTOs that exclude bundle bytes and connection secrets.

Exit criteria:

- an activated member receives at least two nodes and manually connects to either without URI
  import or JSON editing;
- direct and relay profiles both pass through the same supervisor and show the correct path mode;
- switching nodes, stopping, and restarting never creates duplicate Xray processes or stale runtime
  configuration.

## Phase 4: Automatic Selection and Pinned Fallback

Deliverables:

- bounded endpoint probes and non-secret node health history;
- automatic ranking with signed hints, health threshold, latency tolerance, minimum hold-down, and
  deterministic reason codes;
- user-configured pinned fallback ordering and bounded failover;
- node disappearance, endpoint revision, relay outage, recovery, and bundle-refresh reconciliation;
- explicit handling for whether a node switch drains or interrupts existing application traffic;
- deterministic tests with fake time and probe results, including anti-oscillation and unrelated-
  path isolation.

Exit criteria:

- manual mode never changes nodes silently;
- automatic mode selects a healthy eligible node without rapid oscillation;
- pinned fallback follows only the configured order, and a relay failure does not mark healthy
  direct nodes unavailable.

## Phase 5: System Proxy and Lifecycle Recovery

Deliverables:

- macOS and Windows system-proxy adapters while retaining manual proxy mode;
- exact prior-state snapshot, durable pre-mutation recovery record, and idempotent restoration;
- supervisor integration for failed startup, unexpected exit, logout, bundle expiry, node switch,
  app exit, and next-launch recovery;
- configurable loopback port availability checks and startup ordering;
- start-at-login and reconnect policy constrained by verified unexpired configuration;
- crash/fault-injection matrix around every proxy and supervisor state transition.

Exit criteria:

- no tested stop, crash, revocation, expiry, logout, upgrade, or restart path leaves stale OS proxy
  settings, duplicate children, or plaintext runtime config;
- system proxy is never changed before ports and candidate configuration are ready;
- startup recovery executes before any automatic reconnect.

## Phase 6: Compatibility Import Containment

Deliverables:

- move existing `vless://` import behind an explicit Compatibility/Advanced action;
- preserve strict field validation, field-specific errors, platform credential storage, and
  local-only profile management;
- clearly distinguish compatibility profiles from account nodes and disable account bundle refresh,
  automatic selection, and fallback controls for them;
- prevent implicit fallback from revoked, expired, or unavailable account state to an imported
  profile;
- migration tests for existing local profile indexes and credential entries.

Exit criteria:

- existing supported invitations still import and connect through the same supervisor;
- primary onboarding contains no invitation-only/no-account language;
- compatibility data neither joins nor overrides a signed account bundle.

## Phase 7: macOS and Windows Packaging

Deliverables:

- reproducible sidecar acquisition from the pinned Xray manifest with official asset and SHA-256
  verification;
- target-suffixed sidecars for macOS Apple Silicon, macOS Intel, and Windows x64;
- signed and notarized macOS packages and signed Windows x64 installer;
- production Control Service origin, signing trust, credential namespaces, and restricted Tauri
  capabilities separated from development configuration;
- upgrade/uninstall behavior that preserves valid sessions on upgrade and restores app-owned proxy
  state and removes app-owned secrets on explicit uninstall/account removal;
- software bill of materials, release checksums, and release provenance retained by CI.

Exit criteria:

- all three target packages install on clean systems, contain the expected verified Xray binary,
  and cannot enable development trust from normal settings;
- install, upgrade, launch, activation, login, compatibility import, and uninstall checks pass.

## Phase 8: Release Acceptance and Failure Matrix

Deliverables:

- end-to-end tests against the real Control Service member API and signed bundle implementation;
- macOS Apple Silicon, macOS Intel, and Windows x64 install/upgrade smoke tests;
- direct-node and relay-node connection tests with at least two assigned nodes;
- offline service, expired cache, account disable, device revoke, refresh-token reuse, signing-key
  rotation, bundle tamper, clock change, occupied port, Xray crash, relay outage, and corrupt local-
  state tests;
- renderer/log/support-bundle secret-leak scans;
- operator/member acceptance checklist mapped to every criterion in `REQUIREMENTS.md`.

Exit criteria:

- all acceptance criteria in `docs/client/REQUIREMENTS.md` pass on release artifacts, not only
  development builds;
- the failure matrix proves control-plane outage does not stop valid cached data-plane use;
- release evidence records package signatures, notarization, Xray version/checksum, test platform,
  Control Service version, and bundle schema version.

## Engineering Gates for Every Phase

- Do not expose secrets, raw bundle bodies, generated Xray JSON, arbitrary filesystem access, shell
  execution, or arbitrary network targets to the renderer.
- Preserve unrelated worktree changes and keep phase commits scoped to Connect.
- Keep network and credential-store operations off the UI thread and bounded by timeouts.
- Use atomic durable writes for state transitions and inject failures in tests around commit points.
- Use stable IDs as keys; labels and regions are presentation data only.
- Every retry is classified and bounded; authentication and integrity failures do not loop.
- Every release-affecting change updates these client documents before its phase closes.
