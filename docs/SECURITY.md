# Security And Privacy Design

## Status And Scope

This document is the normative security and privacy design for a small, privately operated
private network. It covers the controller, administrator clients, managed Xray nodes,
end-user devices, optional relays, release infrastructure, and backups. `MUST`, `MUST NOT`,
`SHOULD`, and `MAY` have their usual requirements-language meanings.

The intended deployment has one controller, a small number of trusted administrators, tens of
nodes at most, and explicitly enrolled accounts and devices. It is not a public multi-tenant VPN
service design. A deployment that exposes public registration, delegates administration to
untrusted tenants, or operates at substantially larger scale requires a separate threat model and
security review.

This design protects control-plane credentials, Xray credentials, configuration, and retained
telemetry. It does not claim to make a compromised endpoint safe, hide traffic metadata from the
selected exit provider, or prevent an authorized administrator from seeing data the product is
designed to show.

## Security Objectives

The system MUST provide:

- unique, attributable identities for administrators, accounts, devices, and nodes;
- least-privilege authorization and independently revocable credentials;
- authenticated and confidential control traffic over untrusted networks;
- profile authenticity, confidentiality, expiry, and rollback protection;
- node-local custody of every REALITY private key;
- atomic, validated configuration changes without a general remote command channel;
- verifiable, signed software and Xray updates;
- privacy-preserving telemetry defaults with bounded retention and explicit deletion;
- explicit trust boundaries for relays, hosting providers, and backup operators;
- recoverability without silently weakening credential or key protections.

Availability against a large denial-of-service attack and anonymity against a global network
observer are out of scope. The controller and nodes still MUST implement ordinary rate limits,
resource bounds, and safe failure behavior.

## Threat Model

### Protected Assets

- controller identity, bundle-signing keys, database encryption keys, and backup keys;
- administrator authentication and recovery credentials;
- node identity keys and node-local REALITY private keys;
- per-account, per-node VLESS UUIDs and device profile contents;
- desired-state configuration, audit history, quotas, and revocation state;
- client IP addresses, destination metadata, traffic counters, and account labels;
- release signing credentials and CI/CD publishing authority.

### Considered Attackers

- a network attacker able to observe, replay, delay, redirect, or modify traffic;
- a person who obtains a pairing code, invitation link, access token, or old profile bundle;
- a compromised account device, node, relay, controller host, or administrator workstation;
- a malicious or compromised hosting, relay, build, update, or backup provider;
- an authenticated account attempting to exceed its assigned access;
- an administrator making an unsafe or mistaken configuration change.

### Core Assumptions

- the controller host and at least one administrator recovery device are initially trusted;
- operating systems provide a working CSPRNG and supported credential store;
- Xray, the TLS implementation, the OS, and cryptographic libraries are kept supported;
- a node compromise exposes that node's traffic, local telemetry, VLESS credentials, and REALITY
  private key, but must not expose credentials for other nodes;
- a controller compromise is a high-impact incident and can disclose centrally held profile and
  telemetry data, but must not disclose node-local REALITY private keys;
- an end-user device compromise exposes only profiles issued to that device and account.

## Trust Boundaries

The controller is the control-plane authority. It owns desired state, identity records,
authorization, revocation state, bundle signing, audit records, and retention policy.

Each node agent is trusted only to manage its local Xray instance and report data for its own
`node_id`. A node MUST NOT be able to impersonate another node, mint accounts, sign bundles, or
change controller policy. Nodes continue serving the last successfully applied configuration when
the controller is unavailable.

An administrator is trusted according to an explicit role, not merely because the request came
from the local network. An end-user device is a data-plane client, not an administrator. An
account label is never an authentication identity.

A raw TCP relay is an untrusted transport intermediary. It is not part of the controller or node
trust domain and receives no controller CA key, node identity key, REALITY private key, VLESS UUID,
bundle-signing key, plaintext profile, or telemetry plaintext. A reverse proxy that terminates
controller HTTPS is inside the controller trust boundary and follows the separate controls in
Transport Security.

The release system is a separate high-value trust domain. Authority to publish software MUST NOT
automatically grant authority to administer a running deployment.

## Identity Model

All identifiers are random, immutable UUIDs or equivalent 128-bit-or-stronger identifiers. Names,
email addresses, labels, countries, hostnames, and Xray `email` fields are mutable presentation or
mapping data and MUST NOT be used as primary identity keys.

### Administrator Identity

An administrator is a human principal with a stable `admin_id`. Every administrator workstation
or authenticator has a separate credential record so one lost device can be revoked without
removing the person.

- The first owner is created only during local controller initialization.
- An initial high-entropy bootstrap token, if used, is displayed once on the controller host,
  expires within ten minutes, creates only the first owner credential, and is atomically consumed.
  It is disabled permanently after bootstrap and is never accepted as an ordinary admin session.
- Remote administrator authentication MUST use phishing-resistant WebAuthn/passkeys or a
  device-bound asymmetric key plus a separately authenticated enrollment ceremony.
- Password-only remote administration is prohibited. If a local recovery passphrase is offered,
  it MUST be processed by a memory-hard password KDF with parameters stored alongside the hash,
  rate limited, and accepted only through the local recovery path.
- Roles are `owner`, `operator`, and `auditor`. Owners manage administrators, recovery, and trust
  roots; operators manage accounts, nodes, profiles, and ordinary configuration; auditors have
  read-only access to status and audit records.
- Sensitive owner actions require recent authentication. Adding an owner, rotating a trust root,
  exporting secrets, restoring a backup, or disabling audit collection MUST require reauthentication
  within five minutes.
- The system MUST always prevent deletion of the last usable owner and last tested recovery method.

### Account Identity

An account represents one authorized member or service and has a stable `user_id`. It is not
itself a bearer credential.

- Every `(user_id, node_id)` receives a distinct random VLESS UUID.
- Rotation or revocation on one node MUST NOT change credentials on unrelated nodes.
- An account may own multiple devices, each with its own identity and bundle generation.
- Disabling an account schedules removal of all of its node credentials. The UI MUST show nodes
  where that revocation is pending because the node is offline or failed to apply it.
- Quotas and telemetry are attributed by stable account and node IDs, not labels.

### Device Identity

A device is one installed client instance with a stable `device_id` and locally generated key
material. At minimum it has an Ed25519 signing key and an X25519 encryption key, or equivalent
reviewed algorithms provided by the platform cryptographic library.

- Private keys are generated on and never exported from the device except through an explicit,
  encrypted user backup feature.
- Device enrollment binds `device_id`, public keys, `user_id`, allowed nodes, and creation time.
- Each device receives separately encrypted profile bundles. Copying a bundle to another device
  must not make it usable there.
- Revoking a device invalidates its refresh tokens and future bundle access. Because a downloaded
  Xray credential may remain usable until removed from nodes, device revocation MUST also rotate
  affected per-node VLESS credentials or explicitly warn the operator that only controller access
  was revoked.

### Node Identity

A node is one node-agent installation with a stable `node_id` and a non-exportable node identity
key where the OS supports that property. The agent generates its key locally and obtains a unique
short-lived client certificate from the controller's private node CA during pairing.

- Node certificates include `node_id` in a validated subject alternative name and are accepted
  only for the node-agent API purpose.
- A node can submit telemetry and receive desired state only for its own `node_id`.
- Cloning a node disk MUST be detected as an identity collision. The controller quarantines both
  sessions until an owner re-enrolls one installation.
- Removing a node revokes its certificate, tokens, pending commands, relay routes, and account
  credentials associated with that node.

### Controller And Signing Identities

The HTTPS server identity, private node CA, desired-state signing identity, and profile-bundle
signing identity are separate keys. The signing keys use Ed25519 or an equivalently reviewed
signature algorithm. Key IDs and validity periods are included with signed artifacts. Separation
allows TLS certificates to renew without invalidating installed trust and allows one signing-key
incident to be handled without replacing unrelated trust roots.

## One-Time Pairing And Enrollment

Pairing is a bootstrap ceremony, not a permanent authentication mechanism. Separate pairing
purposes are used for nodes, administrator devices, and account devices; a code for one purpose
MUST NOT work for another.

### Pairing Record

The controller creates a pairing record containing:

- at least 256 bits from a CSPRNG, represented as a QR code or high-entropy link;
- purpose, intended account or role, permitted node set, creation time, and expiry;
- the controller URL and controller TLS or enrollment-key fingerprint;
- a server-side hash of the secret, never the plaintext secret;
- `unused`, `claimed`, `completed`, `expired`, or `cancelled` state.

Pairing records expire after ten minutes by default and MUST NOT exceed one hour. They are
single-use, rate limited by source and record, excluded from URLs sent to third-party services,
and redacted from logs, crash reports, clipboard history where the platform allows it, and UI
screens after completion. The controller invalidates a record atomically on the first valid claim.

### Pairing Protocol

1. The joining node or device generates its identity and encryption keys locally.
2. It establishes HTTPS to the encoded controller origin and verifies both normal PKI and the
   encoded controller fingerprint. Private deployments MAY use a pinned private CA instead of
   public PKI, but MUST NOT offer a click-through for a mismatched fingerprint.
3. It submits the pairing secret, purpose, public keys, software version, and a fresh nonce. It
   proves possession by signing the complete request transcript.
4. The controller atomically claims the unused record, validates scope and software policy, and
   displays the joining identity fingerprint and requested permissions to an administrator when
   approval is required.
5. The controller issues the minimum credential for that identity: a node certificate, an admin
   device credential, or a device enrollment credential. Its response is bound to both nonces,
   both public keys, the controller identity, purpose, and pairing record ID.
6. The joining party verifies that binding, stores credentials in the OS credential store, and
   sends authenticated completion. If completion does not arrive, the record remains consumed and
   a new pairing ceremony is required.

Replay, second claim, expired claim, purpose substitution, transcript modification, and unknown
controller fingerprint MUST fail closed and create a redacted audit event. Pairing secrets MUST
never become general API tokens.

For node replacement, the owner creates a new node identity and explicitly chooses whether it is
a new node or a replacement. Replacement does not reuse the old node private key or certificate.

## Authentication, Tokens, Rotation, And Revocation

### Session Tokens

Human and device APIs use opaque, CSPRNG-generated bearer tokens only after asymmetric enrollment.
The database stores a keyed hash of each token, its scope, subject, audience, creation time,
expiry, token-family ID, and revocation state. Tokens are never stored plaintext server-side.

- Access tokens expire after at most 15 minutes.
- Refresh tokens expire after at most 30 days, are bound to an enrolled device, and rotate on
  every use.
- Reuse of an already rotated refresh token revokes the entire token family and raises an alert.
- Tokens have an exact audience and narrow scopes; admin, node, device, relay, and update tokens
  are not interchangeable.
- Browser-facing tokens use `Secure`, `HttpOnly`, and `SameSite=Strict` cookies with CSRF
  protection. Native clients store tokens only in the OS credential store, never web storage.
- Logout revokes the current refresh-token family. Credential removal and account disablement
  revoke all applicable families immediately.

### Node Credentials

Node control traffic uses mutually authenticated TLS when the complete path supports it. When an
HTTP tunnel terminates TLS, every request instead carries an end-to-end signature from the enrolled
node identity key. Node certificates or signing credentials last no more than 90 days and rotate
automatically when less than 30 days remain. Rotation requires the existing valid node identity,
proof of possession of the new key, and controller authorization. The old credential is accepted
only during a bounded overlap of at most 24 hours.

The controller checks certificate status against its authoritative node record on every new
connection. Revocation terminates active sessions and rejects reconnects; certificate expiry or a
failed status check fails closed for new control operations. A disconnected node continues its
last applied Xray configuration but cannot receive changes or upload telemetry.

### VLESS Credential Rotation

VLESS UUIDs are bearer secrets without inherent server-enforced expiry. Rotation therefore uses a
two-phase process:

1. create a new per-node UUID and publish a new signed device bundle containing it;
2. after all intended devices acknowledge the new bundle, or after a configured emergency
   deadline, remove the old UUID from the node with an atomic desired-state revision.

Routine overlap MUST be no longer than seven days. Emergency rotation MAY remove the old UUID
immediately, accepting client interruption. The controller MUST show the old credential as active
until every reachable node confirms the removal revision. Deleting a database row alone is not
successful revocation.

### Revocation Behavior

Revocation is explicit, audited, and scoped by credential type. It must terminate active
controller sessions where technically possible, reject future refresh or certificate use, and
enqueue the corresponding desired-state change. Offline nodes are shown as `revocation_pending`,
not as secure or complete. Emergency response includes a local node command that an authorized
host operator can run when the controller cannot reach the node.

Trust-root rotation supports an overlap in which artifacts are signed by both old and new roots.
Removing the old root requires confirmation that all active devices and nodes trust the new root.
If a root is compromised, the documented recovery path replaces it without trusting an artifact
signed only by the compromised key.

## Transport Security

- Every non-loopback HTTP endpoint uses HTTPS. Plain HTTP listeners on routable interfaces are
  prohibited and must redirect nothing; they close the connection.
- TLS 1.3 is preferred. TLS 1.2 MAY remain enabled only with modern AEAD cipher suites for
  compatibility. SSL, TLS 1.0, TLS 1.1, compression, and insecure renegotiation are disabled.
- Node control connections use mTLS and are initiated outbound by the node when practical. No node
  management port is exposed publicly solely for controller access.
- A controller reverse proxy MAY terminate HTTPS and node mTLS only when it is administered as part
  of the controller trust boundary. It forwards authenticated identity over an authenticated,
  access-controlled local channel, strips client-supplied identity headers, and exposes no direct
  bypass to the Control Service. A third-party HTTP tunnel is not trusted to assert node identity;
  node proof must remain end-to-end at the application layer when mTLS cannot pass through it.
- Public controller deployments use a publicly trusted certificate and HSTS. Private deployments
  use an explicitly installed private CA or fingerprint pinning; certificate warnings are never
  bypassed.
- Requests include bounded sizes, deadlines, replay-resistant nonces or idempotency keys, and rate
  limits. Authentication is performed before expensive parsing or work where possible.
- Local UI-to-backend calls use Tauri IPC or loopback with an unguessable session boundary. The
  renderer is treated as untrusted input and receives no secrets it does not need to display.
- Logs contain request IDs and stable internal IDs, not bearer tokens, private keys, full profile
  URIs, authorization headers, cookies, or plaintext configuration.

## Signed And Encrypted Profile Bundles

HTTPS protects bundle delivery but is not the sole authenticity mechanism. Every device profile
bundle is signed by the controller profile-signing key and encrypted to that device's enrollment
encryption key.

The signed canonical manifest includes:

- format version, bundle ID, signing key ID, `user_id`, and `device_id`;
- monotonically increasing generation and controller instance ID;
- issue time, not-before time, expiry, and minimum supported client version;
- the complete permitted node set, profile hashes, policy, and revocation or replacement metadata;
- an explicit statement that absence of a previously present node or credential means removal.

Serialization MUST be deterministic, such as a specified canonical JSON format. The signature
covers the manifest and hashes of every encrypted payload. Encryption uses a standard,
authenticated recipient-encryption construction from a maintained library; the project MUST NOT
invent a hybrid encryption format.

Clients pin the controller profile-signing root at enrollment, verify the signature before
decryption or use, require their own `device_id`, enforce expiry and minimum client version, and
persist the highest accepted generation. A lower or duplicate generation with different content
is rejected as a rollback or equivocation attempt. Clock-skew handling is bounded and cannot turn
an expired bundle into an indefinitely valid one.

QR codes and links carry only the short-lived enrollment material. They MUST NOT contain reusable
VLESS UUIDs, REALITY private keys, administrator tokens, or long-lived plaintext bundles. Exporting
a portable plaintext profile is an explicit high-risk owner action with a warning, reauthentication,
and audit event; it is disabled by default.

## Secret Storage

### Controller And Administrator Hosts

Long-lived private keys, refresh tokens, database wrapping keys, and backup credentials are stored
in the native OS credential store: macOS Keychain, Windows Credential Manager/DPAPI, or Linux
Secret Service backed by an unlocked user keyring. Hardware-backed non-exportable keys SHOULD be
used where available.

SQLite or another application database stores only secret references, encrypted envelopes, token
hashes, public keys, and non-secret metadata. A file fallback for a missing credential store is
disabled by default. If an operator deliberately enables it for a headless host, secrets MUST be
encrypted by a passphrase-derived key, files and parent directories MUST be owner-only, and the UI
must continuously report the reduced assurance.

Secrets MUST NOT be placed in source control, environment-variable dumps, command-line arguments,
analytics, crash reports, support bundles, browser storage, or world-readable temporary files.
Memory containing secrets SHOULD be zeroized when supported. Support exports use an allowlist and
are scanned for known secret formats before creation.

### Node-Local REALITY Keys

Every node generates its REALITY private key locally using Xray or a reviewed compatible tool. The
private key never enters the controller API, controller database, signed profile bundle, relay,
telemetry, ordinary logs, or central backup. Only the corresponding public key and key fingerprint
are reported to the controller.

The private key is stored on the node in an owner-readable secret file or OS credential store. The
generated Xray runtime configuration is owner-readable only, written atomically, and removed or
overwritten when superseded. The node agent refuses to apply a configuration containing a
controller-supplied REALITY private key.

A node-local encrypted backup MAY contain the key, but it uses a node recovery key not available
to the relay or ordinary controller operators. If the private key is lost, recovery means
generating a new REALITY key pair, publishing new bundles, and revoking the old profile. The UI
must not imply that a controller-only restore can recover it.

## Node Agent And Configuration Safety

The node agent exposes a versioned, allowlisted protocol, not a shell. Permitted operations are:

- receive a complete desired-state revision and its idempotency key;
- validate, stage, apply, health-check, or roll back an Xray configuration;
- rotate node certificates and locally generated REALITY keys through defined workflows;
- start, stop, or restart the managed Xray service;
- report bounded health, version, revision, audit, and telemetry records;
- fetch a signed, policy-approved update artifact.

The protocol MUST NOT accept arbitrary commands, scripts, shell fragments, executable paths,
environment variables, package-manager instructions, filesystem paths outside fixed managed
directories, unrestricted file reads/writes, dynamic library loading, or arbitrary URLs.

Structured inputs are schema validated, size limited, and converted directly into Xray
configuration without shell interpolation. Xray configuration is validated with the pinned Xray
binary before apply. The agent writes a same-filesystem temporary file, fsyncs it where supported,
atomically renames it, restarts Xray, performs a bounded health check, and rolls back to the last
known-good revision on failure.

The agent runs as an unprivileged dedicated OS user whenever possible. A minimal privileged helper,
if required for service control or binding, accepts only fixed operations over authenticated local
IPC. The controller cannot change that allowlist remotely. Local break-glass administration is an
OS-login responsibility and is not tunneled through Control Service.

Desired-state revisions increase monotonically. Nodes report `received_revision`,
`validated_revision`, and `applied_revision`; the controller never reports success before the node
confirms the expected revision and health check. Nodes reject stale revisions, unknown schema
versions, invalid signatures, and revisions addressed to another node.

## Update Supply Chain

Control, Node Host, Connect, and bundled Xray binaries are released as one reviewed
trust chain. The application MUST NOT download and execute an unverified Xray binary at runtime.

- Source changes require review and protected release branches or tags. CI uses pinned actions,
  locked dependencies, least-privilege short-lived credentials, and isolated release jobs.
- Release artifacts are built from an immutable source revision. Builds produce checksums, an
  SBOM, dependency/vulnerability scan results, and provenance identifying source and build inputs.
- Application and node-agent artifacts are platform code-signed; macOS artifacts are notarized.
  An update manifest is separately signed by an offline or hardware-protected release key.
- Each supported platform pins the exact Xray version and SHA-256 or stronger digest. CI downloads
  Xray from its official release source, verifies the expected digest/signature, and embeds or
  packages that verified binary. The runtime verifies the embedded digest before execution.
- The updater verifies signature, product, platform, architecture, version, digest, and minimum
  compatible configuration version before installation. HTTPS is additional transport protection,
  not a substitute for artifact signatures.
- Downgrades are rejected by default. Emergency rollback requires a separately signed rollback
  authorization naming the exact safe version and reason.
- Updates are staged to a canary node, then a bounded cohort, then the remaining nodes. Health
  failures stop rollout automatically. The last known-good signed artifact remains available for
  bounded rollback.
- Release signing keys are inaccessible to ordinary CI jobs. Key rotation and compromise
  procedures are tested, and old vulnerable versions can be denied by controller policy.
- Secrets are scanned before publishing. Build logs, symbols, and support packages are reviewed so
  they do not contain credentials or private configuration.

Critical security fixes SHOULD have a documented response target. Unsupported controller, node,
or client versions are blocked from new enrollment and clearly warned before they become unable to
receive safe updates.

## Telemetry And Privacy

### Data Minimization

The controller collects only data needed for health, quota enforcement, incident response, and
features the operator has enabled. It MUST NOT collect payloads, message contents, full URLs, DNS
response bodies, TLS session secrets, REALITY private keys, or unrelated device data.

Telemetry has two modes:

- **Essential mode (default):** node health, software version, applied revision, aggregate
  per-account traffic counters, quota state, collection errors, and audit events.
- **Detailed connection analytics (opt-in):** connection time bucket, account and node IDs,
  network protocol, destination host and port, and client-IP data needed for the enabled view.

Detailed analytics is disabled by default for new deployments. Enabling it requires an owner to
choose a retention period and acknowledge the privacy impact. Accounts are told what is collected,
why, where it is stored, who can see it, and how long it is retained before credentials are issued.
Where applicable, the operator is responsible for obtaining valid user consent.

Client IP storage SHOULD use a keyed pseudonym or truncated prefix when the product feature does
not require the full address. If full client IP addresses are enabled, they are classified as
sensitive, encrypted at rest, hidden from auditors unless their role explicitly permits access,
and never placed in ordinary logs. Destination values store host and port only, never path, query,
payload, or inferred content category.

### Collection And Integrity

Nodes spool bounded telemetry locally and send bounded batches over an authenticated mTLS or
end-to-end signed channel with `(node_id,
sequence_start, sequence_end)`. The controller commits idempotently and acknowledges only durable
sequence numbers. Nodes retry without duplication and expose gaps, counter resets, clock skew, and
collection failures as data-quality state.

Telemetry is not a command channel. Text fields have strict length and character limits; labels
and remote error text are escaped before rendering. Controller timestamps receipt independently
and preserves the node event time separately.

### Retention And Deletion

Default maximum retention is:

- detailed connection events and full client IPs: 30 days, configurable from 1 to 90 days;
- hourly traffic samples: 90 days;
- daily aggregate usage and security audit events: 365 days;
- transient node health samples: 30 days;
- revoked token hashes and certificate serials: credential lifetime plus 90 days, or longer only
  when required for an active investigation.

Retention is enforced by age per data class and per node, not by a global row count. Deletion jobs
run at least daily, delete expired local node spools as well as controller data, and emit only
aggregate deletion results. Backups expire on a documented schedule so deleted data does not
persist indefinitely in backup generations.

An owner can export data for one account and purge that account's detailed telemetry. Account
deletion removes profiles, tokens, node credentials, and non-required telemetry. Security audit
records may retain a tombstoned random account ID until their normal expiry, but must not retain
the removed label, note, IP address, or profile secrets. Legal holds, if supported, are explicit,
audited, scoped, time bounded, and visible in the retention UI.

The product has no vendor telemetry by default. Any future crash or product analytics is a
separate opt-in with a published schema, endpoint, retention period, and local preview. It must
never reuse network-operation telemetry silently.

## External TCP Executor Trust Boundary

The optional external TCP executor is outside the controller trust boundary. It receives only an
unrelated request ID, at most six controller-resolved public IPv4 literals, one signed-revision
port, and a short timeout. It never receives node/member identity, hostname, database claim token,
REALITY keys, VLESS credentials, configuration artifacts, or administrator credentials. Requests
use a dedicated high-entropy deployment token over HTTPS; that token authorizes only this
non-publishable TCP preflight surface and is not reused for control APIs.

The executor or its provider can observe target IP/port, request timing, and connection outcome; it
can refuse work or lie about a TCP result. Control validates the closed response against its
request and current durable candidate, but cannot make a bare TCP claim trustworthy. Therefore TCP
evidence never marks an endpoint `verified` or enters a client bundle. A later VLESS + REALITY
canary uses a stronger separately scoped identity and is the first phase allowed to affect
publication. Executor logs and platform observability stay disabled, request bodies and
authorization headers are never logged, and the token is stored as a platform secret.
Control accepts only the exact configured HTTPS `/v1/tcp-probe` URL, disables redirects and system
proxies, bounds the response body, and validates response schema, request identity, pinned address,
and latency before recording evidence.

## Relay Trust Boundary

If a management relay is deployed, it forwards opaque, end-to-end authenticated and encrypted
controller-to-node traffic. Endpoint authentication terminates at the controller and node agent,
never at the relay. Relay compromise may reveal IP addresses, connection timing, direction,
volume, and controller/node availability, and may delay, replay, or drop ciphertext. It must not
reveal or modify valid control messages. This untrusted forwarding role is distinct from a reverse
proxy explicitly operated inside the controller trust boundary.

A data-plane TCP relay similarly forwards bytes without receiving REALITY or VLESS secrets. It can
observe client and destination-node addressing plus traffic metadata. If a provider requires TLS
termination, content inspection, or private keys at the relay, that system is a different trust
model and MUST be documented and approved before use.

Relay credentials authorize only a named route with bandwidth, connection, and expiry limits.
They cannot call controller APIs or enroll identities. Relay configuration contains opaque route
IDs, not account labels. The controller and nodes remain correct when the relay is unavailable;
failover to another relay is explicit and does not silently downgrade encryption or certificate
validation.

Operators MUST disclose relay jurisdiction and provider to affected users when it materially
changes metadata exposure. Relay logs are disabled where possible or minimized to operational
aggregates with a retention period no longer than 30 days.

## Abuse Prevention And Provider Consent

The platform is for systems and network connections the operator is authorized to manage. It
must not silently turn a third party's device, residential connection, cloud account, or relay into
an exit node.

- Node enrollment requires an owner to attest that the host and network owner consent to proxy
  operation and that provider terms permit it. The attestation records actor, node, provider,
  policy version, and time.
- The node UI or local status command clearly states that it is operating as a proxy exit, which
  controller manages it, and how the host owner can stop and unpair it.
- Account creation requires explicit authorization, an expiry or review date, and reasonable
  quotas. Public self-registration and anonymous credential issuance are out of scope.
- Per-account and per-node connection, bandwidth, and rate limits protect shared resources. The
  operator can disable high-abuse destination ports or categories when required by the provider.
- The system provides a documented abuse-contact path, rapid account disablement, node isolation,
  credential rotation, and preservation of a narrowly scoped incident record.
- Provider complaints trigger containment first: disable the implicated account or node, preserve
  relevant bounded audit evidence, investigate, and notify affected operators. They do not justify
  enabling indefinite surveillance.
- Consent and terms are reviewed when a node changes provider, jurisdiction, public exposure, or
  relay arrangement. The controller warns on expired attestations.

The product MUST NOT promise that REALITY makes prohibited use acceptable or invisible to a
provider. Operators remain responsible for law, contracts, acceptable-use policies, user notice,
and handling abuse reports in each deployment jurisdiction.

## Audit And Incident Response

Audit events cover authentication, pairing, role and policy changes, token and certificate
rotation/revocation, bundle issuance, secret export, node desired-state changes, update rollout,
backup/restore, telemetry-mode changes, retention overrides, and consent attestations. Each event
records event ID, actor, action, target, result, controller receipt time, request ID, and a redacted
reason. It never records secret values or full before/after configuration.

Audit storage is append-only at the application layer. Daily audit segments SHOULD be hash chained
and periodically anchored outside the controller so deletion or rewriting is detectable. Access is
limited to owners and auditors; export is signed and audited.

The incident runbook MUST distinguish:

- lost account device: revoke device tokens, rotate affected VLESS UUIDs, issue new bundles;
- compromised node: revoke node certificate, isolate relay route, rotate all credentials served by
  that node, rebuild the host, generate a new REALITY key, and re-enroll;
- compromised administrator: revoke its device and token families, review audit history, rotate
  affected credentials, and require owner reauthentication;
- compromised controller: isolate it, preserve evidence, rebuild from trusted media, rotate the
  controller TLS identity, node CA, bundle signing key, admin sessions, and all VLESS credentials,
  then re-enroll nodes and devices through the recovery procedure;
- compromised release key: stop updates, publish out-of-band notice, rotate the release root using
  the offline recovery key, deny affected versions, and rebuild from a verified source revision.

Security-sensitive clock changes, repeated pairing failures, refresh-token reuse, certificate
identity collisions, signature failures, rollback attempts, and unexplained desired-state changes
raise visible alerts. Alerts contain no secrets.

## Backup, Restore, And Disaster Recovery

Backups are encrypted before leaving the controller host with an authenticated encryption scheme
from a maintained library. Each backup has a signed manifest containing controller instance ID,
schema version, creation time, source version, content digest, and required recovery-key IDs.

Backups include controller state, public identity data, encrypted account/node credentials,
desired-state history, policy, and bounded audit/telemetry data. They exclude plaintext OS
credential-store secrets, active session tokens, transient pairing secrets, node identity private
keys, and node REALITY private keys.

The backup encryption key is separate from the live database wrapping key. At least two recovery
copies SHOULD exist in separate failure domains, with one offline. Recovery keys are held by
designated owners using an OS/hardware credential store or split custody. Backup-provider access
alone must not decrypt a backup.

Restore requires owner reauthentication, signature and digest verification, a compatible clean
controller build, and an explicit choice between:

- **same-controller recovery**, using the protected controller trust keys when compromise is not
  suspected; or
- **new-controller recovery**, generating new trust roots and requiring node/device re-enrollment
  when keys may be compromised or unavailable.

After restore, all active session and refresh tokens are revoked, pairing records remain invalid,
and the controller reconciles certificate and desired-state revocation before resuming changes.
Restored telemetry immediately undergoes current retention deletion. Nodes never accept a lower
desired-state revision merely because a controller restored an older backup.

Node-local recovery backups are separately encrypted and tested. Restoring a node identity onto
two machines is prohibited. If uniqueness cannot be guaranteed, the node is re-enrolled with new
identity and REALITY keys.

Automated backups run at least daily for production deployments. Quarterly restore drills verify
that a clean host can recover policy and desired state, that excluded secrets remain excluded, and
that new-controller recovery can re-establish service. Results are audited without recording
recovery secrets.

## Secure Defaults And Failure Behavior

- New remote listeners bind only after HTTPS identity and authorization are configured.
- New nodes, accounts, and devices start disabled until pairing and approval complete.
- Detailed analytics, portable plaintext profiles, file-based secret fallback, remote debug
  logging, and automatic relay use are off by default.
- Authentication, signature, certificate, schema, revision, or update verification errors fail
  closed. Loss of controller connectivity does not stop an already valid local Xray service.
- Secret values are masked by default and require recent authentication for one-time reveal where
  revealing is unavoidable.
- Development modes, test trust roots, debug endpoints, and unsigned updates cannot be enabled in
  production builds through remote configuration.
- Security warnings identify the affected identity or node and remediation; they are not silently
  dismissed after restart.

## Security Acceptance Criteria

A production multi-node release is not accepted until automated tests, integration tests, and a
documented manual review demonstrate all of the following.

### Identity And Authorization

- Every admin device, account, client device, and node has a unique immutable ID and independently
  revocable credential.
- Role tests prove auditors cannot mutate, operators cannot manage owners or trust roots, and nodes
  cannot read or write another node's state or telemetry.
- Per-node VLESS UUID tests prove no account credential is reused across two nodes.
- Removing the last owner or last recovery method is rejected.
- A cloned node identity creates a quarantine event rather than two accepted sessions.

### Pairing And Credential Lifecycle

- Pairing succeeds once with a valid transcript and fails for replay, expiry, cancellation, wrong
  purpose, modified keys, wrong controller fingerprint, and concurrent second claim.
- Pairing secrets, access tokens, refresh tokens, VLESS UUIDs, and private keys are absent from
  logs, URLs, crash reports, audit details, and support exports in secret-scanning tests.
- Access and refresh expiry, refresh rotation, token-family reuse detection, logout, device revoke,
  node-certificate rotation, and certificate revocation are covered by integration tests.
- Revoking an account or device remains visibly pending until every affected node confirms removal
  of the old VLESS credential.
- Emergency rotation can remove an old VLESS UUID immediately and previously issued profiles then
  fail against the updated node.

### Transport, Bundles, And Storage

- Non-loopback plaintext HTTP is unavailable; TLS configuration passes an approved scanner and
  node APIs reject clients without a valid unrevoked certificate or enrolled request-signing key.
- Signed bundle tests reject altered content, unknown signers, wrong recipients, expired bundles,
  stale generations, duplicate generations with different content, and unsupported client
  versions.
- Device A cannot decrypt or install Device B's bundle.
- Native secret-storage inspection confirms long-lived keys and refresh tokens are in the OS
  credential store, not SQLite, web storage, command lines, or plaintext files.
- A controller database and backup compromise test does not reveal any node REALITY private key.
- Files containing node runtime secrets have owner-only permissions and atomic replacement tests
  leave either the old or new complete file after simulated interruption.

### Node Safety

- Protocol fuzzing and schema tests reject unknown operations, shell syntax, traversal paths,
  oversized inputs, arbitrary URLs, arbitrary executable paths, and stale or cross-node revisions.
- No controller API or relay path can execute an arbitrary command, upload an executable, or read
  an arbitrary node file.
- Invalid Xray configuration never replaces the last known-good configuration; failed restart or
  health check rolls back and reports the actual applied revision.
- Disconnecting the controller leaves the last known-good Xray service running while preventing
  unauthenticated changes.

### Updates And Recovery

- Application, agent, manifest, and bundled Xray verification rejects a modified byte, wrong
  product/platform, unapproved downgrade, unknown signer, and mismatched pinned digest.
- CI produces a signed checksum manifest, SBOM, provenance, and secret-scan result for every
  release, and release signing credentials are unavailable to untrusted pull-request jobs.
- Canary failure halts a node rollout without changing untouched nodes.
- A clean-host restore drill verifies backup signature and encryption, revokes restored sessions,
  preserves monotonic revision safety, applies retention, and documents re-enrollment when trust
  keys are unavailable.
- Recovery tests demonstrate that loss of a node REALITY private key causes key regeneration and
  profile replacement, never retrieval from the controller.

### Privacy, Relay, And Abuse Controls

- A fresh deployment sends no vendor telemetry and collects no detailed connection events until an
  owner explicitly enables them.
- Automated retention tests delete each data class on schedule from controller storage, node
  spools, exports, and expired backup generations.
- Account export and purge tests include all scoped data and leave only permitted tombstoned audit
  references without labels, IPs, notes, or credentials.
- Packet capture at a management relay shows only ciphertext and transport metadata; substituting
  or terminating relay TLS causes endpoint verification failure.
- Relay credentials cannot authenticate to controller, node, or account APIs and expire within
  their configured route scope.
- Node enrollment cannot complete without recorded provider/host-owner consent, and the local node
  operator can identify, stop, and unpair the service without controller cooperation.
- Rate-limit and containment tests can disable one abusive account without disabling unrelated
  accounts or exposing additional telemetry.

### Release Gate

The release owner records evidence for each criterion, unresolved findings, and explicit risk
acceptances. A criterion may be waived only by an owner with a documented scope, rationale,
compensating control, expiration date, and tracking issue. There are no permanent silent waivers
for arbitrary remote execution, unsigned updates, plaintext long-lived secrets, reusable pairing
codes, controller-held REALITY private keys, or relay TLS termination.
