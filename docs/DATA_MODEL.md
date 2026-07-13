# Data Model

Status: authoritative storage, ownership, migration, retention, and idempotency design.

This document defines the production data model for Control Service, Node Host, and Connect. It
supersedes prototype table layouts. API field names and values remain governed by
`CONTROL_PROTOCOL.md`; this document governs durable representation and invariants.

## 1. Storage Boundaries

Control Service is the only writer to the authoritative control-plane database. Control is an API
client and must not open that database. Node Host and Connect each own a separate local database and
must not share a SQLite file with Control Service or with each other.

| Owner | Durable data | Explicitly not owned |
| --- | --- | --- |
| Control Service | Networks, admins, users, devices, nodes, assignments, revision metadata, signed artifact metadata, sessions, telemetry, and audit events | Node-local REALITY private keys, provider policy authority, Xray process state |
| Node Host | Node identity metadata, provider policy, controller registration, apply journal, config backups, telemetry queue, reachability results, relay assignment | Member account/session credentials, administrator credentials, global desired state |
| Connect | Account metadata, signed bundle cache, health history, selection policy, proxy recovery journal | Authoritative accounts, node management credentials, REALITY private keys |
| OS credential store or owner-only secret store | Refresh secrets, node authentication secrets, VLESS UUIDs, signing/private keys, REALITY private keys, encrypted response and configuration artifacts | Queryable labels, status, analytics, or audit metadata |

Secret database columns normally contain only keyed verifier hashes, public keys, digests, or
opaque `secret_ref`/`artifact_ref` values. The initial single-process Control Service keeps the
per-assignment VLESS UUID in its owner-only SQLite database because the same service must deliver it
to both Node Host and Connect. That column is never selected by administrator summary APIs, never
opened by a renderer, and is covered by explicit redaction tests. A later split-renderer or remote
secret-store deployment must replace it with an opaque reference. Deleting a metadata row does not
delete separately referenced material until the retention and reference scan permits it.

The initial release has one network per Control Service instance. `network_id` is nevertheless
present in every domain table and every durable token scope. Migration bookkeeping tables are the
only exception.

## 2. SQLite Contract

All databases use bundled SQLite and these connection settings before any query:

```sql
PRAGMA foreign_keys = ON;
PRAGMA journal_mode = WAL;
PRAGMA synchronous = FULL;
PRAGMA busy_timeout = 5000;
PRAGMA trusted_schema = OFF;
PRAGMA secure_delete = FAST;
```

Only one process may own a database. That process uses a bounded connection pool, short write
transactions, and `BEGIN IMMEDIATE` for operations that allocate counters or consume one-time
tokens. Network calls, Xray validation, and artifact downloads never occur while a write transaction
is open.

Storage conventions are:

- IDs are canonical lowercase UUID strings in `TEXT`, validated by the application at every input
  boundary. Keys use `(network_id, entity_id)` even in the single-network release.
- Database timestamps are UTC Unix seconds in `INTEGER`; HTTP DTOs convert them to RFC 3339 UTC.
- Booleans are `INTEGER NOT NULL CHECK (value IN (0, 1))`.
- Byte counts, sequence numbers, and revisions are non-negative signed 64-bit integers. Writers
  reject overflow before binding values.
- Enumerations are lowercase database values. Protocol serializers perform any required casing
  conversion, such as database `rolled_back` to protocol `rolledBack`.
- JSON is canonical UTF-8 JSON with sorted object keys and no insignificant whitespace. Security
  decisions are represented in typed columns, not inferred only from JSON.
- New tables are `STRICT`. Nullable columns are nullable deliberately; empty strings are not used as
  null values.

Every database has `schema_migrations(version INTEGER PRIMARY KEY, name TEXT NOT NULL UNIQUE,
checksum TEXT NOT NULL, applied_at INTEGER NOT NULL) STRICT`. `PRAGMA user_version` mirrors the
largest committed version for diagnostics, but `schema_migrations` is the source of truth.

## 3. Control Service Schema Version 1

The following is the complete logical schema. `created_at` and `updated_at` are server times. Unless
specified otherwise, foreign keys use `ON UPDATE RESTRICT ON DELETE RESTRICT` so history cannot be
silently orphaned.

### 3.1 Network and administrator identity

`networks`

| Column | Constraint and meaning |
| --- | --- |
| `network_id` | `TEXT PRIMARY KEY`; stable network identity |
| `display_name` | `TEXT NOT NULL CHECK(length(display_name) BETWEEN 1 AND 128)` |
| `status` | `TEXT NOT NULL CHECK(status IN ('active','recovery','disabled'))` |
| `last_revision` | `INTEGER NOT NULL DEFAULT 0 CHECK(last_revision >= 0)`; allocation high-water mark |
| `controller_epoch` | `TEXT NOT NULL`; UUID changed only by an explicit disaster-recovery fence |
| `created_at`, `updated_at` | `INTEGER NOT NULL` |

The service enforces exactly one `networks` row in version 1.

`admins`

| Column | Constraint and meaning |
| --- | --- |
| `network_id`, `admin_id` | Composite primary key; `network_id` references `networks` |
| `display_name` | Non-empty text, maximum 128 characters |
| `status` | `active`, `disabled`, or `deleted` |
| `credential_version` | Positive integer incremented on credential rotation or global session invalidation |
| `created_at`, `updated_at`, `deleted_at` | `deleted_at` is required only for `deleted` |

`admin_sessions` stores `(network_id, session_id)` as its primary key, `admin_id`, a keyed
`token_hash`, `credential_version`, `created_at`, `expires_at`, `last_seen_at`, and nullable
`revoked_at`/`revoke_reason`. `UNIQUE(network_id, token_hash)` prevents verifier reuse. Expired,
revoked, disabled-admin, or stale-credential-version sessions never authenticate.

### 3.2 Members, devices, and one-time credentials

`users`

| Column | Constraint and meaning |
| --- | --- |
| `network_id`, `user_id` | Composite primary key |
| `display_name` | Non-empty mutable label, maximum 128 characters; never a key |
| `status` | `active`, `disabled`, or `deleted` |
| `password_verifier` | Nullable Argon2id PHC verifier; password login is optional |
| `credential_version` | Positive integer invalidating all member sessions when incremented |
| `created_at`, `updated_at`, `disabled_at`, `deleted_at` | Status timestamps must agree with status |

`devices`

| Column | Constraint and meaning |
| --- | --- |
| `network_id`, `device_id` | Composite primary key |
| `user_id` | Required composite foreign key to `users` |
| `display_name`, `platform`, `client_version` | Bounded metadata; platform and version are not identity |
| `status` | `active`, `revoked`, or `deleted` |
| `created_at`, `last_seen_at`, `revoked_at`, `deleted_at` | Durable lifecycle timestamps |

`device_activations` stores `(network_id, activation_id)`, `user_id`, a keyed secret verifier,
idempotency/request digests, immutable setup-delivery trust metadata, expiry, and nullable
consumption/device/session/request-response metadata. The raw secret and complete setup code are
never stored. Exact creation and consumption retries reconstruct the same secret-bearing response
from the controller identity; changed retries conflict.

`account_reset_tokens` stores `(network_id, token_id)`, `user_id`, a unique keyed 32-byte secret
verifier, issue idempotency/request digests, expiry, creation time, and nullable consume time,
consume idempotency/request digests, plus the bounded safe response JSON. The raw `rcr1` bearer and
password are never stored. Exact issue retries derive the same bearer from controller identity;
exact consume retries return the committed response. A different concurrent or later consume sees
the terminal consumed state. Reset consumption changes the Argon2id password verifier, increments
`credential_version`, revokes refresh sessions, rotates current assignment credentials, publishes
the required per-node revisions, consumes the token, and writes the audit event in one
`BEGIN IMMEDIATE` transaction. Migration 14 creates this table and its unconsumed-expiry index.

`refresh_sessions`

| Column | Constraint and meaning |
| --- | --- |
| `network_id`, `session_id` | Composite primary key; `session_id` identifies a rotation family |
| `user_id`, `device_id` | Required and mutually consistent member/device foreign keys |
| `generation` | Non-negative rotation generation |
| `current_refresh_verifier` | Keyed verifier, unique within the network |
| `previous_refresh_verifier` | Nullable verifier retained for reuse detection |
| `current_access_verifier`, `access_expires_at` | Current short-lived member bearer verifier and deadline |
| `credential_version` | User credential version at issue time |
| `created_at`, `rotated_at`, `expires_at`, `revoked_at` | Session lifecycle |
| `revoke_reason` | Stable code when revoked |

Refresh rotation uses `BEGIN IMMEDIATE`: match the current verifier, write the replacement and
previous verifier, increment `generation`, and commit before returning the new secret.
`refresh_idempotency_records` scope request/key digests and deterministic response metadata to the
session family plus source generation. `login_idempotency_records` provide the same crash recovery
for password device enrollment. Raw access/refresh credentials are reconstructed from the
controller identity and committed metadata, never stored. Reuse of a previous credential with a
different idempotency key revokes the family.

### 3.3 Nodes and reachability

`node_invitations` stores `(network_id, invitation_id)`, the intended display name, SHA-256 secret
verifier, controller origin/fingerprint, expiry, optional initial-configuration JSON, creation and
consumption state, plus SHA-256 request/idempotency-key digests. A partial unique index on
`(network_id, idempotency_key_sha256)` makes invitation creation retryable. The bearer secret is
derived with a domain-separated controller signature and request/key digests, so an exact retry can
reconstruct it without storing plaintext. A different request under the same key is a conflict.

`nodes`

| Column | Constraint and meaning |
| --- | --- |
| `network_id`, `node_id` | Composite primary key |
| `display_name` | Mutable label, maximum 128 characters |
| `status` | `pending`, `approved`, `active`, `disabled`, `revoked`, or `removed` |
| `platform`, `agent_version`, `xray_version` | Last reported bounded metadata |
| `capabilities_json` | Canonical array of recognized capability strings |
| `provider_paused` | Last observed provider-owned pause state |
| `last_seen_at` | Nullable last authenticated heartbeat time |
| `last_heartbeat_generation` | Last accepted positive Node Host snapshot generation |
| `last_heartbeat_sha256` | Canonical 32-byte digest used to recognize exact retries |
| `consent_router_mapping` | Signed provider choice allowing narrow automatic mapping |
| `reality_public_key`, `reality_short_id` | Nullable all-or-nothing node-generated public material; the private key never leaves Node Host |
| `created_at`, `approved_at`, `revoked_at`, `removed_at` | Lifecycle timestamps |

Node enrollment consumes the invitation, inserts `nodes`, inserts the first authentication
credential, and writes an audit event in one `BEGIN IMMEDIATE` transaction. A preconfigured
invitation additionally changes the node to active and publishes its signed initial revision and
empty member snapshot before that transaction commits. Exactly one concurrent consumer succeeds;
any failure leaves the invitation unconsumed and no partial node or revision.

Control Service migration 11 adds idempotent preconfigured invitations and node public REALITY
material. Operator summaries expose only material readiness and a conservative derived onboarding
state; raw node keys and short IDs stay out of list/get responses.

`node_auth_credentials` stores `(network_id, node_credential_id)`, `node_id`, the node-generated
identity public key, optional certificate serial/issuer metadata, `not_before`, `expires_at`,
`created_at`, nullable `revoked_at`, and `rotation_parent_id`. The corresponding private key never
leaves Node Host. At most two unrevoked credentials may overlap for a node, and only for the bounded
rotation window.

`node_request_nonces` stores `(network_id, node_id, node_credential_id, nonce_hash)` as its primary
key with `request_timestamp` and `expires_at`. It is inserted before an authenticated node request is
accepted, rejects replay across HTTP tunnels, and is retained for at least the allowed clock-skew
window.

`node_endpoint_candidates`

| Column | Constraint and meaning |
| --- | --- |
| `network_id`, `node_id`, `endpoint_id` | Composite primary key |
| `mode` | `direct` or `relay` |
| `source` | `manual`, `pcp`, `natPmp`, `upnp`, or `relay` and must agree with mode |
| `address`, `port` | Bounded host/IP and port `1..65535` |
| `applied_revision` | Required foreign key to this node's immutable revision target |
| `observed_at`, `expires_at` | Node observation and finite mapping/relay lease; manual may omit expiry |
| `last_report_generation` | Binds presence to one complete authenticated heartbeat snapshot |
| `verification_generation` | Oldest heartbeat generation whose probe results belong to the current active lifecycle |
| `first_reported_at`, `last_reported_at`, `withdrawn_at` | Candidate lifecycle timestamps |

Candidate rows never contain node-authored verification state. The heartbeat transaction first
fences stale or conflicting durable `heartbeatGeneration` values, then uses the accepted generation
to refresh exact current candidates and mark omitted candidates withdrawn without deleting history.
An exact current retry is a no-op and cannot mutate controller-owned verification. An exact
withdrawn candidate may be reactivated after a normal node restart; this advances
`verification_generation`, resets controller verification to `pending`, and requires fresh probes
without deleting the old audit records. Reusing an endpoint ID with any changed immutable field is a
state conflict. Only one non-withdrawn row may exist for the same
`(network_id, node_id, mode, address, port, applied_revision)`. The schema-6 migration discards legacy
`node_reported_endpoints` because those rows allowed a node to assert `verified`.

`node_endpoint_verifications` is controller-owned and keyed by the same candidate identity. It
stores `status` (`pending`, `verified`, `failed`, or `withdrawn`), probe count, last probe/success,
latency, stable error code, verification expiry, and update time. Candidate insertion creates only
`pending`; candidate withdrawal forces `withdrawn`.

Schema migration 8 adds `endpoint_probe_attempts` as retained controller evidence. A monotonic
`attempt_id` orders claims while `(network_id, probe_id)` is unique. Each row binds the node,
endpoint, phase, runner, candidate heartbeat generation, address, port, applied revision, finite
claim expiry, and SHA-256 claim-token verifier. Only `claimed` may transition, exactly once, to
`succeeded`, `failed`, `cancelled`, or `expired`; rows cannot be deleted. The raw 256-bit claim
token exists only in the claimed job returned to the runner. Network I/O occurs after the claim
transaction releases the SQLite lock, and completion rechecks the token plus every bound candidate
field before committing. Direct-candidate ingestion, claim selection, and completion each require
the candidate port to equal `document.xray.publicPort` in the referenced immutable signed
revision; a relay endpoint keeps its separately assigned public port.

The implemented TCP phase stores a resolved public address, latency, and stable result code. It
rejects literal or DNS-resolved private, loopback, link-local, carrier-grade NAT, documentation,
benchmark, multicast, and reserved targets. A TCP success is preflight evidence only and does not
increment or mutate `node_endpoint_verifications`; only the later protocol-aware VLESS + REALITY
canary may make an endpoint `verified`. Candidate withdrawal, generation/revision change, node
pause, or loss of serving state turns an in-flight result into `cancelled` rather than current
health evidence.

A node is shareable only when it is approved/active, not revoked, not provider-paused, has a current
verified endpoint, and has an applied configuration compatible with the profile being generated.

### 3.4 Assignments and per-node member credentials

`user_node_assignments`

| Column | Constraint and meaning |
| --- | --- |
| `network_id`, `assignment_id` | Composite primary key; assignment has its own stable UUID |
| `user_id`, `node_id` | Required foreign keys with `UNIQUE(network_id, user_id, node_id)` |
| `status` | `enabled`, `disabled`, or `deleted` |
| `created_at`, `updated_at`, `disabled_at`, `deleted_at` | Lifecycle timestamps |

`user_node_credentials`

| Column | Constraint and meaning |
| --- | --- |
| `network_id`, `credential_id` | Composite primary key; stable credential UUID |
| `assignment_id`, `user_id`, `node_id` | Required IDs; a composite foreign key verifies all three identify the same assignment |
| `xray_email` | Immutable non-secret Xray tag, unique per node while active |
| `vless_uuid` | Owner-only UUID secret used only to build node desired state and encrypted member bundles; never returned by administrator APIs |
| `version` | Positive rotation number unique for an assignment |
| `status` | `pending`, `active`, `retiring`, or `revoked` |
| `created_at`, `activated_at`, `retire_after`, `revoked_at` | Rotation lifecycle |

`UNIQUE(network_id, assignment_id, version)`, `UNIQUE(network_id, node_id, xray_email)`, and
`UNIQUE(network_id, node_id, vless_uuid)` apply. The service generates a different VLESS UUID for
every node assignment. Rotation may overlap old and new credentials only until `retire_after`; a
disabled/deleted user or assignment gates bundle publication regardless of cached credential state.

Control Service migration 9 creates accounts, assignments, credentials, and durable creation
idempotency. Migration 10 closes the data-plane evidence loop. A newly generated credential is
`pending`: it is durable but is not evidence that Node Host has received, validated, or applied it.
Only an exact `applied` result for a revision whose immutable member snapshot contains that
credential promotes it to `active`. An active or retiring credential becomes `revoked` only when a
later applied snapshot excludes it. No Connect bundle may advertise a profile before this evidence
and endpoint verification both exist.

Disabling or revoking a node closes its assignments and revokes its stored member credentials in
the same Control transaction, but the provisioning view remains `removalPending` when the node's
last applied snapshot still contains them. Remote Xray removal still requires a reachable Node Host
and a successfully applied replacement revision; Control never claims stronger offline revocation.

### 3.5 Immutable desired state and rollout state

Administrator node summaries derive `lastFailure` from the highest revision with a terminal
`rejected` or `rolledBack` result. The API parses the bounded stored result and exposes only its
revision, state, stable error code, optional restored revision, and completion time.

`config_revisions`

| Column | Constraint and meaning |
| --- | --- |
| `network_id`, `revision` | Composite primary key; `revision > 0` |
| `revision_id` | Stable UUID, unique within the network |
| `parent_revision` | Previous published revision, or null only for revision 1 |
| `kind` | `change`, `operator_rollback`, or `recovery_republish` |
| `source_revision` | Required for rollback, otherwise null |
| `schema_version`, `min_agent_version` | Compatibility contract |
| `request_id`, `created_by_admin_id`, `created_at` | Causality and audit metadata |
| `summary_json` | Canonical secret-free summary |

`revision` is allocated with `UPDATE networks SET last_revision = last_revision + 1 ... RETURNING`
inside the publication transaction. A unique foreign key on `(network_id, parent_revision)` is not
used; the application requires `parent_revision = revision - 1`. Publication may target only
affected nodes, so an unaffected node can legitimately have an applied revision below the network
high-water mark.

Desired-state schema version 2 separates the unprivileged Xray loopback port from the public
admission-gate port and signs both. Version-1 rows remain immutable and verifiable for rollback;
new publications use version 2.

`node_revision_targets`

| Column | Constraint and meaning |
| --- | --- |
| `network_id`, `node_id`, `revision` | Composite primary key; foreign keys to node and revision |
| `source_node_revision` | Historical per-node revision used by rollback, if any |
| `schema_version`, `min_agent_version` | Must agree with the signed envelope |
| `artifact_ref` | Owner-only immutable desired-state envelope reference |
| `artifact_digest`, `desired_digest`, `signature` | SHA-256 envelope digest, canonical desired-input digest, and public signature |
| `created_at` | Publication time |

The artifact contains the protocol envelope and secrets required by that node. Before the database
commit, it is written to a temporary owner-only file, fsynced, atomically renamed, and hashed. A
failed database transaction can leave only an unreferenced artifact, which garbage collection may
remove. A committed row can never reference a partially written artifact.

`node_revision_member_snapshots` has one immutable marker for every newly compiled
`(network_id, node_id, revision)`, including an empty member list.
`node_revision_member_credentials` stores the exact credential, assignment, and user identities
present in that target, with uniqueness per revision and composite foreign keys back to both the
target and credential. Update/delete triggers make both tables append-only. The tables contain no
VLESS UUID; the signed owner-only artifact carries the secret.

Account and assignment APIs derive provisioning evidence by comparing `nodes.applied_revision`
with these snapshots. A historical applied snapshot plus a current applied snapshot that excludes
the assignment yields `removed`; a currently applied snapshot that still contains disabled access
yields `removalPending`.

`node_rollout_gates` is mutable operational state keyed by `(network_id, node_id, revision)`. It has
`gate_state` (`held`, `eligible`, `paused`, or `cancelled`), `wave`, `eligible_at`,
`last_transition_at`, `failure_code`, and `updated_by_admin_id`. Changing a gate does not alter the
immutable target or create a configuration revision; every operator gate change is audited.

`node_revision_results` is an append-only state journal keyed by
`(network_id, node_id, revision, state)`:

| Column | Constraint and meaning |
| --- | --- |
| `state` | `received`, `validated`, `applied`, `rejected`, or `rolled_back` |
| `state_rank` | Stored checked value: 10, 20, or 30; terminal states use 30 |
| `report_digest` | Hash of the canonical report body |
| `config_digest` | Required for `validated`, `applied`, and `rolled_back` |
| `rollback_revision` | Required only for `rolled_back` |
| `started_at`, `completed_at`, `reported_at` | Node-reported and server-received times |
| `error_code`, `diagnostic_json` | Stable code and bounded secret-free details |

An insert trigger rejects a lower-rank transition, any transition after a terminal state, a
`rolled_back` result without an earlier `validated` state, and an `applied` result whose config digest
does not equal the preceding `validated` result. Control verifies the signed desired digest; only
Node Host can compute the final rendered-config digest because REALITY private material remains
local. Repeating a state with the same `report_digest` returns the existing row; the same state with
different content is `revision_result_conflict`.

Views expose each node's latest targeted (`desired`), received, validated, applied, and failed
revision. Mutable cached values in heartbeat processing may accelerate UI queries but never replace
the revision journal as source of truth.

### 3.6 Profile bundles

`profile_bundles` stores `(network_id, bundle_id)`, `user_id`, exact `device_id`, monotonically
increasing generation per device, source/artifact digests, immutable encrypted artifact JSON,
signature, ETag, issue/refresh/offline-expiry times, and nullable supersession time.
`UNIQUE(network_id, device_id, generation)` and `UNIQUE(network_id, etag)` apply.

Bundle generation intersects current user/assignment authorization with current protocol-verified
endpoints and credential IDs present in each node's last applied target. Every node profile is HPKE
encrypted to that device's X25519 key before the complete manifest/ciphertext set is signed. It must
never advertise desired-but-not-applied credentials. Signed bytes are immutable; changed source
state creates a new `bundle_id` and device generation.

### 3.7 Request idempotency

`idempotency_records`

| Column | Constraint and meaning |
| --- | --- |
| `network_id`, `principal_type`, `principal_id`, `route_id`, `idempotency_key_hash` | Composite primary key; raw keys are never stored |
| `request_hash` | Hash of method, normalized route, versioned principal scope, and canonical body |
| `state` | `in_progress` or `completed` |
| `response_status`, `response_ref`, `response_hash` | Committed response metadata; secret responses use encrypted owner-only artifacts |
| `created_at`, `completed_at`, `expires_at` | Record lifetime |

Authenticated routes scope keys to the authenticated admin, node, user, or device. Enrollment and
activation scope them to the resolved invitation/activation ID after secret verification, never to
the raw secret. The mutation, audit event, and completed idempotency record commit in one
transaction. A matching retry returns the stored response; a reused key with a different request
hash returns `idempotency_key_conflict`. `in_progress` rows are not committed independently, so a
crash cannot permanently strand a request.

Idempotency records are retained for at least the supported retry window. Secret-bearing node/member
creation, login, activation, and refresh responses store only digests, stable IDs, timestamps, and
safe account snapshots; domain-separated controller-key derivation reconstructs the exact bearer
response after loss without a plaintext response artifact.

Migration 9 materializes this contract first for `POST /v1/admin/accounts`: it stores the canonical
request hash and the complete secret-free `201` response JSON in the same transaction as the user
and audit event. Concurrent or post-restart retries therefore return the same account identity and
body. Migration 12 extends the contract to setup delivery, login, and generation-scoped refresh.

### 3.8 Telemetry and audit

Control migration 13 implements `node_telemetry_cursors`, keyed by `(network_id, node_id)`, with
the highest acknowledged sequence and update time. `node_telemetry_events` is keyed by the same
identity plus sequence and stores event type, optional user, occurred/received times, canonical
event digest, and only the closed optional fields permitted for that event. It never stores
payloads, URL paths, queries, or destination byte claims. When detailed collection is disabled, a
connection event becomes a `droppedPolicy` row with no destination/client fields so sequencing can
advance without retaining opted-out data.

`traffic_hourly_aggregates` and `traffic_daily_aggregates` are keyed by
`(network_id, user_id, node_id, bucket_start)` and contain non-negative upload/download deltas,
connection count, and update time. Both are updated in the same transaction that inserts the raw
event and advances the cursor. `telemetry_policy` is a singleton opt-in plus a detailed-event
retention period from 1 to 90 days.

Telemetry ingestion uses `BEGIN IMMEDIATE` on the node cursor:

1. Verify ordering, bounds, and the batch digest before opening the write transaction.
2. Lock/read `acknowledged_sequence`; the expected sequence is `acknowledged_sequence + 1`.
3. If the whole batch is at or below the cursor, acknowledge the cursor without inserting data.
4. Require every new batch to begin exactly at `acknowledged_sequence + 1`; reject overlap or a gap
   without changing data and return `expectedSequence`.
5. Insert event rows, update hourly/daily aggregates, and advance the cursor in one commit.

`audit_events` is append-only and keyed by `(network_id, audit_id)`. It contains `occurred_at`,
`actor_type`, nullable `actor_id`, `action`, `target_type`, nullable `target_id`, `result`,
`request_id`, nullable `idempotency_key_hash`, and canonical secret-free `details_json`. Indexes cover
time, actor, and target. Enrollment, account, assignment, revision, rollout gate, rollback,
revocation, purge, migration, backup restore, and recovery-fence actions are mandatory audit events.

## 4. Node Host Local Schema

The implemented Node Host migration version is 15. The database is owner-only and bound to one
enrolled `node_id`; it uses the same SQLite contract and migration table. The list below includes
implemented tables and later planned policy/telemetry expansions.

- `node_identity`: singleton row containing `network_id`, `node_id`, public identity, identity
  `secret_ref`, installation ID, created time, and revocation state. It is never regenerated because
  metadata is corrupt.
- `provider_network_policy`: singleton provider-owned automatic-mapping flag, durable consent time,
  reserved permanent-UPnP flag, stable last mapping error and attempt time, and update time. The
  current agent always leaves the reserved flag disabled and rejects permanent leases. Local policy
  always overrides controller desire toward less sharing.
- `provider_consent_receipt`: singleton invitation-bound disclosure version, required host-owner
  and exit-IP confirmations, router-mapping choice, and acceptance time. It is committed before
  enrollment network I/O and reused byte-for-byte on retry; a different invitation may replace it
  only while the installation remains unenrolled.
- `controller_registration`: controller URL, network ID, controller epoch, pinned signing public
  keys, node-auth `secret_ref`, credential ID, supported schema versions, last contact, and
  credential-rotation state.
- `controller_status_state`: latest signature-verified controller lifecycle and endpoint-readiness
  snapshot, with immutable transcript/envelope digests and non-regressing heartbeat generation.
- `xray_runtime_config`: installer-supplied absolute binary path, trusted SHA-256, bounded version
  probe result, a persisted loopback-only Stats API port, and configuration/update times. The
  separate REALITY private seed remains in the
  owner-only secret store; only its public key and derived short ID are exposed by safe status.
- `desired_state_artifacts` and `local_revision_results`: the current receive/validation journal.
  Signed envelopes and lifecycle result payloads are immutable; only a result's nullable delivery
  acknowledgement may change. Results are uploaded in explicit lifecycle order rather than text
  sort order.
- `rendered_xray_configs`: one immutable row per validated revision containing only the private
  candidate's relative path, `sha256:` config digest, historical pinned-binary digest, and
  validation time. The corresponding 0600 JSON is under a 0700 node data subdirectory, is created
  without overwriting an existing artifact, and is digest-checked before a queued `validated`
  result can be retried.
- `xray_active_state`: the singleton durable pointer to the last locally proven revision, config
  digest, historical binary digest, generation, restart count, and apply timestamps. A null pointer
  means no revision has ever passed activation health; it is not inferred from a process ID.
- `xray_activation_journal`: one retained row per attempted revision with an immutable predecessor,
  start time, mutable closed phase, attempt count, completion time, and stable secret-free error
  code. An interrupted nonterminal row forces conservative startup recovery before any newer
  candidate can run.
- `router_mapping_leases`: one retained row per finite owned mapping. It binds mapping and endpoint
  IDs, applied revision, PCP/NAT-PMP/UPnP source, gateway and internal/external addresses and ports,
  protocol-specific ownership evidence, a hashed local topology fingerprint, lease interval,
  closed lifecycle state, and stable failure code. A partial unique index permits only one active
  or releasing mapping.
- `apply_journal`: one row per revision with envelope artifact reference/digest, state
  (`received`, `validated`, `activating`, `applied`, `rejected`, `rolling_back`, `rolled_back`),
  rendered config digest, predecessor revision, timestamps, attempt count, and error code. State
  changes are transactionally committed before the corresponding filesystem/process action.
- `applied_revision`: singleton containing current applied revision/config digest/artifact reference,
  highest seen revision, pending revision, and last known-good time. `highest_seen_revision` never
  decreases, including after rollback.
- `config_backups`: `(revision, config_digest)` primary key, owner-only artifact reference, created
  time, last successful health time, and pin reason. Artifact hashes are verified before use.
- `telemetry_spool_state` allocates the next monotonic sequence. `telemetry_spool` stores immutable
  canonical event JSON/digest, event type, occurred/created time, and nullable acknowledgement.
  Sequence allocation and insertion are one transaction; unacknowledged aggregate traffic is never
  silently dropped. Acknowledged rows remain replayable for seven days.
- `xray_traffic_collection_state` and `xray_user_traffic_counters` bind the previous cumulative
  counters to an applied revision/runtime generation. Counter restart or rollback emits a bounded
  collection-status transition and establishes a new baseline; only positive differences become
  `TrafficDelta`, and connection count remains zero when Xray cannot prove it.
- `reachability_results`: append-only attempt ID, endpoint candidate, local test result, mapping
  protocol, started/completed times, error code, and expiry.
- `relay_provider_consent` records the local disclosure version and acceptance time.
  `relay_assignment` stores only endpoint/route metadata, expiry, owner-only material generation,
  and digest. Token, client certificate/private key, and relay CA bytes live under a 0700
  generation directory as 0600 files and are deleted on explicit revoke.

Control migration 15 adds `relay_routes`, `relay_grants`, and `relay_outbox`. `relay_routes`
contains the stable logical `route_id` and endpoint ID for a node. Each `relay_grants` row has a
unique `grant_id` and monotonic generation, public metadata, HPKE ciphertext, signed route JSON,
and digests only; it has no raw route token, issued client key, or client certificate plaintext.
`relay_outbox` persists publish/revoke work across file-side-effect crashes. The managed filename
and Relay/Node Host registration key are the exact `grant_id`, never the stable `route_id`.
`published` follows an observed exact file; `revoked` follows observed absence. N+1 publication
queues N revocation only after the new exact grant is published.

Node-local REALITY private keys and raw controller credentials are outside SQLite. The database may
be restored only when its node identity matches the credential-store identity; otherwise Node Host
enters recovery and requires re-enrollment as a new node.

Acknowledged telemetry remains locally recoverable for seven days before deletion. If disk pressure
requires shedding optional connection metadata, Node Host replaces it with an ordered redaction
marker and preserves sequence continuity. If durable aggregate traffic cannot be queued, sharing is
paused rather than silently losing quota/accounting data.

## 5. Connect Local Persistence Version 1

Connect does not share Control's SQLite database. Native Keychain/Credential Manager entries hold
device private keys, two refresh slots with pending idempotency state, activation/login pending
operations, and one versioned installed-account record containing public controller trust and the
device binding. The renderer cannot enumerate or read these records.

Each device has an owner-only `account-bundles-v1/<network>/<user>/<device>` directory containing
immutable signed HPKE bundle artifacts plus one atomic `active.json` pointer. Writes sync the file
and parent directory; recovery verifies digest, signature, device/network/controller binding,
generation, version, and time before decrypting. The current and one prior complete generation are
retained. An invalid, expired, interrupted, or rollback candidate never replaces the last valid
bundle. Offline use is allowed only through `offline_expires_at`.

Selection health is bounded process state rebuilt by backend-owned probes after restart. System
proxy mode stores one owner-only, size-bounded, atomic recovery journal containing the exact prior
macOS/Windows proxy settings. Startup, stop, logout, failure, expiry, and app-exit paths serialize
restoration before clearing the journal. Manual loopback mode never captures or mutates OS proxy
state.

## 6. Deletion and Referential Rules

Users, devices, nodes, assignments, and credentials are soft-deleted or revoked first. Public APIs
return them according to explicit lifecycle filters. Hard deletion is a retention purge and must:

1. Create an audit event describing scope and policy.
2. Preserve stable IDs in retained revisions, telemetry aggregates, and audit records.
3. Replace optional labels and addresses with tombstone/redacted values where privacy purge requires
   removal but referential history must remain.
4. Delete secret artifacts only after no live session, bundle, revision, backup, or idempotent
   response references them.

Foreign keys prevent deletion of a parent with live operational children. Cascades are allowed only
for ephemeral probe attempts, expired idempotency responses, and local health samples whose parent
artifact is being purged by the same retention transaction.

## 7. Retention and Garbage Collection

Retention is time-based and scoped by network/node/user where applicable. It runs in bounded chunks,
records its high-water mark, yields between transactions, and never blocks request handling for an
unbounded delete.

| Data | Default | Rule |
| --- | --- | --- |
| Raw connection events | 30 days, configurable 1-90 | Optional collection; purge by `occurred_at` per node |
| Raw traffic samples | 90 days | Daily aggregate must exist before purge |
| Daily usage aggregates | 365 days | Preserve longer when required by an active quota period/export |
| Audit events | 365 days | Security/recovery events may be explicitly pinned |
| Endpoint probe attempts | 30 days | Current state remains in `node_endpoint_verifications` |
| Telemetry batch receipts | 30 days | Cursor is retained for the life of the node tombstone |
| Idempotency records | 24 hours | Never shorter than supported retry window |
| Expired/revoked sessions and one-time tokens | 30 days after terminal time | Hash only; audit history remains |
| Profile bundle artifacts | Offline expiry plus 7 days | Current device-visible bundle is always pinned |
| Revision metadata/results | At least 365 days | Stable audit metadata remains after artifact expiry |
| Revision artifacts | Newest 100 per network and all artifacts newer than 365 days | Additional pin rules below apply |

Revision garbage collection always pins the current desired target, every node's applied target, the
three preceding known-good targets per node, unresolved/failed rollout targets, rollback sources,
artifacts referenced by unexpired bundles, and artifacts involved in an open recovery fence. The
UI marks a revision `metadata_only` when its artifact is gone; it cannot be selected for rollback.
Referenced VLESS secret material follows the same pin graph.

Node Host retains the current config, at least three prior known-good configs, every pending/failed
candidate for 30 days, and acknowledged telemetry for seven days. Connect retains the current
bundle and one previous valid bundle until both are past offline expiry.

## 8. Migrations and Compatibility

Migrations are ordered, checksummed Rust-embedded SQL/code units. Startup performs these steps before
binding an HTTP or local control socket:

1. Acquire the single-process data-directory lock and validate the SQLite application identity.
2. Open read-only first; run `quick_check`, inspect schema version, and verify migration checksums.
3. Refuse a database newer than the binary's maximum schema.
4. Create a SQLite online backup and artifact manifest outside the application data directory before
   any non-additive migration.
5. Reopen read-write, use one `BEGIN EXCLUSIVE` transaction per migration, and insert its
   `schema_migrations` row in that same transaction.
6. For table rewrites, create the new table, copy with explicit columns and validation queries,
   swap names, recreate indexes/triggers, run `foreign_key_check`, and commit.
7. Set `user_version`, run `quick_check`, and only then start serving.

A failed migration rolls back completely and leaves the service stopped with a stable diagnostic.
There are no automatic down migrations. Releases use expand/backfill/contract migrations so the
immediately previous binary can run throughout a rolling application upgrade. A contract migration
is allowed only after the compatibility window has elapsed and a verified backup exists.

The prototype `xray-plane.db` tables (`user_traffic`, `user_usage_v2`, `connection_logs`, `kv`,
`user_identities`, and earlier `traffic_samples`/`connection_events`) are imported, not modified in
place. The importer:

- makes and hashes a read-only snapshot of the prototype database;
- creates the new Control Service database at a separate path;
- preserves valid stable IDs, generates IDs only where none exist, and records the mapping;
- maps the prototype local node ID to an enrolled/local `node_id`;
- converts cumulative usage only from already normalized stored deltas and never guesses missing
  destination bytes;
- quarantines ambiguous email-to-user connection rows instead of misattributing them;
- commits imported rows and an `legacy_import_completed` audit event atomically; and
- is restartable by an idempotency/import manifest digest.

The old database remains read-only until the operator verifies totals and explicitly removes it.

## 9. Backup, Restore, and Integrity

Control Service creates a daily backup using SQLite's online backup API, then checkpoints and hashes
the resulting database. A matching manifest contains schema version, network ID, controller epoch,
revision high-water mark, artifact digests, and secret-store backup status. Copying only the main
SQLite file while WAL writes are active is not a backup.

Backups are encrypted and copied outside the application data directory. Keep 30 daily and 12
monthly backups by default. Restore is performed into a staging directory, where `integrity_check`,
`foreign_key_check`, migration, artifact hash verification, and network/signing identity checks must
pass before an atomic directory switch. Recovery behavior after a stale restore is defined in
`ROLLOUT_AND_RECOVERY.md`.

## 10. Required Data-Layer Acceptance Tests

1. A fresh database creates exactly the current schema version with all foreign keys, indexes,
   triggers, and singleton constraints active.
2. Every supported prior schema fixture upgrades transactionally; injected failure after every
   migration statement leaves the prior schema and rows intact.
3. A newer or checksum-modified schema is refused without writes.
4. Two concurrent invitation consumers produce one node and one reusable idempotent response, not
   two identities or a consumed-without-credential state.
5. Reusing an idempotency key with the same request returns the byte-equivalent response; changing
   the request returns `idempotency_key_conflict`.
6. Concurrent configuration mutations allocate unique, strictly increasing revisions and atomically
   commit logical changes, targets, idempotency records, and audit events.
7. Attempts to update/delete published revisions or targets fail. Duplicate result reports are
   idempotent, while regressive, post-terminal, or digest-conflicting reports fail.
8. One logical user assigned to two nodes receives two distinct credential IDs and VLESS secret
   references; renaming the user does not change attribution.
9. Duplicate, overlapping, and gapped telemetry batches produce the specified cursor and exact
   aggregate totals under concurrent retry.
10. Retention purges only expired rows, preserves per-node fairness and all revision/bundle pins, and
    never uses a global row-count limit.
11. Backup/restore preserves schema version, IDs, revision high-water mark, cursor values, artifact
    digests, and aggregate totals.
12. Secret-scanning database pages, normal logs, API list/get responses, renderer state, and support
    bundles finds no raw invitation, refresh, node-auth, VLESS, signing, or REALITY private secret.
