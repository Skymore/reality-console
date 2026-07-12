# Rollout and Recovery

Status: authoritative desired-state delivery, rollback, convergence, and recovery design.

This document defines how immutable desired state becomes running node state and how the system
recovers without replacing a known-good data plane with an unverified candidate. Protocol payloads
and result names are defined by `CONTROL_PROTOCOL.md`; durable records are defined by
`DATA_MODEL.md`.

## 1. Safety Invariants

The implementation must preserve these invariants across retries, crashes, partitions, upgrades,
and operator actions:

1. A node runs only a locally validated, signed desired-state artifact for its own `node_id`.
2. Publishing a revision never mutates a prior revision. Rollback publishes a higher revision and
   never decrements a revision counter.
3. Failure before candidate health is proven leaves or restores the prior known-good configuration.
4. Re-delivering a terminal `(node_id, revision)` result does not rewrite files or restart Xray.
5. Control Service unavailability does not stop an already serving node or invalidate an unexpired
   Connect bundle.
6. Provider pause/removal is local authority and can only reduce sharing; controller desire cannot
   override it.
7. A disabled or deleted user, device, assignment, node, or credential is a hard deny. Rollback may
   restore operational settings but may not implicitly reverse a hard deny.
8. Endpoint advertisement requires a current controller-side probe and an applied compatible node
   configuration.
9. There is no fleet-wide atomic commit. Per-node observed state is explicit, and partial convergence
   is a normal, visible state rather than hidden success.
10. The agent accepts only the closed desired-state schema. No rollout or recovery path can execute
    an arbitrary command or shell string.

## 2. Revision and State Vocabulary

- **Network revision**: immutable, globally increasing publication number allocated by Control
  Service.
- **Target revision**: a network revision containing an immutable envelope for a specific node.
  Nodes unaffected by a network change have no target row for that revision.
- **Desired revision**: newest eligible target for a node.
- **Received revision**: artifact durably stored and its envelope digest/signature checked.
- **Validated revision**: closed schema accepted and candidate Xray configuration validated without
  replacing the active config.
- **Applied revision**: candidate atomically activated and bounded startup/health checks passed.
- **Rejected revision**: candidate failed authenticity, compatibility, schema, policy, or pre-apply
  validation; active config was never replaced.
- **Rolled-back revision**: activation began but the previous known-good config was restored.
- **Converged node**: applied revision equals its newest eligible target, provider policy permits
  sharing, and its advertised endpoint remains verified.

`desired`, `received`, `validated`, and `applied` are independent values in Control. The UI must not
collapse them into one `version` field or infer success from heartbeat freshness.

## 3. Publishing Desired State

### 3.1 Configuration-affecting transaction

A configuration-affecting admin request uses its idempotency key and one publication transaction:

1. Authenticate and authorize the admin, canonicalize the request, and check the idempotency record.
2. Lock the network revision counter with `BEGIN IMMEDIATE`.
3. Apply the logical mutation, including immediate session revocation for a disabled member/device.
4. Determine affected nodes from stable IDs, not labels.
5. Allocate `revision = last_revision + 1` and record its parent.
6. Compile a complete node-specific snapshot for every affected node. A snapshot is not a patch and
   does not depend on a node's in-memory state.
7. Resolve per-node credential references in the service process, create and sign each envelope,
   write/fsync/rename its owner-only artifact, and insert its digest and target row.
8. Create rollout gates and the secret-free audit event.
9. Mark the idempotency response completed and commit all database changes together.

If compilation or artifact persistence fails for any affected node, no logical mutation or revision
is committed. Orphan pre-commit artifacts are harmless and later garbage-collected. Once committed,
revision rows, target rows, artifacts, digests, and signatures are immutable.

Non-configuration operations such as changing a display label do not create a revision unless the
label is intentionally present in generated Xray tags or client profiles. Account disable,
assignment change, credential rotation, endpoint-affecting Xray configuration, and node removal
always create revisions for affected nodes.

### 3.2 Authorization safety floor

Every compilation, including operator rollback, applies the current authorization safety floor:

- disabled/deleted users and assignments are absent;
- revoked credentials and nodes are absent;
- expired credential overlap is absent; and
- provider policy is not widened by desired state.

Therefore selecting an old revision as rollback source does not re-enable an identity revoked after
that revision. Re-enabling access is a separate, explicit audited admin mutation that creates its own
credentials/revision as necessary.

### 3.3 Rollout classes

The publisher assigns one of these policies:

| Class | Delivery policy | Typical operations |
| --- | --- | --- |
| `security_urgent` | All affected targets immediately eligible; failed/offline nodes become explicitly noncompliant | User/node/credential disable or revocation |
| `node_scoped` | The single affected node immediately eligible | Node endpoint or node-specific setting |
| `standard` | One canary, then bounded waves after stabilization | Multi-node Xray/runtime setting |
| `operator_held` | All targets held until explicit release | High-risk maintenance or recovery |

For `standard`, the default is one healthy canary, a 120-second stabilization period, then waves of
at most two nodes while keeping at most one previously healthy node unavailable. Small fleets may
reduce a wave to one. A failure pauses unreleased waves; it does not mutate or delete their targets.
Gate transitions are audited.

Security-urgent rollout bypasses canary delay because leaving revoked access active is the greater
risk. It still does not claim convergence until each node reports a terminal result.

## 4. Delivery and Reconciliation

Node Host polls with its durable `highest_seen_revision` and conditional request metadata. Control
Service returns the newest eligible target above the node's reported revision and marks older
unstarted targets superseded in mutable rollout state. Each target is a complete snapshot, so missing
intermediate revisions do not block convergence. If a candidate is already activating, Node Host
finishes or rolls it back before fetching the newest target.

The service returns:

- `204` when no eligible target is newer;
- `200` with the exact immutable signed artifact;
- `409` when the node reports an unresolved local candidate/result that conflicts with the next
  safe delivery; or
- `426` when no mutually supported required schema exists.

An unaffected node can remain at revision 10 while another node applies network revision 12. This is
not drift if the first node had no targets in 11 or 12. Drift is evaluated against the latest target
for that node, never against `networks.last_revision` alone.

Heartbeat is observed-state evidence, not a command acknowledgement. Revision result reports are
the durable source of truth. If heartbeat and result history disagree, Control marks the node
`reconciling`, stops newer delivery, and asks it to replay its durable apply journal.

## 5. Node Apply State Machine

Node Host serializes apply operations; only one candidate can be pending. All filesystem paths are
fixed by the agent and no desired-state field is interpreted as a command or arbitrary path.

### 5.1 Receive

1. Download with a size/time bound to a temporary owner-only file.
2. Verify network ID, node ID, revision, schema version, minimum agent version, envelope digest, and
   signature against a pinned controller key.
3. Reject a revision below `highest_seen_revision` unless it is byte-identical to an existing local
   journal entry requested for reconciliation.
4. Persist the artifact and `received` apply-journal state, fsync, then report `received`.

Authentication/signature, wrong-node, unsupported required schema, expired credential, and closed-
schema violations produce `rejected` with a stable code. They do not retry indefinitely and do not
touch the active Xray config.

### 5.2 Validate

1. Resolve only node-local permitted secret references, including the REALITY private key.
2. Render candidate Xray JSON into a new owner-only file from typed values.
3. Enforce local provider limits and reject any candidate that attempts to widen them.
4. Run the pinned Xray binary's offline configuration validation with a bounded timeout.
5. Hash the rendered config, persist that node-computed digest with `validated`, fsync, then report
   `validated`. Control separately verifies the signed desired-input digest.

Validation failure records a bounded secret-free diagnostic and `rejected`. The previous process and
config are unchanged.

### 5.3 Activate

1. Verify the current config digest against the recorded applied revision. A mismatch enters
   recovery rather than overwriting unknown local state.
2. Copy or hard-link the current known-good config into a versioned backup, fsync the file and
   directory, and verify its digest.
3. Persist journal state `activating` with predecessor revision before changing the active path.
4. Atomically rename the candidate over the active config on the same filesystem and fsync the
   parent directory.
5. Restart the supervised Xray child using bounded graceful-stop and force-stop timeouts.
6. Require process survival, expected loopback/control listener readiness, and a local protocol
   smoke check within 30 seconds.
7. Continue a 120-second stabilization watch. Only after it passes, persist the new applied
   revision/config digest and report the terminal `applied` result. Any earlier failure rolls back
   and reports the terminal `rolledBack` result.

Heartbeat may show `stabilizing` during the watch, but revision results do not claim `applied` yet. A
controller-side endpoint probe is separate and required before the endpoint is advertised. A node
can be correctly applied but not shareable because reachability failed.

### 5.4 Duplicate delivery

For a locally terminal revision, Node Host verifies the delivered digest against its journal and
returns the existing result without rendering, renaming, or restarting. Same revision with a
different digest is a security conflict: the node retains its current config, reports
`revision_digest_conflict`, and stops desired-state polling until operator resolution.

## 6. Automatic Rollback

Automatic rollback is a local corrective action for a candidate; it does not publish a new network
revision.

Rollback is required when, after activation starts:

- atomic activation or filesystem durability cannot be confirmed;
- Xray fails to start or exits during initial health/stabilization;
- the expected local listener or protocol smoke check fails;
- the active config digest does not match the activated candidate; or
- a provider safety check detects that the candidate widened local limits.

Node Host performs these steps:

1. Persist `rolling_back` and stop the candidate process.
2. Verify the predecessor backup digest. If it cannot be proven, do not guess or regenerate; remain
   stopped in `recovery_required`.
3. Atomically restore and fsync the predecessor config.
4. Restart Xray and run the same bounded health check.
5. Persist the predecessor as current, retain the failed artifact/diagnostic, and report the
   candidate as `rolledBack` with `rollbackRevision`.

If the restored predecessor also fails, the node reports `rollback_failed`, remains non-shareable,
and exposes local recovery instructions. It must not alternate indefinitely between configs.

After the 120-second stabilization window, an unrelated process crash restarts the current applied
revision idempotently. Repeated crashes within a five-minute correlation window may trigger rollback
only when there is a verified predecessor and the crash began with the newly applied config;
otherwise operator diagnosis is required.

Control pauses later standard-rollout waves on `rejected`, `rolledBack`, missing stabilization, or
lost endpoint verification. Security-urgent changes continue to other nodes while clearly marking
the failed node noncompliant and removing it from new bundles.

## 7. Operator Rollback

Operator rollback is an idempotent admin mutation and always creates a new revision. It never edits a
target, asks a node to decrement, or treats a local automatic rollback as fleet desired state.

### 7.1 Preconditions

For every selected node, Control Service verifies that:

- the source revision targeted that node and reached `applied` at least once;
- its artifact, referenced secrets, schema support, and digest are retained and valid;
- the node has no unresolved local apply journal conflict; and
- applying the source through the current authorization safety floor produces a valid candidate.

If any selected source is unavailable, the request fails before publication unless the operator
explicitly narrows the scope. `metadata_only` revisions cannot be rolled back.

### 7.2 Scope

- **Node rollback** targets one or an explicit set of nodes. Other nodes remain on their current
  desired state.
- **Affected-fleet rollback** targets every node targeted by the failed change for which a compatible
  source exists.

The implemented admin surfaces are `POST /v1/admin/nodes/{nodeId}/rollback` for one node and
`POST /v1/admin/rollbacks` for an explicit affected cohort. A cohort contains at most 100 unique
node/source/failure tuples. Control validates the entire canonicalized cohort before allocating a
revision, so one invalid or incompatible tuple publishes none of them.

Rollback restores operational configuration inputs from the selected source, then overlays current
hard denies and local provider restrictions. It does not restore old member sessions, consumed
invitations, revoked credentials, endpoint verification, or deleted identities.

### 7.3 Publication and completion

The service allocates a higher revision with `kind = operator_rollback`, records both the failed and
source revisions, generates newly signed node envelopes, and releases rollback targets immediately
unless the operator explicitly holds them. The audit event records scope, reason, source, target,
and idempotency key hash.

Rollback succeeds per node only after the new revision reports `applied` and required endpoint probes
pass. The UI reports `rollback progressing`, `rollback complete`, or `rollback partial`; accepting
the HTTP request is not completion.

## 8. Partial Fleet Convergence

Control never presents a multi-node publication as simply successful while nodes differ. A rollout
has one derived state:

| State | Meaning |
| --- | --- |
| `held` | No target is eligible yet |
| `progressing` | At least one eligible node is pending and none has terminal failure |
| `stabilizing` | Current wave applied but has not passed stabilization/probe gates |
| `converged` | Every selected node applied and required probes passed |
| `partial` | Some selected nodes converged and others are offline, held, incompatible, or failed |
| `paused` | Further waves are deliberately stopped |
| `failed` | No selected node converged or a declared safety threshold was crossed |
| `rolled_back` | A later operator rollback converged for the selected scope |

Each node row shows desired, received, validated, applied, endpoint status, provider pause, last
heartbeat, last error code, and age. Operator actions are `retry report reconciliation`, `release
wave`, `pause rollout`, `cancel unreleased targets`, `rollback`, or `remove node from service`; there
is no ambiguous `force success` action.

New profile bundles are built from each node's applied target and current authorization. A node with
a pending incompatible credential change is omitted for the affected user rather than advertised
optimistically. Existing cached bundles remain cryptographically valid until their offline deadline,
so emergency disable is immediate at refresh/session authorization but physically removes the user
from an offline node only when that node reconnects. Until then Control shows `revocation pending`,
marks the node noncompliant, omits it from new bundles, and may revoke its relay/node control
credential. The product must not claim stronger offline revocation than the data plane can enforce.

## 9. Provider Pause, Removal, and Reachability

Provider pause is processed locally without waiting for Control Service:

1. Stop accepting member traffic and stop Xray if needed.
2. Remove consent-gated router mappings and close the relay tunnel.
3. Persist provider policy and heartbeat/report when connectivity returns.

Desired state may be received and validated while paused, but the node remains non-shareable. On
resume, Node Host applies or starts the latest validated desired state and requires a new external
probe before advertisement.

Provider removal revokes local node credentials, removes mappings/tunnels, stops Xray, and tombstones
local registration even while offline. Control later reconciles removal. Rejoining creates a new
`node_id`; copying old state must not clone the identity successfully.

Loss of endpoint verification removes only that endpoint from new bundles. It does not roll back a
valid Xray configuration. Direct and relay endpoints fail independently.

## 10. Crash Recovery by Apply Boundary

On every Node Host start, recovery runs before ordinary polling or Xray supervision:

| Durable journal state | Recovery action |
| --- | --- |
| No candidate; applied digest matches active file | Start/continue applied config idempotently |
| `received` | Reverify artifact and continue validation, or reject |
| `validated` | Verify predecessor/current digest, then continue activation |
| `activating`; active file is predecessor | Continue atomic activation |
| `activating`; active file is candidate | Run health check and finish apply or rollback |
| `activating`; active file matches neither | Stop Xray and enter `recovery_required` |
| `rolling_back`; active file is candidate | Continue verified restore |
| `rolling_back`; active file is predecessor | Verify health and finish rollback |
| `applied`; process absent | Restart exactly that applied revision |

Recovery compares hashes, not modification times or filenames. It never deletes the only verified
known-good backup. A crash after server commit but before receiving the HTTP response is resolved by
re-reporting the durable local terminal result.

Connect uses the same journal principle for proxy changes. On start it either completes the intended
loopback listener/proxy setup or restores the captured OS proxy state; it never assumes a previous
stop completed.

## 11. Control Service Failure and Restore

### 11.1 Temporary outage

While Control Service is unavailable:

- applied nodes keep serving and enforce provider policy locally;
- Node Host queues telemetry durably and backs off boundedly;
- Connect uses the last valid bundle only until `offline_expires_at`;
- activation, refresh, mutation, probe, and aggregated telemetry are unavailable; and
- no component treats timeout as authorization to weaken checks.

After recovery, nodes resume from durable revision and telemetry cursors. Duplicate reports and
batches are safe.

### 11.2 Disk full or database busy

The service bounds waits and returns a retryable stable error without claiming a mutation committed.
SQLite `FULL`, `IOERR`, failed fsync, or artifact-store exhaustion places configuration publication
in read-only degraded mode. Existing desired-state reads may continue only when artifact hashes
verify. Telemetry returns no acknowledgement unless its cursor transaction committed.

### 11.3 Database corruption

On failed integrity checks, stop all writes and do not create a fresh empty database at the same
path. Existing nodes continue their applied configuration. Recovery requires a verified backup or
an explicit new-network bootstrap; these are never silently conflated.

Restore procedure:

1. Stop Control Service and preserve the corrupt directory read-only for forensic export.
2. Restore database, artifacts, and secret-store material into staging.
3. Run SQLite integrity/foreign-key checks, migrations, artifact digest verification, and signing-key
   identity checks.
4. Start in `recovery` status with publication, enrollment, refresh issuance, and retention disabled.
5. Collect authenticated heartbeats/results from known nodes without sending older desired state.
6. Compute the revision high-water mark as the maximum of restored metadata, backup manifest, and
   authenticated node `highest_seen_revision`; never reuse a revision number.
7. Reconcile logical authorization, node-applied artifacts, sessions, and telemetry cursors. Show all
   post-backup uncertainty to the operator.
8. After explicit operator confirmation, set a new controller epoch and publish a
   `recovery_republish` revision above the high-water mark to affected nodes.
9. Exit recovery only after a new backup succeeds and critical nodes converge or are explicitly
   removed from scope.

A node whose applied revision is unknown to the restored service keeps serving but is quarantined
from new profile bundles until reconciled. The service must not overwrite it with a numerically older
revision.

Refresh sessions created after the restored backup are unknown and therefore fail closed. They are
not recreated from client claims. Node credentials missing from the restore must be recovered from
the encrypted backup or rotated through an authenticated recovery flow; otherwise the node is
re-enrolled with a new identity.

The implemented Control CLI provides `backup create`, `backup verify`, and explicit recovery-mode
`restore`. It uses SQLite's online backup API, owner-only staging, controller-signed manifests,
artifact/identity/migration checks, and per-domain high-water comparison. Restore writes a new
generation directory and never replaces an existing database path. Because the controller identity
sidecar is not application-encrypted, backup creation requires a named externally encrypted
destination contract. Switching the service to the restored generation and performing steps 4-9
above remain explicit deployment/operator actions.

### 11.4 Telemetry after stale restore

Node Host retains acknowledged telemetry for seven days. If restored Control reports an earlier
expected sequence, the node replays the retained contiguous range and normal ingestion deduplicates
it. If the required prefix is no longer available, Control records a visible data gap. Advancing a
cursor past that gap requires an explicit operator recovery action and audit event; aggregate bytes
for the missing interval are reported unknown, never fabricated.

## 12. Artifact and Key Recovery

A committed revision with a missing or digest-invalid artifact is not regenerated under the same
revision. Control returns a retryable service error, marks the target corrupt, pins related evidence,
and requires either artifact restore or a newly published revision.

Controller signing-key rotation uses a bounded overlap: nodes first apply a revision signed by the
old key that trusts the new public key, then subsequent artifacts may use the new key. Losing the
only trusted signing private key requires restoring encrypted key material; Control cannot ask nodes
to trust an unsigned replacement.

Node REALITY private-key loss cannot be repaired by copying another node's key. Restore the node's
owner-only backup or rotate to new local key material through a newly published configuration and
new profile bundles. Until clients receive compatible public parameters and the endpoint probe
passes, the node remains unadvertised.

Pinned Xray binary checksum failure, missing binary, or unsupported binary version prevents apply.
Node Host keeps the existing verified binary/config where possible and reports a stable upgrade
error; it never downloads and executes an unverified replacement.

## 13. Revision and Backup Retention

Control retains revision artifacts according to `DATA_MODEL.md`: newest 100 and at least 365 days,
plus every desired/applied/predecessor/unresolved/bundle/recovery pin. Node Host retains current plus
at least three prior known-good configs and 30 days of failed candidates. A rollout cannot select a
revision whose artifact or secret dependencies have expired.

Before retention removes a rollback artifact, Control computes the full reference graph in one
snapshot transaction, marks candidates, rechecks references immediately before deletion, deletes
the owner-only file, and then records artifact removal. A crash can cause an orphan or a missing-file
marker, but never reuse an artifact reference for different bytes.

Daily Control backups use SQLite online backup plus an artifact/secret manifest and are copied
outside the application data directory. Node config backups are separate from Control backups; both
are required because neither side owns all recovery material.

## 14. Operator Runbooks

### Bad revision on one node

1. Confirm desired/received/validated/applied values and stable error code.
2. Verify whether automatic rollback restored a healthy predecessor.
3. Pause later waves if not already paused.
4. Fix and publish a new revision, or select a retained known-good source for node rollback.
5. Require applied result and endpoint probe before returning the node to bundles.

### Bad revision across a partial fleet

1. Freeze unreleased waves; do not alter already published targets.
2. Remove failed/noncompliant nodes from new bundles.
3. Choose affected-fleet rollback with a known-good per-node source.
4. Track rollback convergence per node; do not wait indefinitely for offline nodes.
5. Explicitly remove or quarantine unreachable nodes before declaring the selected fleet converged.

### Node local-state corruption

1. Pause sharing and preserve the state directory.
2. Match credential-store identity to a verified local database/config backup.
3. Restore only matching artifacts and replay the apply journal.
4. If identity cannot be proven, revoke the old node in Control and enroll as a new `node_id`.

### Control restore from backup

1. Keep nodes serving; do not reset them.
2. Restore into staging and verify database, artifact, and key manifests.
3. Enter recovery fence and collect node high-water marks.
4. Reconcile authorization and telemetry gaps with explicit operator decisions.
5. Publish a higher recovery revision, verify convergence, then create a fresh backup.

## 15. Required Acceptance Tests

### Publication and normal apply

1. A configuration mutation atomically commits logical state, one higher immutable revision, every
   affected target, rollout gates, audit event, and idempotent response.
2. Failure while compiling/writing any target commits none of those rows and leaves only removable
   orphan artifacts.
3. An unaffected node receives `204` even when the network high-water mark is higher; an affected
   node receives eligible targets in order.
4. A valid revision records received, validated, and applied states, survives restart, and becomes
   advertised only after an external probe.
5. Duplicate fetch/report/request delivery causes no extra Xray restart, revision, credential, audit
   mutation, or telemetry count.

### Validation and automatic rollback

6. Wrong node ID, bad signature, unknown required schema, unsafe local policy, invalid Xray JSON, and
   binary checksum mismatch are rejected without changing the active config.
7. Injected failures at every activation boundary either leave the predecessor active or restore it
   from a verified backup after restart.
8. Startup, listener, smoke-check, and stabilization failures report `rolledBack` with the correct
   predecessor; a failed predecessor restore enters `recovery_required` without retry loops.
9. Re-delivering a rolled-back candidate returns its terminal result and never reapplies it.

### Operator rollback and staged rollout

10. Operator rollback creates a higher newly signed revision and preserves every historical row.
11. Rolling back to a revision predating a user revocation does not restore that user or credential.
12. A standard multi-node rollout holds later waves until canary stabilization; canary failure pauses
    them while already healthy nodes continue serving.
13. Node-scoped rollback changes only selected nodes. Fleet rollback reports partial until every
    selected online node converges or is explicitly removed from scope.
14. A metadata-only, corrupt, incompatible, or secret-incomplete source revision is refused before
    rollback publication.

### Partitions, revocation, and local authority

15. With Control Service offline, nodes continue the last applied config, Connect uses an unexpired
    cached bundle, and queued telemetry survives service and machine restart.
16. Provider pause/removal stops local sharing and mappings without Control connectivity, and remote
    desired state cannot override it.
17. During a security-urgent disable with one offline node, refresh fails immediately, new bundles
    omit the user/node, online nodes remove access, and Control visibly reports the offline node's
    revocation pending rather than false convergence.
18. Relay failure affects relay-backed endpoints only; direct nodes remain selectable. Lost endpoint
    verification removes advertisement without rolling back valid config.

### Disaster recovery and retention

19. Restoring a database behind a node's highest seen revision enters the recovery fence, never
    serves the older target, and publishes recovery above the observed high-water mark.
20. Stale-restore telemetry replays retained acknowledged events exactly once; an unrecoverable gap
    requires audited cursor advancement and is shown as unknown data.
21. Missing/corrupt revision artifacts are never regenerated under the same revision. Key loss cannot
    install an unsigned replacement trust root.
22. Revision garbage collection preserves all desired, applied, predecessor, unresolved, bundle,
    rollback, and recovery pins; retained artifacts pass digest verification.
23. Daily backup restore reproduces network identity, signing trust, revision counter, current
    authorization, artifacts, and aggregate telemetry, then passes a full publish/apply/probe cycle.
24. macOS service kill/restart tests at each database, fsync, rename, Xray restart, result-report,
    proxy-change, and telemetry-ack boundary preserve all safety invariants.
