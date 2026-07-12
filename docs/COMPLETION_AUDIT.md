# Product Completion Audit

Status: Stage 6 complete; Stage 7 implementation in progress and signed-candidate acceptance pending.

This document prevents implementation milestones from being mistaken for product acceptance. A
requirement is complete only when the production path and a scope-matched test prove it. Signed
package and real-platform claims additionally require the immutable Stage 7 evidence matrix.

## Current Decision

The backend and operating architecture have completed their local implementation gates, but the
product is not yet an accepted release. Stage 6 closes the previously identified local
implementation gaps: reset and rollback operations, provider policy, installation identity binding,
packaged privileged setup,
automatic Relay provisioning/rotation, exact Relay quota enforcement, telemetry replay evidence,
and fail-closed release aggregation. Stage 7 remains pending until signed artifacts run the complete
direct-plus-relay matrix on clean supported machines.

Stage 7 implementation now includes installed Connect/Node Host headless control, explicit Node Host
preserve/purge uninstall, non-privileged package validation, and a fail-closed Connect release-lab
coordinator for online, offline, independent direct/relay failure, and logout proof. These are
implementation assets only until their candidate-bound proofs run on the required signed packages.
Connect state-preserving and failed-update rollback remain an implementation gap: bundle-cache and
system-proxy recovery do not constitute transactional application-package rollback. Those lifecycle
rows must remain `incomplete` until a real updater/helper preserves the installed predecessor and
restores it after an injected package-switch failure on macOS and Windows.

## Functional Requirement Matrix

| Requirement | State | Evidence still required |
| --- | --- | --- |
| ACC-001 | complete | Independent two-device revoke is covered by Control integration tests. |
| ACC-002 | partial | Exercise native Keychain and Credential Manager from signed packages. |
| ACC-003 | complete | Reset tokens are hashed, bounded, expiring, single-use, replay-safe, and audited. |
| ACC-004 | partial | Stage 7 must prove removal on two installed Node Hosts and rejection of both old credentials. |
| ACC-005 | partial | Frontend must keep manual VLESS import under compatibility only. |
| NOD-001 | complete | Enrollment and management are outbound HTTPS plus authenticated local IPC only. |
| NOD-002 | complete | Immutable fingerprint binding points outside copyable state; state-only copies fail closed. |
| NOD-003 | complete | Closed signed desired state exposes no arbitrary command surface. |
| NOD-004 | complete | Validate, atomic activation, immutable predecessors, health rollback, and operator rollback exist. |
| NOD-005 | complete | Last-known-good state restores before Control synchronization. |
| NOD-006 | complete | Local pause withdraws admission, mapping, and Relay without Control. |
| NOD-007 | complete | UTC schedule, monthly cap, session limit, and aggregate bandwidth limit are durable and enforced. |
| NOD-008 | complete | Setup evidence remains distinct through external protocol verification. |
| NET-001 | complete | Bundle publication requires the exact revision's protocol canary. |
| NET-002 | complete | Automatic mapping and finite explicit public endpoint/forwarding input are supported. |
| NET-003 | complete | Pause removes owned mappings without uninstalling enrollment. |
| NET-004 | complete | Relay forwards bounded opaque TCP; automatic grants require registered node acknowledgement. |
| NET-005 | complete | Cloudflare is absent from the member data path. |
| CFG-001 | complete | Stable typed identifiers own every durable relationship. |
| CFG-002 | complete | Every user-node assignment owns a distinct VLESS UUID. |
| CFG-003 | complete | Desired revisions are immutable, monotonic, signed, and idempotent. |
| CFG-004 | complete | Latest failure summary and stable failure code are exposed. |
| CFG-005 | complete | Exact node and explicit affected-cohort rollback publish new monotonic revisions. |
| CLI-001 | partial | Backend contract exists; the separately owned frontend and signed package journey remain. |
| CLI-002 | complete | Signature, device binding, digest, lifetime, and HPKE are verified before cache. |
| CLI-003 | complete | Manual, latency, and pinned fallback selection are implemented. |
| CLI-004 | partial | Non-empty cache primitives exist; Stage 7 must prove the installed offline data path. |
| CLI-005 | complete | HTTP and SOCKS listeners bind only to loopback. |
| CLI-006 | complete | Start, stop, recovery, and system-proxy restoration are idempotent. |
| TEL-001 | complete | Ordered bounded local spool persists before upload. |
| TEL-002 | complete | Exact duplicate, overlap, gap, stale, signed HTTP, and concurrent ingestion are tested. |
| TEL-003 | complete | Two-node acknowledged sequences reconcile exactly to per-node and per-user aggregates. |
| TEL-004 | complete | Detailed metadata is optional, bounded, redacted, and retained by policy. |
| TEL-005 | complete | Revision failure, operator rollback, enrollment, account, assignment, and revocation are audited. |

## Remaining Product Proof

1. The separately owned frontend must consume the privileged Node Host setup, policy, manual
   endpoint, pause/resume, and unpair commands without moving secrets into renderer state.
2. Signed Connect packages must prove native credential storage and a non-empty cached bundle across
   restart, Control outage, expiry, logout, and proxy restoration.
3. Two installed Node Hosts must converge account disable/removal, one direct and one Relay path
   must remain independently selectable, and the old credentials must fail end to end.
4. Apple Silicon, Intel macOS, and Windows package lifecycle evidence must come from clean matching
   hosts and exact release artifact digests.

## Release Gate State

The local release implementation now has complete component gates, previous-schema migration tests,
actual-package lifecycle recorders, nested executable signature checks, manifest/package digest
binding, strict `accepted`/`rejected`/`incomplete` aggregation, state-preserving installer rollback,
and publish-time evidence replay. Validation builds remain unconditionally `incomplete` by design.

The remaining release blockers are external evidence, not permission to weaken the gate:

- production controller/manifest trust roots and signing identities;
- Apple signing, notarization, stapling, and clean arm64/x86_64 package hosts;
- Windows Authenticode credentials and a clean x86_64 package host;
- a disposable two-node direct-plus-relay topology; and
- every required Stage 7 lifecycle scenario recorded as passed for the same immutable candidate.

## Authoritative Naming

- `Private Network`, `Private Network Node`, and `_privnetnode` are the product/package names.
- Historical `Reality Console`, `Reality Node`, and internal compatibility labels are not user-facing
  product terminology.
- Stage 6 is one product-sized implementation commit; Stage 7 is a separate signed-candidate
  acceptance stage and cannot be completed by unsigned or simulated artifacts.
