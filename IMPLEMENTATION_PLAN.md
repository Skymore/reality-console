# Private Network Delivery Plan

Work is grouped into independently usable product stages, not endpoint-sized commits. Each stage
closes its complete backend behavior, migrations, tests, and authoritative documentation before a
single stage commit. Existing unrelated worktree changes are never folded into a stage.

## Stage 1: Product, Architecture, And Trust Foundation

Status: complete.

Deliverables:

- product requirements, release acceptance, component ownership, and non-goals;
- versioned shared protocol, stable IDs, errors, cryptographic transcripts, and redaction rules;
- Control Service and Node Host persistence foundations with migration validation;
- security, privacy, rollout, recovery, Node Host, and Connect architecture documents.

## Stage 2: Control Plane And Data-Plane Convergence

Status: complete.

Deliverables:

- secure node enrollment, signed heartbeat/status, immutable desired state, and apply journals;
- pinned Xray validation, activation, admission gate, rollback, and resilient outbound sync;
- consent-gated PCP/NAT-PMP/UPnP mapping and controller-owned external TCP preflight;
- member accounts, atomic multi-node assignments, per-node credentials, exact applied evidence,
  removal convergence, reconciliation, and failure recovery.

## Stage 3: One-Action Contributed Node Onboarding

Status: complete.

Deliverables:

- idempotent preconfigured node invitations returned as one-time setup codes and fragment links;
- provider confirmation preview without exposing the bearer secret to ordinary status surfaces;
- installer-owned Xray/runtime inputs, durable consent receipt, node-local REALITY identity, and
  versioned enrollment carrying only public material;
- atomic enrollment, activation, and initial revision publication with exact retry recovery;
- native background-service registration and conservative setup progress from enrollment through
  protocol verification;
- a separate Node Host desktop backend contract ready for the frontend and signed package stages.

Stage acceptance requires a real Control Service plus Node Host integration test proving:
invitation creation -> code/link input -> runtime verification -> v2 enrollment -> automatic
activation -> initial desired-state fetch and validation. `loaded`, `enrolled`, TCP reachable, and
protocol verified remain distinct states.

## Stage 4: Member Account And Connect Experience

Status: complete.

Deliverables:

- member activation, device enrollment, refresh rotation, logout, reset, and independent revoke;
- encrypted, signed, offline-valid multi-node bundles generated only from applied credentials and
  protocol-verified endpoints;
- Connect activation/login, OS credential storage, atomic bundle cache, automatic/manual/fallback
  node selection, and existing Xray supervisor integration;
- cross-node account disable/delete and automatic client node-list synchronization.

## Stage 5: Packaging, Operations, And Release

Status: foundation complete; product and release acceptance are incomplete.

This stage established the production canary, telemetry, relay data path, system-proxy recovery,
backup/restore, package definitions, and signed-manifest primitives. A requirement-by-requirement
audit found that these foundations do not yet form an acceptable release: provider policy,
packaged Node Host setup, controller-driven recovery operations, complete evidence aggregation,
and real package lifecycle gates remain open. See `docs/COMPLETION_AUDIT.md`.

Deliverables:

- dedicated signed Node Host application/package and macOS system service, followed by supported
  Windows/Linux service targets;
- protocol-aware VLESS + REALITY canary, relay fallback, telemetry aggregation, retention, and
  redacted support bundles;
- credential/runtime rotation, side-by-side upgrades, rollback, backup/restore, and uninstall;
- macOS/Windows packaging plus direct/relay/offline/sleep/restart/upgrade end-to-end release matrix.

## Stage 6: Core Requirement Closure

Status: complete.

This is one product-sized implementation stage and one final stage commit. It is not split into
endpoint-sized commits.

Deliverables:

- provider-local pause, schedule, monthly transfer cap, concurrent-session/bandwidth policy, and
  manual direct-endpoint configuration, enforced without Control Service availability;
- a packaged Node Host setup confirmation path that crosses the macOS privilege boundary without
  putting invitation or identity secrets in renderer state, process arguments, or world-readable
  files;
- controller-issued relay assignments and rotation/revocation convergence so a provider never
  imports relay JSON, certificates, route tokens, ports, or hashes;
- single-use account reset tokens, explicit node/cohort rollback operations, failed-revision
  visibility, and complete recovery/audit events;
- anti-clone installation binding outside the copyable Node Host state directory;
- missing multi-device, cross-node disable, telemetry reconciliation, non-empty offline bundle,
  direct/relay topology, and bad-revision end-to-end tests;
- full component CI gates, real package lifecycle jobs, installed-binary signature checks, release
  evidence aggregation, and a fail-closed publish gate.

Stage acceptance is backed by the local component suites, strict lint and documentation builds,
downstream desktop builds, package-state rollback tests, and fail-closed release evidence tests.
Signed artifact and real-platform evidence intentionally remain outside this stage.

## Stage 7: Signed Candidate Acceptance

Status: in progress; signed-candidate evidence pending.

One immutable candidate must satisfy every row in `docs/RELEASE_ACCEPTANCE.md` on the required real
platforms. This stage supplies production trust roots and signing identities, runs the direct and
relay topology, installs signed artifacts on clean macOS/Windows hosts, records the complete
evidence matrix, and publishes only an `accepted` candidate. Unsigned or simulated artifacts cannot
complete this stage.

Current implementation work adds non-privileged validation inspection, clean package payload
enforcement, explicit Node Host preserve/purge uninstall, authenticated installed-service headless
control, installed Connect headless control on macOS and Windows, candidate-bound direct/relay/
offline/logout scenario coordination, and actual-package lifecycle coverage. Acceptance remains
open until the complete Connect and Node Host scenario matrix, including sleep and upgrade/rollback,
runs on signed Apple Silicon, Intel macOS, and Windows artifacts.

## Engineering Gates

- Control plane and data plane remain independent; an outage does not stop last-known-good service.
- Node Host receives declarative desired state and never arbitrary shell commands.
- Every secret has a named owner, storage location, rotation path, and redaction test.
- Every retryable write has an idempotency key or monotonic sequence.
- Every configuration mutation validates, persists atomically, health-checks, and can roll back.
- UI-facing state never claims more than signed or locally proven evidence supports.
- Network and filesystem work is bounded and remains off desktop UI threads.
- Each stage passes strict formatting, tests, Clippy, Rustdoc, downstream builds, and diff checks.
