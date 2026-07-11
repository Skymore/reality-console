use crate::config::{validate_network_name, ConfigError};
use crate::desired::{
    build_signed_desired_state, controller_signing_key_id, verify_stored_desired_state,
    DesiredStateConfigurationDraft, DesiredStateError, StoredDesiredState,
    SUPPORTED_DESIRED_STATE_SCHEMA_VERSIONS,
};
use crate::identity::{set_owner_only, ControllerIdentity, IdentityError};
use crate::probe::{
    ProbeSchedule, TcpProbeCompletion, TcpProbeJob, TcpProbeLoopOptions, TcpProbeResult,
};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use control_protocol::account::{
    AccountMetadata, AccountNodeAssignment, AccountNodeAssignmentStatus,
    AccountNodeProvisioningState, AccountStatus, AccountSummary, CreateAccountRequest,
    ReplaceAccountNodesRequest,
};
use control_protocol::crypto::{Ed25519PublicKey, Sha256Digest};
use control_protocol::enrollment::{
    enrollment_request_transcript, enrollment_response_transcript, verify_enrollment_proof,
    EnrollmentCryptoError, EnrollmentInvitation,
};
use control_protocol::id::{
    AssignmentId, ControllerInstanceId, CredentialId, EndpointId, NetworkId, NodeId,
    NodeInvitationId, NodeKeyId, Revision, SequenceNumber, SigningKeyId, Timestamp, UserId,
};
use control_protocol::idempotency::IdempotencyKey;
use control_protocol::node::{
    CreateNodeInvitationRequest, CreateNodeInvitationResponse, DesiredUser, EndpointCandidate,
    EndpointMode, EndpointReadiness, EnrollNodeRequest, EnrollNodeResponse, NodeAuthenticationMode,
    NodeCapability, NodeCredential, NodeEndpointStatus, NodeHeartbeat, NodeHeartbeatStatus,
    NodeInitialConfiguration, NodeLifecycleState, PairingPurpose, RevisionResult,
    RevisionResultState, SignedDesiredState, SignedNodeHeartbeatStatus,
};
use control_protocol::node_status::node_heartbeat_status_transcript;
use control_protocol::request_auth::{
    verify_node_request_signature, NodeRequestAuthHeaders, NodeRequestSigningInput,
};
use control_protocol::secret::Secret;
use control_protocol::validation::ProtocolValidationError;
use fs2::FileExt;
use rand_core::{OsRng, RngCore as _};
use rusqlite::{params, Connection, OpenFlags, OptionalExtension, TransactionBehavior};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::fs::{self, File, OpenOptions};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};
use subtle::ConstantTimeEq as _;
use thiserror::Error;
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

pub const SCHEMA_VERSION: i64 = 11;
const APPLICATION_ID: i64 = 0x5243_4F4E;
const INVITATION_SECRET_BYTES: usize = 32;
const NODE_CREDENTIAL_LIFETIME_DAYS: i64 = 90;
const IDEMPOTENCY_LIFETIME_SECONDS: i64 = 24 * 60 * 60;
const BOOTSTRAP_ADMIN_PRINCIPAL: &str = "bootstrap-admin";
const CREATE_ACCOUNT_ROUTE_ID: &str = "v1.admin.accounts.create";
const NODE_INVITATION_SECRET_DOMAIN: &[u8] = b"private-network/node-invitation-secret/v1\0";
const HTTP_CREATED_STATUS: i64 = 201;
const NODE_REQUEST_CLOCK_SKEW_SECONDS: i64 = 5 * 60;

const MIGRATION_1_SQL: &str = r"
CREATE TABLE networks (
    network_id TEXT PRIMARY KEY,
    display_name TEXT NOT NULL CHECK(length(display_name) BETWEEN 1 AND 128),
    status TEXT NOT NULL CHECK(status IN ('active', 'recovery', 'disabled')),
    last_revision INTEGER NOT NULL DEFAULT 0 CHECK(last_revision >= 0),
    controller_epoch TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
) STRICT;

CREATE UNIQUE INDEX networks_singleton ON networks ((1));
";

const MIGRATION_2_SQL: &str = r"
CREATE TABLE node_invitations (
    invitation_id TEXT PRIMARY KEY,
    network_id TEXT NOT NULL REFERENCES networks(network_id) ON DELETE CASCADE,
    purpose TEXT NOT NULL CHECK(purpose = 'node-enrollment'),
    intended_display_name TEXT NOT NULL CHECK(length(intended_display_name) BETWEEN 1 AND 128),
    secret_verifier BLOB NOT NULL UNIQUE CHECK(length(secret_verifier) = 32),
    controller_origin TEXT NOT NULL,
    controller_fingerprint TEXT NOT NULL,
    expires_at INTEGER NOT NULL,
    consumed_at INTEGER,
    consumed_node_id TEXT,
    cancelled_at INTEGER,
    created_at INTEGER NOT NULL,
    CHECK(consumed_at IS NULL OR consumed_node_id IS NOT NULL),
    CHECK(NOT (consumed_at IS NOT NULL AND cancelled_at IS NOT NULL))
) STRICT;

CREATE INDEX node_invitations_expiry ON node_invitations(expires_at)
    WHERE consumed_at IS NULL AND cancelled_at IS NULL;

CREATE TABLE nodes (
    node_id TEXT PRIMARY KEY,
    network_id TEXT NOT NULL REFERENCES networks(network_id) ON DELETE CASCADE,
    display_name TEXT NOT NULL CHECK(length(display_name) BETWEEN 1 AND 128),
    status TEXT NOT NULL CHECK(status IN ('pending', 'active', 'disabled', 'revoked')),
    agent_version TEXT NOT NULL,
    platform TEXT NOT NULL,
    capabilities_json TEXT NOT NULL CHECK(json_valid(capabilities_json)),
    identity_public_key TEXT NOT NULL UNIQUE,
    encryption_public_key TEXT NOT NULL UNIQUE,
    consent_policy_version TEXT NOT NULL,
    consent_host_owner INTEGER NOT NULL CHECK(consent_host_owner IN (0, 1)),
    consent_exit_ip INTEGER NOT NULL CHECK(consent_exit_ip IN (0, 1)),
    consent_accepted_at INTEGER NOT NULL,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    UNIQUE(network_id, node_id)
) STRICT;

CREATE TABLE node_auth_credentials (
    network_id TEXT NOT NULL REFERENCES networks(network_id) ON DELETE CASCADE,
    node_credential_id TEXT NOT NULL,
    node_id TEXT NOT NULL,
    identity_public_key TEXT NOT NULL,
    auth_mode TEXT NOT NULL CHECK(auth_mode = 'signedRequest'),
    not_before INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    revoked_at INTEGER,
    rotation_parent_id TEXT,
    created_at INTEGER NOT NULL,
    PRIMARY KEY(network_id, node_credential_id),
    UNIQUE(network_id, node_id, identity_public_key),
    FOREIGN KEY(network_id, node_id) REFERENCES nodes(network_id, node_id) ON DELETE CASCADE,
    FOREIGN KEY(network_id, rotation_parent_id)
        REFERENCES node_auth_credentials(network_id, node_credential_id)
) STRICT;

CREATE TABLE audit_events (
    event_id INTEGER PRIMARY KEY AUTOINCREMENT,
    network_id TEXT REFERENCES networks(network_id) ON DELETE SET NULL,
    actor_type TEXT NOT NULL,
    actor_id TEXT,
    event_type TEXT NOT NULL,
    target_type TEXT NOT NULL,
    target_id TEXT,
    outcome TEXT NOT NULL CHECK(outcome IN ('success', 'rejected', 'failure')),
    details_json TEXT NOT NULL CHECK(json_valid(details_json)),
    created_at INTEGER NOT NULL
) STRICT;

CREATE INDEX audit_events_created_at ON audit_events(created_at);
";

const MIGRATION_3_SQL: &str = r"
ALTER TABLE nodes ADD COLUMN xray_version TEXT;
ALTER TABLE nodes ADD COLUMN runtime_state TEXT;
ALTER TABLE nodes ADD COLUMN provider_paused INTEGER NOT NULL DEFAULT 0
    CHECK(provider_paused IN (0, 1));
ALTER TABLE nodes ADD COLUMN last_seen_at INTEGER;
ALTER TABLE nodes ADD COLUMN desired_revision INTEGER CHECK(desired_revision > 0);
ALTER TABLE nodes ADD COLUMN received_revision INTEGER CHECK(received_revision > 0);
ALTER TABLE nodes ADD COLUMN validated_revision INTEGER CHECK(validated_revision > 0);
ALTER TABLE nodes ADD COLUMN applied_revision INTEGER CHECK(applied_revision > 0);
ALTER TABLE nodes ADD COLUMN telemetry_cursor INTEGER NOT NULL DEFAULT 0
    CHECK(telemetry_cursor >= 0);

CREATE INDEX nodes_last_seen_at ON nodes(last_seen_at);
CREATE INDEX nodes_status_last_seen ON nodes(status, last_seen_at);

CREATE TABLE node_request_nonces (
    network_id TEXT NOT NULL,
    node_id TEXT NOT NULL,
    node_credential_id TEXT NOT NULL,
    nonce_hash BLOB NOT NULL CHECK(length(nonce_hash) = 32),
    request_timestamp INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    created_at INTEGER NOT NULL,
    PRIMARY KEY(network_id, node_id, node_credential_id, nonce_hash),
    FOREIGN KEY(network_id, node_id)
        REFERENCES nodes(network_id, node_id) ON DELETE CASCADE,
    FOREIGN KEY(network_id, node_credential_id)
        REFERENCES node_auth_credentials(network_id, node_credential_id) ON DELETE CASCADE
) STRICT, WITHOUT ROWID;

CREATE INDEX node_request_nonces_expiry ON node_request_nonces(expires_at);

CREATE TABLE node_reported_endpoints (
    network_id TEXT NOT NULL,
    node_id TEXT NOT NULL,
    mode TEXT NOT NULL CHECK(mode IN ('direct', 'relay')),
    address TEXT NOT NULL CHECK(length(address) BETWEEN 1 AND 253),
    port INTEGER NOT NULL CHECK(port BETWEEN 1 AND 65535),
    status TEXT NOT NULL CHECK(status IN ('pending', 'verified', 'failed', 'withdrawn')),
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    PRIMARY KEY(network_id, node_id, mode, address, port),
    FOREIGN KEY(network_id, node_id)
        REFERENCES nodes(network_id, node_id) ON DELETE CASCADE
) STRICT, WITHOUT ROWID;
";

const MIGRATION_4_SQL: &str = r"
ALTER TABLE nodes ADD COLUMN reported_desired_revision INTEGER
    CHECK(reported_desired_revision > 0);

-- Version 3 accepted heartbeat cursors as authority. They cannot be imported
-- into the signed revision journal, so discard them during the trust upgrade.
UPDATE nodes
SET desired_revision = NULL,
    received_revision = NULL,
    validated_revision = NULL,
    applied_revision = NULL;

CREATE TABLE config_revisions (
    network_id TEXT NOT NULL,
    revision INTEGER NOT NULL CHECK(revision > 0),
    parent_revision INTEGER,
    schema_version INTEGER NOT NULL CHECK(schema_version = 1),
    node_id TEXT NOT NULL,
    artifact_json TEXT NOT NULL
        CHECK(json_valid(artifact_json) AND length(artifact_json) BETWEEN 2 AND 1048576),
    artifact_sha256 TEXT NOT NULL
        CHECK(length(artifact_sha256) = 71
            AND substr(artifact_sha256, 1, 7) = 'sha256:'
            AND substr(artifact_sha256, 8) NOT GLOB '*[^0-9a-f]*'),
    transcript_sha256 TEXT NOT NULL
        CHECK(length(transcript_sha256) = 71
            AND substr(transcript_sha256, 1, 7) = 'sha256:'
            AND substr(transcript_sha256, 8) NOT GLOB '*[^0-9a-f]*'),
    signature TEXT NOT NULL CHECK(length(signature) = 86),
    signing_key_id TEXT NOT NULL CHECK(length(signing_key_id) = 36),
    controller_instance_id TEXT NOT NULL CHECK(length(controller_instance_id) = 36),
    created_at INTEGER NOT NULL,
    PRIMARY KEY(network_id, revision),
    UNIQUE(network_id, revision, node_id),
    CHECK((revision = 1 AND parent_revision IS NULL)
        OR (revision > 1 AND parent_revision = revision - 1)),
    FOREIGN KEY(network_id) REFERENCES networks(network_id) ON DELETE CASCADE,
    FOREIGN KEY(network_id, node_id) REFERENCES nodes(network_id, node_id),
    FOREIGN KEY(network_id, parent_revision)
        REFERENCES config_revisions(network_id, revision)
) STRICT, WITHOUT ROWID;

CREATE TABLE node_revision_targets (
    network_id TEXT NOT NULL,
    node_id TEXT NOT NULL,
    revision INTEGER NOT NULL CHECK(revision > 0),
    created_at INTEGER NOT NULL,
    PRIMARY KEY(network_id, node_id, revision),
    UNIQUE(network_id, revision),
    FOREIGN KEY(network_id, revision, node_id)
        REFERENCES config_revisions(network_id, revision, node_id),
    FOREIGN KEY(network_id, node_id)
        REFERENCES nodes(network_id, node_id)
) STRICT, WITHOUT ROWID;

CREATE INDEX node_revision_targets_latest
    ON node_revision_targets(network_id, node_id, revision DESC);

CREATE TABLE node_revision_results (
    network_id TEXT NOT NULL,
    node_id TEXT NOT NULL,
    revision INTEGER NOT NULL CHECK(revision > 0),
    state TEXT NOT NULL
        CHECK(state IN ('received', 'validated', 'applied', 'rejected', 'rolledBack')),
    state_rank INTEGER NOT NULL CHECK(
        (state = 'received' AND state_rank = 10)
        OR (state = 'validated' AND state_rank = 20)
        OR (state IN ('applied', 'rejected', 'rolledBack') AND state_rank = 30)
    ),
    result_json TEXT NOT NULL
        CHECK(json_valid(result_json) AND length(result_json) BETWEEN 2 AND 8192),
    config_digest TEXT CHECK(config_digest IS NULL OR (
        length(config_digest) = 71
        AND substr(config_digest, 1, 7) = 'sha256:'
        AND substr(config_digest, 8) NOT GLOB '*[^0-9a-f]*'
    )),
    rollback_revision INTEGER CHECK(
        rollback_revision IS NULL
        OR (rollback_revision > 0 AND rollback_revision < revision)
    ),
    created_at INTEGER NOT NULL,
    PRIMARY KEY(network_id, node_id, revision, state),
    FOREIGN KEY(network_id, node_id, revision)
        REFERENCES node_revision_targets(network_id, node_id, revision)
) STRICT, WITHOUT ROWID;

CREATE INDEX node_revision_results_latest
    ON node_revision_results(network_id, node_id, revision, state_rank DESC);

CREATE TRIGGER config_revisions_no_update
BEFORE UPDATE ON config_revisions
BEGIN
    SELECT RAISE(ABORT, 'config revisions are immutable');
END;

CREATE TRIGGER config_revisions_no_delete
BEFORE DELETE ON config_revisions
BEGIN
    SELECT RAISE(ABORT, 'config revisions are immutable');
END;

CREATE TRIGGER node_revision_targets_no_update
BEFORE UPDATE ON node_revision_targets
BEGIN
    SELECT RAISE(ABORT, 'node revision targets are immutable');
END;

CREATE TRIGGER node_revision_targets_no_delete
BEFORE DELETE ON node_revision_targets
BEGIN
    SELECT RAISE(ABORT, 'node revision targets are immutable');
END;

CREATE TRIGGER node_revision_results_no_update
BEFORE UPDATE ON node_revision_results
BEGIN
    SELECT RAISE(ABORT, 'node revision results are immutable');
END;

CREATE TRIGGER node_revision_results_no_delete
BEFORE DELETE ON node_revision_results
BEGIN
    SELECT RAISE(ABORT, 'node revision results are immutable');
END;
";

const MIGRATION_5_SQL: &str = r"
PRAGMA defer_foreign_keys = ON;

DROP TRIGGER config_revisions_no_update;
DROP TRIGGER config_revisions_no_delete;
DROP TRIGGER node_revision_targets_no_update;
DROP TRIGGER node_revision_targets_no_delete;
DROP TRIGGER node_revision_results_no_update;
DROP TRIGGER node_revision_results_no_delete;
DROP INDEX node_revision_targets_latest;
DROP INDEX node_revision_results_latest;

ALTER TABLE node_revision_results RENAME TO node_revision_results_v4;
ALTER TABLE node_revision_targets RENAME TO node_revision_targets_v4;
ALTER TABLE config_revisions RENAME TO config_revisions_v4;

CREATE TABLE config_revisions (
    network_id TEXT NOT NULL,
    revision INTEGER NOT NULL CHECK(revision > 0),
    parent_revision INTEGER,
    schema_version INTEGER NOT NULL CHECK(schema_version IN (1, 2)),
    node_id TEXT NOT NULL,
    artifact_json TEXT NOT NULL
        CHECK(json_valid(artifact_json) AND length(artifact_json) BETWEEN 2 AND 1048576),
    artifact_sha256 TEXT NOT NULL
        CHECK(length(artifact_sha256) = 71
            AND substr(artifact_sha256, 1, 7) = 'sha256:'
            AND substr(artifact_sha256, 8) NOT GLOB '*[^0-9a-f]*'),
    transcript_sha256 TEXT NOT NULL
        CHECK(length(transcript_sha256) = 71
            AND substr(transcript_sha256, 1, 7) = 'sha256:'
            AND substr(transcript_sha256, 8) NOT GLOB '*[^0-9a-f]*'),
    signature TEXT NOT NULL CHECK(length(signature) = 86),
    signing_key_id TEXT NOT NULL CHECK(length(signing_key_id) = 36),
    controller_instance_id TEXT NOT NULL CHECK(length(controller_instance_id) = 36),
    created_at INTEGER NOT NULL,
    PRIMARY KEY(network_id, revision),
    UNIQUE(network_id, revision, node_id),
    CHECK((revision = 1 AND parent_revision IS NULL)
        OR (revision > 1 AND parent_revision = revision - 1)),
    FOREIGN KEY(network_id) REFERENCES networks(network_id) ON DELETE CASCADE,
    FOREIGN KEY(network_id, node_id) REFERENCES nodes(network_id, node_id),
    FOREIGN KEY(network_id, parent_revision)
        REFERENCES config_revisions(network_id, revision)
) STRICT, WITHOUT ROWID;

CREATE TABLE node_revision_targets (
    network_id TEXT NOT NULL,
    node_id TEXT NOT NULL,
    revision INTEGER NOT NULL CHECK(revision > 0),
    created_at INTEGER NOT NULL,
    PRIMARY KEY(network_id, node_id, revision),
    UNIQUE(network_id, revision),
    FOREIGN KEY(network_id, revision, node_id)
        REFERENCES config_revisions(network_id, revision, node_id),
    FOREIGN KEY(network_id, node_id)
        REFERENCES nodes(network_id, node_id)
) STRICT, WITHOUT ROWID;

CREATE TABLE node_revision_results (
    network_id TEXT NOT NULL,
    node_id TEXT NOT NULL,
    revision INTEGER NOT NULL CHECK(revision > 0),
    state TEXT NOT NULL
        CHECK(state IN ('received', 'validated', 'applied', 'rejected', 'rolledBack')),
    state_rank INTEGER NOT NULL CHECK(
        (state = 'received' AND state_rank = 10)
        OR (state = 'validated' AND state_rank = 20)
        OR (state IN ('applied', 'rejected', 'rolledBack') AND state_rank = 30)
    ),
    result_json TEXT NOT NULL
        CHECK(json_valid(result_json) AND length(result_json) BETWEEN 2 AND 8192),
    config_digest TEXT CHECK(config_digest IS NULL OR (
        length(config_digest) = 71
        AND substr(config_digest, 1, 7) = 'sha256:'
        AND substr(config_digest, 8) NOT GLOB '*[^0-9a-f]*'
    )),
    rollback_revision INTEGER CHECK(
        rollback_revision IS NULL
        OR (rollback_revision > 0 AND rollback_revision < revision)
    ),
    created_at INTEGER NOT NULL,
    PRIMARY KEY(network_id, node_id, revision, state),
    FOREIGN KEY(network_id, node_id, revision)
        REFERENCES node_revision_targets(network_id, node_id, revision)
) STRICT, WITHOUT ROWID;

INSERT INTO config_revisions SELECT * FROM config_revisions_v4;
INSERT INTO node_revision_targets SELECT * FROM node_revision_targets_v4;
INSERT INTO node_revision_results SELECT * FROM node_revision_results_v4;

DROP TABLE node_revision_results_v4;
DROP TABLE node_revision_targets_v4;
DROP TABLE config_revisions_v4;

CREATE INDEX node_revision_targets_latest
    ON node_revision_targets(network_id, node_id, revision DESC);
CREATE INDEX node_revision_results_latest
    ON node_revision_results(network_id, node_id, revision, state_rank DESC);

CREATE TRIGGER config_revisions_no_update
BEFORE UPDATE ON config_revisions
BEGIN
    SELECT RAISE(ABORT, 'config revisions are immutable');
END;

CREATE TRIGGER config_revisions_no_delete
BEFORE DELETE ON config_revisions
BEGIN
    SELECT RAISE(ABORT, 'config revisions are immutable');
END;

CREATE TRIGGER node_revision_targets_no_update
BEFORE UPDATE ON node_revision_targets
BEGIN
    SELECT RAISE(ABORT, 'node revision targets are immutable');
END;

CREATE TRIGGER node_revision_targets_no_delete
BEFORE DELETE ON node_revision_targets
BEGIN
    SELECT RAISE(ABORT, 'node revision targets are immutable');
END;

CREATE TRIGGER node_revision_results_no_update
BEFORE UPDATE ON node_revision_results
BEGIN
    SELECT RAISE(ABORT, 'node revision results are immutable');
END;

CREATE TRIGGER node_revision_results_no_delete
BEFORE DELETE ON node_revision_results
BEGIN
    SELECT RAISE(ABORT, 'node revision results are immutable');
END;
";

const MIGRATION_6_SQL: &str = r"
-- Version 3 allowed a node heartbeat to assert endpoint verification. Those
-- rows are not controller evidence and must not cross the trust upgrade.
DROP TABLE node_reported_endpoints;

ALTER TABLE nodes ADD COLUMN last_heartbeat_generation INTEGER NOT NULL DEFAULT 0
    CHECK(last_heartbeat_generation >= 0);

ALTER TABLE nodes ADD COLUMN last_heartbeat_sha256 BLOB
    CHECK(last_heartbeat_sha256 IS NULL OR length(last_heartbeat_sha256) = 32);

CREATE TABLE node_endpoint_candidates (
    network_id TEXT NOT NULL,
    node_id TEXT NOT NULL,
    endpoint_id TEXT NOT NULL CHECK(length(endpoint_id) = 36),
    mode TEXT NOT NULL CHECK(mode IN ('direct', 'relay')),
    source TEXT NOT NULL CHECK(source IN ('manual', 'pcp', 'natPmp', 'upnp', 'relay')),
    address TEXT NOT NULL CHECK(length(address) BETWEEN 1 AND 253),
    port INTEGER NOT NULL CHECK(port BETWEEN 1 AND 65535),
    applied_revision INTEGER NOT NULL CHECK(applied_revision > 0),
    observed_at INTEGER NOT NULL,
    expires_at INTEGER,
    last_report_generation INTEGER NOT NULL CHECK(last_report_generation > 0),
    first_reported_at INTEGER NOT NULL,
    last_reported_at INTEGER NOT NULL,
    withdrawn_at INTEGER,
    PRIMARY KEY(network_id, node_id, endpoint_id),
    CHECK(
        (mode = 'direct' AND source IN ('manual', 'pcp', 'natPmp', 'upnp'))
        OR (mode = 'relay' AND source = 'relay')
    ),
    CHECK(source = 'manual' OR expires_at IS NOT NULL),
    CHECK(expires_at IS NULL OR expires_at > observed_at),
    FOREIGN KEY(network_id, node_id)
        REFERENCES nodes(network_id, node_id) ON DELETE CASCADE,
    FOREIGN KEY(network_id, node_id, applied_revision)
        REFERENCES node_revision_targets(network_id, node_id, revision)
) STRICT, WITHOUT ROWID;

CREATE UNIQUE INDEX node_endpoint_candidates_current_address
    ON node_endpoint_candidates(network_id, node_id, mode, address, port, applied_revision)
    WHERE withdrawn_at IS NULL;

CREATE INDEX node_endpoint_candidates_current_node
    ON node_endpoint_candidates(network_id, node_id, last_reported_at DESC)
    WHERE withdrawn_at IS NULL;

CREATE TABLE node_endpoint_verifications (
    network_id TEXT NOT NULL,
    node_id TEXT NOT NULL,
    endpoint_id TEXT NOT NULL,
    status TEXT NOT NULL CHECK(status IN ('pending', 'verified', 'failed', 'withdrawn')),
    probe_attempts INTEGER NOT NULL DEFAULT 0 CHECK(probe_attempts >= 0),
    last_probe_at INTEGER,
    last_success_at INTEGER,
    latency_ms INTEGER CHECK(latency_ms IS NULL OR latency_ms >= 0),
    error_code TEXT,
    verification_expires_at INTEGER,
    updated_at INTEGER NOT NULL,
    PRIMARY KEY(network_id, node_id, endpoint_id),
    CHECK(last_success_at IS NULL OR (
        last_probe_at IS NOT NULL AND last_success_at <= last_probe_at
    )),
    CHECK(verification_expires_at IS NULL OR (
        last_success_at IS NOT NULL AND verification_expires_at > last_success_at
    )),
    CHECK(
        (status = 'pending' AND probe_attempts = 0
            AND last_probe_at IS NULL AND last_success_at IS NULL
            AND latency_ms IS NULL AND error_code IS NULL
            AND verification_expires_at IS NULL)
        OR (status = 'verified' AND probe_attempts > 0
            AND last_probe_at IS NOT NULL AND last_success_at IS NOT NULL
            AND latency_ms IS NOT NULL AND error_code IS NULL
            AND verification_expires_at IS NOT NULL)
        OR (status = 'failed' AND probe_attempts > 0
            AND last_probe_at IS NOT NULL AND error_code IS NOT NULL)
        OR status = 'withdrawn'
    ),
    FOREIGN KEY(network_id, node_id, endpoint_id)
        REFERENCES node_endpoint_candidates(network_id, node_id, endpoint_id)
        ON DELETE RESTRICT
) STRICT, WITHOUT ROWID;

CREATE INDEX node_endpoint_verifications_status
    ON node_endpoint_verifications(network_id, status, updated_at);
";

const MIGRATION_7_SQL: &str = r"
ALTER TABLE nodes ADD COLUMN consent_router_mapping INTEGER NOT NULL DEFAULT 0
    CHECK(consent_router_mapping IN (0, 1));
";

const MIGRATION_8_SQL: &str = r"
CREATE TABLE endpoint_probe_attempts (
    attempt_id INTEGER PRIMARY KEY AUTOINCREMENT,
    network_id TEXT NOT NULL,
    probe_id TEXT NOT NULL CHECK(length(probe_id) = 36),
    node_id TEXT NOT NULL,
    endpoint_id TEXT NOT NULL,
    phase TEXT NOT NULL CHECK(phase IN ('tcp', 'protocol')),
    status TEXT NOT NULL
        CHECK(status IN ('claimed', 'succeeded', 'failed', 'cancelled', 'expired')),
    runner_id TEXT NOT NULL CHECK(length(runner_id) = 36),
    claim_token_sha256 BLOB NOT NULL CHECK(length(claim_token_sha256) = 32),
    candidate_generation INTEGER NOT NULL CHECK(candidate_generation > 0),
    address TEXT NOT NULL CHECK(length(address) BETWEEN 1 AND 253),
    port INTEGER NOT NULL CHECK(port BETWEEN 1 AND 65535),
    applied_revision INTEGER NOT NULL CHECK(applied_revision > 0),
    started_at INTEGER NOT NULL,
    claim_expires_at INTEGER NOT NULL,
    completed_at INTEGER,
    resolved_address TEXT CHECK(
        resolved_address IS NULL OR length(resolved_address) BETWEEN 2 AND 45
    ),
    latency_ms INTEGER CHECK(latency_ms IS NULL OR latency_ms >= 0),
    result_code TEXT CHECK(result_code IS NULL OR length(result_code) BETWEEN 1 AND 64),
    UNIQUE(network_id, probe_id),
    CHECK(claim_expires_at > started_at),
    CHECK(completed_at IS NULL OR completed_at >= started_at),
    CHECK(
        (status = 'claimed' AND completed_at IS NULL
            AND resolved_address IS NULL AND latency_ms IS NULL AND result_code IS NULL)
        OR (status = 'succeeded' AND completed_at IS NOT NULL
            AND resolved_address IS NOT NULL AND latency_ms IS NOT NULL
            AND (
                (phase = 'tcp' AND result_code = 'direct_tcp_connected')
                OR (phase = 'protocol' AND result_code = 'direct_protocol_connected')
            ))
        OR (status = 'failed' AND completed_at IS NOT NULL AND result_code IS NOT NULL)
        OR (status = 'cancelled' AND completed_at IS NOT NULL
            AND resolved_address IS NULL AND latency_ms IS NULL
            AND result_code = 'candidate_changed')
        OR (status = 'expired' AND completed_at IS NOT NULL
            AND resolved_address IS NULL AND latency_ms IS NULL
            AND result_code = 'claim_expired')
    ),
    FOREIGN KEY(network_id, node_id, endpoint_id)
        REFERENCES node_endpoint_candidates(network_id, node_id, endpoint_id)
        ON DELETE RESTRICT
) STRICT;

CREATE UNIQUE INDEX endpoint_probe_attempts_active_node
    ON endpoint_probe_attempts(network_id, node_id)
    WHERE status = 'claimed';

CREATE INDEX endpoint_probe_attempts_latest_endpoint
    ON endpoint_probe_attempts(
        network_id, node_id, endpoint_id, phase, attempt_id DESC
    );

CREATE TRIGGER endpoint_probe_attempts_terminal_transition
BEFORE UPDATE ON endpoint_probe_attempts
WHEN OLD.status != 'claimed'
    OR NEW.status NOT IN ('succeeded', 'failed', 'cancelled', 'expired')
    OR NEW.attempt_id != OLD.attempt_id
    OR NEW.network_id != OLD.network_id
    OR NEW.probe_id != OLD.probe_id
    OR NEW.node_id != OLD.node_id
    OR NEW.endpoint_id != OLD.endpoint_id
    OR NEW.phase != OLD.phase
    OR NEW.runner_id != OLD.runner_id
    OR NEW.claim_token_sha256 != OLD.claim_token_sha256
    OR NEW.candidate_generation != OLD.candidate_generation
    OR NEW.address != OLD.address
    OR NEW.port != OLD.port
    OR NEW.applied_revision != OLD.applied_revision
    OR NEW.started_at != OLD.started_at
    OR NEW.claim_expires_at != OLD.claim_expires_at
BEGIN
    SELECT RAISE(ABORT, 'endpoint probe attempts allow only one terminal transition');
END;

CREATE TRIGGER endpoint_probe_attempts_no_delete
BEFORE DELETE ON endpoint_probe_attempts
BEGIN
    SELECT RAISE(ABORT, 'endpoint probe attempts are retained');
END;
";

const MIGRATION_9_SQL: &str = r"
CREATE TABLE users (
    network_id TEXT NOT NULL REFERENCES networks(network_id) ON DELETE CASCADE,
    user_id TEXT NOT NULL CHECK(length(user_id) = 36),
    display_name TEXT NOT NULL CHECK(length(display_name) BETWEEN 1 AND 128),
    status TEXT NOT NULL CHECK(status IN ('active', 'disabled', 'deleted')),
    credential_version INTEGER NOT NULL DEFAULT 1 CHECK(credential_version > 0),
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    disabled_at INTEGER,
    deleted_at INTEGER,
    PRIMARY KEY(network_id, user_id),
    CHECK(updated_at >= created_at),
    CHECK(
        (status = 'active' AND disabled_at IS NULL AND deleted_at IS NULL)
        OR (status = 'disabled' AND disabled_at IS NOT NULL AND deleted_at IS NULL)
        OR (status = 'deleted' AND deleted_at IS NOT NULL)
    )
) STRICT, WITHOUT ROWID;

CREATE TABLE user_node_assignments (
    network_id TEXT NOT NULL,
    assignment_id TEXT NOT NULL CHECK(length(assignment_id) = 36),
    user_id TEXT NOT NULL,
    node_id TEXT NOT NULL,
    status TEXT NOT NULL CHECK(status IN ('enabled', 'disabled', 'deleted')),
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    disabled_at INTEGER,
    deleted_at INTEGER,
    PRIMARY KEY(network_id, assignment_id),
    UNIQUE(network_id, user_id, node_id),
    UNIQUE(network_id, assignment_id, user_id, node_id),
    CHECK(updated_at >= created_at),
    CHECK(
        (status = 'enabled' AND disabled_at IS NULL AND deleted_at IS NULL)
        OR (status = 'disabled' AND disabled_at IS NOT NULL AND deleted_at IS NULL)
        OR (status = 'deleted' AND deleted_at IS NOT NULL)
    ),
    FOREIGN KEY(network_id, user_id)
        REFERENCES users(network_id, user_id) ON DELETE RESTRICT,
    FOREIGN KEY(network_id, node_id)
        REFERENCES nodes(network_id, node_id) ON DELETE RESTRICT
) STRICT, WITHOUT ROWID;

CREATE TABLE user_node_credentials (
    network_id TEXT NOT NULL,
    credential_id TEXT NOT NULL CHECK(length(credential_id) = 36),
    assignment_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    node_id TEXT NOT NULL,
    xray_email TEXT NOT NULL CHECK(length(xray_email) BETWEEN 1 AND 128),
    vless_uuid TEXT NOT NULL CHECK(length(vless_uuid) = 36),
    version INTEGER NOT NULL CHECK(version > 0),
    status TEXT NOT NULL CHECK(status IN ('pending', 'active', 'retiring', 'revoked')),
    created_at INTEGER NOT NULL,
    activated_at INTEGER,
    retire_after INTEGER,
    revoked_at INTEGER,
    PRIMARY KEY(network_id, credential_id),
    UNIQUE(network_id, assignment_id, version),
    UNIQUE(network_id, node_id, xray_email),
    UNIQUE(network_id, node_id, vless_uuid),
    CHECK(
        (status = 'pending' AND activated_at IS NULL
            AND retire_after IS NULL AND revoked_at IS NULL)
        OR (status = 'active' AND activated_at IS NOT NULL
            AND retire_after IS NULL AND revoked_at IS NULL)
        OR (status = 'retiring' AND activated_at IS NOT NULL
            AND retire_after IS NOT NULL AND revoked_at IS NULL)
        OR (status = 'revoked' AND retire_after IS NULL AND revoked_at IS NOT NULL)
    ),
    CHECK(activated_at IS NULL OR activated_at >= created_at),
    CHECK(retire_after IS NULL OR retire_after > activated_at),
    CHECK(revoked_at IS NULL OR revoked_at >= created_at),
    CHECK(activated_at IS NULL OR revoked_at IS NULL OR revoked_at >= activated_at),
    FOREIGN KEY(network_id, assignment_id, user_id, node_id)
        REFERENCES user_node_assignments(network_id, assignment_id, user_id, node_id)
        ON DELETE RESTRICT
) STRICT, WITHOUT ROWID;

CREATE TABLE idempotency_records (
    network_id TEXT NOT NULL REFERENCES networks(network_id) ON DELETE CASCADE,
    principal_type TEXT NOT NULL CHECK(length(principal_type) BETWEEN 1 AND 64),
    principal_id TEXT NOT NULL CHECK(length(principal_id) BETWEEN 1 AND 128),
    route_id TEXT NOT NULL CHECK(length(route_id) BETWEEN 1 AND 128),
    idempotency_key_sha256 BLOB NOT NULL CHECK(length(idempotency_key_sha256) = 32),
    request_sha256 BLOB NOT NULL CHECK(length(request_sha256) = 32),
    state TEXT NOT NULL CHECK(state IN ('in_progress', 'completed')),
    response_status INTEGER CHECK(response_status BETWEEN 100 AND 599),
    response_json TEXT CHECK(
        response_json IS NULL OR (json_valid(response_json) AND length(response_json) <= 65536)
    ),
    response_sha256 BLOB CHECK(response_sha256 IS NULL OR length(response_sha256) = 32),
    created_at INTEGER NOT NULL,
    completed_at INTEGER,
    expires_at INTEGER NOT NULL,
    PRIMARY KEY(
        network_id, principal_type, principal_id, route_id, idempotency_key_sha256
    ),
    CHECK(expires_at > created_at),
    CHECK(
        (state = 'in_progress' AND response_status IS NULL
            AND response_json IS NULL AND response_sha256 IS NULL
            AND completed_at IS NULL)
        OR (state = 'completed' AND response_status IS NOT NULL
            AND response_json IS NOT NULL AND response_sha256 IS NOT NULL
            AND completed_at IS NOT NULL AND completed_at >= created_at)
    )
) STRICT, WITHOUT ROWID;

CREATE INDEX user_node_assignments_user_status
    ON user_node_assignments(network_id, user_id, status, node_id);
CREATE INDEX user_node_credentials_node_status
    ON user_node_credentials(network_id, node_id, status, user_id);
CREATE INDEX idempotency_records_expiry
    ON idempotency_records(network_id, expires_at);
";

const MIGRATION_10_SQL: &str = r"
CREATE UNIQUE INDEX user_node_credentials_snapshot_identity
    ON user_node_credentials(
        network_id, credential_id, assignment_id, user_id, node_id
    );

CREATE TABLE node_revision_member_snapshots (
    network_id TEXT NOT NULL,
    node_id TEXT NOT NULL,
    revision INTEGER NOT NULL CHECK(revision > 0),
    created_at INTEGER NOT NULL,
    PRIMARY KEY(network_id, node_id, revision),
    FOREIGN KEY(network_id, node_id, revision)
        REFERENCES node_revision_targets(network_id, node_id, revision)
        ON DELETE RESTRICT
) STRICT, WITHOUT ROWID;

CREATE TABLE node_revision_member_credentials (
    network_id TEXT NOT NULL,
    node_id TEXT NOT NULL,
    revision INTEGER NOT NULL CHECK(revision > 0),
    credential_id TEXT NOT NULL,
    assignment_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    PRIMARY KEY(network_id, node_id, revision, credential_id),
    UNIQUE(network_id, node_id, revision, assignment_id),
    UNIQUE(network_id, node_id, revision, user_id),
    FOREIGN KEY(network_id, node_id, revision)
        REFERENCES node_revision_member_snapshots(network_id, node_id, revision)
        ON DELETE RESTRICT,
    FOREIGN KEY(network_id, credential_id, assignment_id, user_id, node_id)
        REFERENCES user_node_credentials(
            network_id, credential_id, assignment_id, user_id, node_id
        ) ON DELETE RESTRICT
) STRICT, WITHOUT ROWID;

CREATE INDEX node_revision_member_credentials_assignment
    ON node_revision_member_credentials(network_id, assignment_id, revision);

CREATE TRIGGER node_revision_member_snapshots_no_update
BEFORE UPDATE ON node_revision_member_snapshots
BEGIN
    SELECT RAISE(ABORT, 'node revision member snapshots are immutable');
END;

CREATE TRIGGER node_revision_member_snapshots_no_delete
BEFORE DELETE ON node_revision_member_snapshots
BEGIN
    SELECT RAISE(ABORT, 'node revision member snapshots are immutable');
END;

CREATE TRIGGER node_revision_member_credentials_no_update
BEFORE UPDATE ON node_revision_member_credentials
BEGIN
    SELECT RAISE(ABORT, 'node revision member credentials are immutable');
END;

CREATE TRIGGER node_revision_member_credentials_no_delete
BEFORE DELETE ON node_revision_member_credentials
BEGIN
    SELECT RAISE(ABORT, 'node revision member credentials are immutable');
END;
";

const MIGRATION_11_SQL: &str = r"
ALTER TABLE node_invitations ADD COLUMN initial_configuration_json TEXT
    CHECK(initial_configuration_json IS NULL OR (
        json_valid(initial_configuration_json)
        AND length(initial_configuration_json) BETWEEN 2 AND 4096
    ));
ALTER TABLE node_invitations ADD COLUMN idempotency_key_sha256 BLOB
    CHECK(idempotency_key_sha256 IS NULL OR length(idempotency_key_sha256) = 32);
ALTER TABLE node_invitations ADD COLUMN request_sha256 BLOB
    CHECK(
        (idempotency_key_sha256 IS NULL AND request_sha256 IS NULL)
        OR (idempotency_key_sha256 IS NOT NULL
            AND request_sha256 IS NOT NULL
            AND length(request_sha256) = 32)
    );

CREATE UNIQUE INDEX node_invitations_idempotency
    ON node_invitations(network_id, idempotency_key_sha256)
    WHERE idempotency_key_sha256 IS NOT NULL;

ALTER TABLE nodes ADD COLUMN reality_public_key TEXT
    CHECK(reality_public_key IS NULL OR length(reality_public_key) = 43);
ALTER TABLE nodes ADD COLUMN reality_short_id TEXT
    CHECK(
        (reality_public_key IS NULL AND reality_short_id IS NULL)
        OR (reality_public_key IS NOT NULL
            AND reality_short_id IS NOT NULL
            AND length(reality_short_id) = 16
            AND reality_short_id NOT GLOB '*[^0-9a-f]*')
    );

CREATE UNIQUE INDEX nodes_reality_public_key_unique
    ON nodes(reality_public_key) WHERE reality_public_key IS NOT NULL;
";

struct Migration {
    version: i64,
    name: &'static str,
    sql: &'static str,
}

const MIGRATIONS: &[Migration] = &[
    Migration {
        version: 1,
        name: "control_service_foundation",
        sql: MIGRATION_1_SQL,
    },
    Migration {
        version: 2,
        name: "node_enrollment",
        sql: MIGRATION_2_SQL,
    },
    Migration {
        version: 3,
        name: "node_request_auth_and_heartbeat",
        sql: MIGRATION_3_SQL,
    },
    Migration {
        version: 4,
        name: "signed_desired_state_revisions",
        sql: MIGRATION_4_SQL,
    },
    Migration {
        version: 5,
        name: "desired_state_schema_v2",
        sql: MIGRATION_5_SQL,
    },
    Migration {
        version: 6,
        name: "controller_owned_endpoint_verification",
        sql: MIGRATION_6_SQL,
    },
    Migration {
        version: 7,
        name: "router_mapping_consent",
        sql: MIGRATION_7_SQL,
    },
    Migration {
        version: 8,
        name: "endpoint_tcp_probe_attempts",
        sql: MIGRATION_8_SQL,
    },
    Migration {
        version: 9,
        name: "member_accounts_and_assignments",
        sql: MIGRATION_9_SQL,
    },
    Migration {
        version: 10,
        name: "member_desired_state_snapshots",
        sql: MIGRATION_10_SQL,
    },
    Migration {
        version: 11,
        name: "one_action_node_bootstrap",
        sql: MIGRATION_11_SQL,
    },
];

#[derive(Clone)]
pub struct Database {
    inner: Arc<Mutex<DatabaseInner>>,
    controller_identity: ControllerIdentity,
}

struct DatabaseInner {
    connection: Connection,
    _lock: File,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NetworkRecord {
    pub network_id: String,
    pub display_name: String,
    pub status: String,
    pub last_revision: i64,
    pub controller_epoch: String,
    pub created_at: i64,
    pub updated_at: i64,
}

/// Enrollment response plus whether this request created the durable node.
pub struct NodeEnrollmentResult {
    pub response: EnrollNodeResponse,
    pub created: bool,
}

pub(crate) struct DesiredStateReconcileResult {
    pub desired: SignedDesiredState,
    pub created: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AuthenticatedNode {
    pub node_id: NodeId,
    pub key_id: NodeKeyId,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NodeProviderConsentRecord {
    pub policy_version: String,
    pub host_owner: bool,
    pub exit_ip: bool,
    pub router_mapping: bool,
    pub accepted_at: i64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NodeSummaryRecord {
    pub node_id: NodeId,
    pub network_id: String,
    pub display_name: String,
    pub status: String,
    pub platform: String,
    pub agent_version: String,
    pub xray_version: Option<String>,
    pub public_material_ready: bool,
    pub onboarding_state: String,
    pub capabilities: Vec<NodeCapability>,
    pub provider_consent: NodeProviderConsentRecord,
    pub last_seen_at: Option<i64>,
    pub runtime_state: Option<String>,
    pub provider_paused: bool,
    pub desired_revision: Option<i64>,
    pub received_revision: Option<i64>,
    pub validated_revision: Option<i64>,
    pub applied_revision: Option<i64>,
    pub telemetry_cursor: i64,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NodeLifecycleAction {
    Approve,
    Disable,
    Revoke,
}

impl NodeLifecycleAction {
    const fn wire_name(self) -> &'static str {
        match self {
            Self::Approve => "approve",
            Self::Disable => "disable",
            Self::Revoke => "revoke",
        }
    }

    const fn audit_event(self) -> &'static str {
        match self {
            Self::Approve => "node.approved",
            Self::Disable => "node.disabled",
            Self::Revoke => "node.revoked",
        }
    }
}

impl Database {
    /// Opens the exclusively owned database, migrates it, and bootstraps its network.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] for invalid configuration, another live
    /// owner, incompatible migration history, failed integrity checks, or I/O.
    pub fn open(path: &Path, network_display_name: &str) -> Result<Self, DatabaseError> {
        validate_network_name(network_display_name)?;
        prepare_parent(path)?;
        prepare_owner_only_file(path)?;
        let lock = acquire_lock(path)?;
        let controller_identity = ControllerIdentity::load_or_create(path)?;
        let mut connection = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_WRITE
                | OpenFlags::SQLITE_OPEN_CREATE
                | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;

        configure_connection(&connection)?;
        validate_application_id(&connection)?;
        migrate(&mut connection)?;
        bootstrap_network(&mut connection, network_display_name)?;
        verify_database(&connection)?;

        Ok(Self {
            inner: Arc::new(Mutex::new(DatabaseInner {
                connection,
                _lock: lock,
            })),
            controller_identity,
        })
    }

    /// Loads the singleton network without blocking the async executor.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] when the blocking worker, ownership mutex, or
    /// `SQLite` query fails.
    pub async fn network(&self) -> Result<NetworkRecord, DatabaseError> {
        let inner = Arc::clone(&self.inner);
        tokio::task::spawn_blocking(move || {
            let guard = inner.lock().map_err(|_| DatabaseError::LockPoisoned)?;
            load_network(&guard.connection)
        })
        .await
        .map_err(DatabaseError::Worker)?
    }

    /// Loads safe operator-facing node summaries without credential or key material.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] when the blocking worker, ownership mutex,
    /// stored protocol data, or `SQLite` query fails.
    pub async fn list_nodes(&self) -> Result<Vec<NodeSummaryRecord>, DatabaseError> {
        let inner = Arc::clone(&self.inner);
        tokio::task::spawn_blocking(move || {
            let guard = inner.lock().map_err(|_| DatabaseError::LockPoisoned)?;
            load_nodes(&guard.connection)
        })
        .await
        .map_err(DatabaseError::Worker)?
    }

    /// Creates one active logical member account.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] when validation, clock, worker, or durable
    /// storage fails.
    pub async fn create_account(
        &self,
        request: CreateAccountRequest,
        idempotency_key: IdempotencyKey,
    ) -> Result<AccountSummary, DatabaseError> {
        request.validate()?;
        let inner = Arc::clone(&self.inner);
        tokio::task::spawn_blocking(move || {
            let mut guard = inner.lock().map_err(|_| DatabaseError::LockPoisoned)?;
            create_account(&mut guard.connection, &request, &idempotency_key)
        })
        .await
        .map_err(DatabaseError::Worker)?
    }

    /// Loads safe account and assignment summaries.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] for worker, storage, or stored-value failures.
    pub async fn list_accounts(&self) -> Result<Vec<AccountSummary>, DatabaseError> {
        let inner = Arc::clone(&self.inner);
        tokio::task::spawn_blocking(move || {
            let guard = inner.lock().map_err(|_| DatabaseError::LockPoisoned)?;
            load_accounts(&guard.connection)
        })
        .await
        .map_err(DatabaseError::Worker)?
    }

    /// Atomically replaces the complete enabled node set for one account.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] when the account or node is unavailable, the
    /// lifecycle conflicts, credential generation is exhausted, or storage
    /// fails.
    pub async fn replace_account_nodes(
        &self,
        user_id: UserId,
        request: ReplaceAccountNodesRequest,
    ) -> Result<AccountSummary, DatabaseError> {
        request.validate()?;
        let identity = self.controller_identity.clone();
        let inner = Arc::clone(&self.inner);
        tokio::task::spawn_blocking(move || {
            let mut guard = inner.lock().map_err(|_| DatabaseError::LockPoisoned)?;
            replace_account_nodes(&mut guard.connection, &identity, user_id, &request)
        })
        .await
        .map_err(DatabaseError::Worker)?
    }

    /// Applies an explicit account lifecycle transition.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] when the account is unknown, a deleted account
    /// would be restored, credential generation is exhausted, or storage fails.
    pub async fn set_account_status(
        &self,
        user_id: UserId,
        status: AccountStatus,
    ) -> Result<AccountSummary, DatabaseError> {
        let identity = self.controller_identity.clone();
        let inner = Arc::clone(&self.inner);
        tokio::task::spawn_blocking(move || {
            let mut guard = inner.lock().map_err(|_| DatabaseError::LockPoisoned)?;
            set_account_status(&mut guard.connection, &identity, user_id, status)
        })
        .await
        .map_err(DatabaseError::Worker)?
    }

    /// Applies an operator-controlled node lifecycle transition atomically.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError::NodeNotFound`] for an unknown node and
    /// [`DatabaseError::NodeLifecycleConflict`] for a disallowed transition.
    pub async fn transition_node(
        &self,
        node_id: NodeId,
        action: NodeLifecycleAction,
    ) -> Result<(), DatabaseError> {
        let inner = Arc::clone(&self.inner);
        tokio::task::spawn_blocking(move || {
            let mut guard = inner.lock().map_err(|_| DatabaseError::LockPoisoned)?;
            transition_node(&mut guard.connection, node_id, action)
        })
        .await
        .map_err(DatabaseError::Worker)?
    }

    /// Creates a high-entropy one-time node invitation.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] for validation, clock, or storage failures.
    pub async fn create_node_invitation(
        &self,
        request: CreateNodeInvitationRequest,
        controller_origin: String,
        idempotency_key: IdempotencyKey,
    ) -> Result<CreateNodeInvitationResponse, DatabaseError> {
        request.validate()?;
        let identity = self.controller_identity.clone();
        let inner = Arc::clone(&self.inner);
        tokio::task::spawn_blocking(move || {
            let mut guard = inner.lock().map_err(|_| DatabaseError::LockPoisoned)?;
            create_node_invitation(
                &mut guard.connection,
                &identity,
                &request,
                &controller_origin,
                &idempotency_key,
            )
        })
        .await
        .map_err(DatabaseError::Worker)?
    }

    /// Atomically consumes an invitation and creates the node and first key.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] for invalid invitations or proofs, validation,
    /// clock, and storage failures.
    pub async fn enroll_node(
        &self,
        request: EnrollNodeRequest,
    ) -> Result<NodeEnrollmentResult, DatabaseError> {
        request.validate()?;
        let identity = self.controller_identity.clone();
        let inner = Arc::clone(&self.inner);
        tokio::task::spawn_blocking(move || {
            let mut guard = inner.lock().map_err(|_| DatabaseError::LockPoisoned)?;
            enroll_node(&mut guard.connection, &identity, &request)
        })
        .await
        .map_err(DatabaseError::Worker)?
    }

    /// Verifies a signed node request and atomically reserves its nonce.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] when identity, credential lifetime, clock,
    /// signature, replay policy, or durable nonce storage validation fails.
    pub async fn authenticate_node_request(
        &self,
        headers: NodeRequestAuthHeaders,
        input: NodeRequestSigningInput,
    ) -> Result<AuthenticatedNode, DatabaseError> {
        let inner = Arc::clone(&self.inner);
        tokio::task::spawn_blocking(move || {
            let mut guard = inner.lock().map_err(|_| DatabaseError::LockPoisoned)?;
            authenticate_node_request(&mut guard.connection, &headers, &input)
        })
        .await
        .map_err(DatabaseError::Worker)?
    }

    /// Persists the latest validated heartbeat and replaces its reported endpoints.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] when the heartbeat is invalid, the node is no
    /// longer active, or the transactional update cannot be committed.
    pub async fn record_heartbeat(
        &self,
        node_id: NodeId,
        heartbeat: NodeHeartbeat,
    ) -> Result<SignedNodeHeartbeatStatus, DatabaseError> {
        let identity = self.controller_identity.clone();
        let inner = Arc::clone(&self.inner);
        tokio::task::spawn_blocking(move || {
            let mut guard = inner.lock().map_err(|_| DatabaseError::LockPoisoned)?;
            record_heartbeat(&mut guard.connection, &identity, node_id, &heartbeat)
        })
        .await
        .map_err(DatabaseError::Worker)?
    }

    /// Claims one due direct-endpoint TCP preflight with a finite lease.
    ///
    /// The returned token is not stored in plaintext. Callers must release the
    /// database lock before doing network work and then submit the whole job to
    /// [`Self::complete_tcp_probe`].
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] for invalid scheduling, clock, worker, or
    /// durable storage failures.
    pub async fn claim_tcp_probe(
        &self,
        runner_id: Uuid,
        options: TcpProbeLoopOptions,
    ) -> Result<Option<TcpProbeJob>, DatabaseError> {
        let schedule = options
            .validated_schedule()
            .map_err(|_| DatabaseError::InvalidProbeSchedule)?;
        let inner = Arc::clone(&self.inner);
        tokio::task::spawn_blocking(move || {
            let mut guard = inner.lock().map_err(|_| DatabaseError::LockPoisoned)?;
            claim_tcp_probe(&mut guard.connection, runner_id, schedule)
        })
        .await
        .map_err(DatabaseError::Worker)?
    }

    /// Completes one claimed TCP preflight without trusting stale candidate state.
    ///
    /// A successful TCP connection is retained as preflight evidence only. It
    /// never changes `node_endpoint_verifications` to `verified`; that requires
    /// a later protocol-aware VLESS+REALITY canary.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] when the claim is unknown, forged, corrupt, or
    /// cannot be committed atomically.
    pub async fn complete_tcp_probe(
        &self,
        job: TcpProbeJob,
        result: TcpProbeResult,
    ) -> Result<TcpProbeCompletion, DatabaseError> {
        let inner = Arc::clone(&self.inner);
        tokio::task::spawn_blocking(move || {
            let mut guard = inner.lock().map_err(|_| DatabaseError::LockPoisoned)?;
            complete_tcp_probe(&mut guard.connection, &job, &result)
        })
        .await
        .map_err(DatabaseError::Worker)?
    }

    /// Publishes one immutable signed desired-state revision for an active node.
    pub(crate) async fn publish_desired_state(
        &self,
        node_id: NodeId,
        configuration: DesiredStateConfigurationDraft,
    ) -> Result<SignedDesiredState, DatabaseError> {
        let identity = self.controller_identity.clone();
        let inner = Arc::clone(&self.inner);
        tokio::task::spawn_blocking(move || {
            let mut guard = inner.lock().map_err(|_| DatabaseError::LockPoisoned)?;
            publish_desired_state(&mut guard.connection, &identity, node_id, configuration)
        })
        .await
        .map_err(DatabaseError::Worker)?
    }

    /// Returns or republishes the current authoritative snapshot for one node.
    pub(crate) async fn reconcile_node_desired_state(
        &self,
        node_id: NodeId,
    ) -> Result<DesiredStateReconcileResult, DatabaseError> {
        let identity = self.controller_identity.clone();
        let inner = Arc::clone(&self.inner);
        tokio::task::spawn_blocking(move || {
            let mut guard = inner.lock().map_err(|_| DatabaseError::LockPoisoned)?;
            reconcile_node_desired_state(&mut guard.connection, &identity, node_id)
        })
        .await
        .map_err(DatabaseError::Worker)?
    }

    /// Loads and verifies the latest desired state newer than the node cursor.
    pub(crate) async fn desired_state_after(
        &self,
        node_id: NodeId,
        after_revision: i64,
    ) -> Result<Option<SignedDesiredState>, DatabaseError> {
        let identity = self.controller_identity.clone();
        let inner = Arc::clone(&self.inner);
        tokio::task::spawn_blocking(move || {
            let guard = inner.lock().map_err(|_| DatabaseError::LockPoisoned)?;
            desired_state_after(&guard.connection, &identity, node_id, after_revision)
        })
        .await
        .map_err(DatabaseError::Worker)?
    }

    /// Appends a monotonic result for one targeted desired-state revision.
    pub(crate) async fn record_revision_result(
        &self,
        node_id: NodeId,
        revision: Revision,
        result: RevisionResult,
    ) -> Result<(), DatabaseError> {
        result.validate(revision)?;
        let inner = Arc::clone(&self.inner);
        tokio::task::spawn_blocking(move || {
            let mut guard = inner.lock().map_err(|_| DatabaseError::LockPoisoned)?;
            record_revision_result(&mut guard.connection, node_id, revision, &result)
        })
        .await
        .map_err(DatabaseError::Worker)?
    }

    #[must_use]
    pub fn controller_identity(&self) -> ControllerIdentity {
        self.controller_identity.clone()
    }
}

fn authenticate_node_request(
    connection: &mut Connection,
    headers: &NodeRequestAuthHeaders,
    input: &NodeRequestSigningInput,
) -> Result<AuthenticatedNode, DatabaseError> {
    let now = unix_timestamp()?;
    let request_timestamp = headers.timestamp().as_datetime().unix_timestamp();
    if now.abs_diff(request_timestamp) > NODE_REQUEST_CLOCK_SKEW_SECONDS.unsigned_abs() {
        return Err(DatabaseError::NodeRequestClockSkew);
    }

    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    transaction.execute(
        "DELETE FROM node_request_nonces WHERE expires_at < ?1",
        [now],
    )?;
    let network = load_network(&transaction)?;
    let credential = transaction
        .query_row(
            "SELECT n.status, c.identity_public_key, c.not_before, c.expires_at, c.revoked_at
             FROM nodes AS n
             JOIN node_auth_credentials AS c
               ON c.network_id = n.network_id AND c.node_id = n.node_id
             WHERE n.network_id = ?1 AND n.node_id = ?2 AND c.node_credential_id = ?3",
            params![
                network.network_id,
                headers.node_id().to_string(),
                headers.key_id().to_string(),
            ],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, Option<i64>>(4)?,
                ))
            },
        )
        .optional()?;
    let Some((node_status, public_key, not_before, expires_at, revoked_at)) = credential else {
        return Err(DatabaseError::NodeAuthenticationFailed);
    };
    if matches!(node_status.as_str(), "disabled" | "revoked") || revoked_at.is_some() {
        return Err(DatabaseError::NodeRevoked);
    }
    if not_before > now || expires_at <= now {
        return Err(DatabaseError::NodeAuthenticationFailed);
    }

    let controller_instance_id = network
        .controller_epoch
        .parse::<ControllerInstanceId>()
        .map_err(|_| DatabaseError::StoredProtocolValue)?;
    let public_key = public_key
        .parse::<Ed25519PublicKey>()
        .map_err(|_| DatabaseError::StoredProtocolValue)?;
    verify_node_request_signature(&public_key, headers, input, controller_instance_id)
        .map_err(|_| DatabaseError::InvalidNodeRequestSignature)?;

    let expires_at = request_timestamp
        .checked_add(NODE_REQUEST_CLOCK_SKEW_SECONDS)
        .ok_or(DatabaseError::TimestampOverflow)?;
    let nonce_hash = Sha256::digest(headers.nonce().as_str().as_bytes());
    let inserted = transaction.execute(
        "INSERT OR IGNORE INTO node_request_nonces(
            network_id, node_id, node_credential_id, nonce_hash,
            request_timestamp, expires_at, created_at
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            network.network_id,
            headers.node_id().to_string(),
            headers.key_id().to_string(),
            nonce_hash.as_slice(),
            request_timestamp,
            expires_at,
            now,
        ],
    )?;
    if inserted == 0 {
        return Err(DatabaseError::NodeRequestNonceReplayed);
    }
    transaction.commit()?;

    Ok(AuthenticatedNode {
        node_id: headers.node_id(),
        key_id: headers.key_id(),
    })
}

fn record_heartbeat(
    connection: &mut Connection,
    identity: &ControllerIdentity,
    node_id: NodeId,
    heartbeat: &NodeHeartbeat,
) -> Result<SignedNodeHeartbeatStatus, DatabaseError> {
    heartbeat.validate()?;
    let heartbeat_json = serde_json::to_vec(heartbeat)?;
    let heartbeat_digest: [u8; 32] = Sha256::digest(&heartbeat_json).into();
    let now = unix_timestamp()?;
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let network = load_network(&transaction)?;
    let previous = transaction
        .query_row(
            "SELECT status, last_heartbeat_generation, last_heartbeat_sha256
             FROM nodes WHERE network_id = ?1 AND node_id = ?2",
            params![network.network_id, node_id.to_string()],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, Option<Vec<u8>>>(2)?,
                ))
            },
        )
        .optional()?;
    let Some((status, previous_generation, previous_digest)) = previous else {
        return Err(DatabaseError::NodeRevoked);
    };
    if !matches!(status.as_str(), "pending" | "active") {
        return Err(DatabaseError::NodeRevoked);
    }
    match heartbeat
        .heartbeat_generation
        .get()
        .cmp(&previous_generation)
    {
        std::cmp::Ordering::Less => return Err(DatabaseError::NodeHeartbeatStale),
        std::cmp::Ordering::Equal => {
            if previous_digest.as_deref() == Some(&heartbeat_digest[..]) {
                let response = build_signed_node_heartbeat_status(
                    &transaction,
                    identity,
                    &network,
                    node_id,
                    heartbeat.heartbeat_generation,
                    &status,
                    now,
                )?;
                transaction.commit()?;
                return Ok(response);
            }
            return Err(DatabaseError::NodeHeartbeatConflict);
        }
        std::cmp::Ordering::Greater => {}
    }
    validate_reported_progress(&transaction, &network.network_id, node_id, heartbeat)?;
    let updated = transaction.execute(
        "UPDATE nodes
         SET agent_version = ?1, xray_version = ?2, runtime_state = ?3,
             provider_paused = ?4, last_seen_at = ?5,
             reported_desired_revision = ?6,
             telemetry_cursor = ?7,
             last_heartbeat_generation = ?8,
             last_heartbeat_sha256 = ?9,
             updated_at = ?5
         WHERE network_id = ?10 AND node_id = ?11 AND status IN ('pending', 'active')",
        params![
            heartbeat.agent_version,
            heartbeat.xray_version,
            enum_wire(&heartbeat.state)?,
            i64::from(heartbeat.provider_paused),
            now,
            heartbeat
                .revisions
                .desired_revision
                .map(control_protocol::id::Revision::get),
            heartbeat.telemetry_cursor.get(),
            heartbeat.heartbeat_generation.get(),
            &heartbeat_digest[..],
            network.network_id,
            node_id.to_string(),
        ],
    )?;
    if updated != 1 {
        return Err(DatabaseError::NodeRevoked);
    }
    record_endpoint_candidates(
        &transaction,
        &network.network_id,
        node_id,
        heartbeat,
        heartbeat.heartbeat_generation.get(),
        now,
    )?;
    let response = build_signed_node_heartbeat_status(
        &transaction,
        identity,
        &network,
        node_id,
        heartbeat.heartbeat_generation,
        &status,
        now,
    )?;
    transaction.commit()?;
    Ok(response)
}

fn build_signed_node_heartbeat_status(
    transaction: &rusqlite::Transaction<'_>,
    identity: &ControllerIdentity,
    network: &NetworkRecord,
    node_id: NodeId,
    heartbeat_generation: SequenceNumber,
    lifecycle: &str,
    now: i64,
) -> Result<SignedNodeHeartbeatStatus, DatabaseError> {
    let lifecycle = match lifecycle {
        "pending" => NodeLifecycleState::Pending,
        "active" => NodeLifecycleState::Active,
        _ => return Err(DatabaseError::StoredProtocolValue),
    };
    let mut statement = transaction.prepare(
        "SELECT candidate.endpoint_id, candidate.last_report_generation,
                verification.status, verification.last_probe_at,
                verification.verification_expires_at,
                attempt.status, attempt.candidate_generation, attempt.claim_expires_at,
                attempt.completed_at, attempt.result_code
         FROM node_endpoint_candidates AS candidate
         JOIN node_endpoint_verifications AS verification
           ON verification.network_id = candidate.network_id
          AND verification.node_id = candidate.node_id
          AND verification.endpoint_id = candidate.endpoint_id
         LEFT JOIN endpoint_probe_attempts AS attempt
           ON attempt.attempt_id = (
               SELECT latest.attempt_id
               FROM endpoint_probe_attempts AS latest
               WHERE latest.network_id = candidate.network_id
                 AND latest.node_id = candidate.node_id
                 AND latest.endpoint_id = candidate.endpoint_id
                 AND latest.phase = 'tcp'
               ORDER BY latest.attempt_id DESC
               LIMIT 1
           )
         WHERE candidate.network_id = ?1 AND candidate.node_id = ?2
           AND candidate.withdrawn_at IS NULL
         ORDER BY candidate.endpoint_id",
    )?;
    let stored = statement
        .query_map(params![network.network_id, node_id.to_string()], |row| {
            Ok(StoredNodeEndpointStatus {
                endpoint_id: row.get(0)?,
                candidate_generation: row.get(1)?,
                verification_status: row.get(2)?,
                verification_last_probe_at: row.get(3)?,
                verification_expires_at: row.get(4)?,
                attempt_status: row.get(5)?,
                attempt_candidate_generation: row.get(6)?,
                attempt_claim_expires_at: row.get(7)?,
                attempt_completed_at: row.get(8)?,
                attempt_result_code: row.get(9)?,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;
    drop(statement);

    let mut endpoints = stored
        .into_iter()
        .map(|stored| decode_node_endpoint_status(stored, now))
        .collect::<Result<Vec<_>, _>>()?;
    endpoints.sort_by_key(|endpoint| endpoint.endpoint_id);

    let controller_instance_id = network
        .controller_epoch
        .parse::<ControllerInstanceId>()
        .map_err(|_| DatabaseError::StoredProtocolValue)?;
    let document = NodeHeartbeatStatus {
        schema_version: 1,
        node_id,
        heartbeat_generation,
        observed_at: timestamp(now)?,
        lifecycle,
        endpoints,
        signing_key_id: controller_signing_key_id(identity)?,
        controller_instance_id,
    };
    let transcript = node_heartbeat_status_transcript(&document)
        .map_err(|_| DatabaseError::StoredProtocolValue)?;
    let signature = identity.sign(&transcript)?;
    Ok(SignedNodeHeartbeatStatus {
        document,
        signature,
    })
}

struct StoredNodeEndpointStatus {
    endpoint_id: String,
    candidate_generation: i64,
    verification_status: String,
    verification_last_probe_at: Option<i64>,
    verification_expires_at: Option<i64>,
    attempt_status: Option<String>,
    attempt_candidate_generation: Option<i64>,
    attempt_claim_expires_at: Option<i64>,
    attempt_completed_at: Option<i64>,
    attempt_result_code: Option<String>,
}

fn decode_node_endpoint_status(
    stored: StoredNodeEndpointStatus,
    now: i64,
) -> Result<NodeEndpointStatus, DatabaseError> {
    let endpoint_id = stored
        .endpoint_id
        .parse::<EndpointId>()
        .map_err(|_| DatabaseError::StoredProtocolValue)?;
    let verification_is_current = match stored.verification_status.as_str() {
        "verified" => stored
            .verification_expires_at
            .is_some_and(|expires_at| expires_at > now),
        "pending" | "failed" => false,
        _ => return Err(DatabaseError::StoredProtocolValue),
    };
    if verification_is_current {
        return Ok(NodeEndpointStatus {
            endpoint_id,
            readiness: EndpointReadiness::Verified,
            last_checked_at: Some(timestamp(
                stored
                    .verification_last_probe_at
                    .ok_or(DatabaseError::StoredProtocolValue)?,
            )?),
            error_code: None,
        });
    }

    let (readiness, last_checked_at, error_code) = match stored.attempt_status.as_deref() {
        Some("claimed")
            if stored.attempt_candidate_generation == Some(stored.candidate_generation)
                && stored
                    .attempt_claim_expires_at
                    .is_some_and(|expires_at| expires_at > now) =>
        {
            (EndpointReadiness::Checking, None, None)
        }
        Some("claimed" | "cancelled" | "expired") | None => {
            (EndpointReadiness::Pending, None, None)
        }
        Some("succeeded") => (
            EndpointReadiness::TcpReachable,
            Some(timestamp(
                stored
                    .attempt_completed_at
                    .ok_or(DatabaseError::StoredProtocolValue)?,
            )?),
            None,
        ),
        Some("failed") => (
            EndpointReadiness::TcpUnreachable,
            Some(timestamp(
                stored
                    .attempt_completed_at
                    .ok_or(DatabaseError::StoredProtocolValue)?,
            )?),
            Some(
                stored
                    .attempt_result_code
                    .ok_or(DatabaseError::StoredProtocolValue)?,
            ),
        ),
        Some(_) => return Err(DatabaseError::StoredProtocolValue),
    };
    Ok(NodeEndpointStatus {
        endpoint_id,
        readiness,
        last_checked_at,
        error_code,
    })
}

const SELECT_DUE_TCP_PROBE_SQL: &str = r"
SELECT c.network_id, c.node_id, c.endpoint_id, c.address, c.port,
       c.applied_revision, c.last_report_generation
FROM node_endpoint_candidates AS c
JOIN nodes AS n ON n.network_id = c.network_id AND n.node_id = c.node_id
JOIN networks AS network ON network.network_id = c.network_id
JOIN config_revisions AS revision
  ON revision.network_id = c.network_id
 AND revision.node_id = c.node_id
 AND revision.revision = c.applied_revision
JOIN node_endpoint_verifications AS verification
  ON verification.network_id = c.network_id
 AND verification.node_id = c.node_id
 AND verification.endpoint_id = c.endpoint_id
WHERE network.status = 'active'
  AND n.status = 'active'
  AND n.runtime_state = 'serving'
  AND n.provider_paused = 0
  AND n.last_seen_at IS NOT NULL AND n.last_seen_at >= ?1
  AND n.applied_revision = c.applied_revision
  AND n.last_heartbeat_generation = c.last_report_generation
  AND revision.schema_version = 2
  AND json_type(revision.artifact_json, '$.document.xray.publicPort') = 'integer'
  AND json_extract(revision.artifact_json, '$.document.xray.publicPort') = c.port
  AND c.mode = 'direct'
  AND c.withdrawn_at IS NULL
  AND (c.expires_at IS NULL OR c.expires_at > ?2)
  AND verification.status != 'withdrawn'
  AND NOT EXISTS (
      SELECT 1 FROM endpoint_probe_attempts AS active
      WHERE active.network_id = c.network_id
        AND active.node_id = c.node_id
        AND active.status = 'claimed'
  )
  AND COALESCE((
      SELECT previous.started_at + CASE
          WHEN previous.status = 'succeeded' THEN ?3 ELSE ?4 END
      FROM endpoint_probe_attempts AS previous
      WHERE previous.network_id = c.network_id
        AND previous.node_id = c.node_id
        AND previous.endpoint_id = c.endpoint_id
        AND previous.phase = 'tcp'
      ORDER BY previous.attempt_id DESC
      LIMIT 1
  ), 0) <= ?5
ORDER BY COALESCE((
            SELECT MAX(previous.attempt_id)
            FROM endpoint_probe_attempts AS previous
            WHERE previous.network_id = c.network_id
              AND previous.node_id = c.node_id
              AND previous.endpoint_id = c.endpoint_id
              AND previous.phase = 'tcp'
         ), 0),
         c.first_reported_at,
         c.endpoint_id
LIMIT 1
";

struct StoredProbeCandidate {
    network_id: String,
    node_id: String,
    endpoint_id: String,
    address: String,
    port: i64,
    applied_revision: i64,
    candidate_generation: i64,
}

struct ProbeCandidate {
    network_id: NetworkId,
    node_id: NodeId,
    endpoint_id: EndpointId,
    address: String,
    port: u16,
    applied_revision: Revision,
    candidate_generation: i64,
}

fn claim_tcp_probe(
    connection: &mut Connection,
    runner_id: Uuid,
    schedule: ProbeSchedule,
) -> Result<Option<TcpProbeJob>, DatabaseError> {
    let now = unix_timestamp()?;
    let claim_expires_at = now
        .checked_add(probe_duration_seconds(schedule.claim_lease)?)
        .ok_or(DatabaseError::TimestampOverflow)?;
    let online_cutoff = now
        .checked_sub(probe_duration_seconds(schedule.node_online_window)?)
        .ok_or(DatabaseError::TimestampOverflow)?;
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    expire_stale_probe_claims(&transaction, now)?;
    let candidate = select_due_tcp_probe(
        &transaction,
        online_cutoff,
        claim_expires_at,
        probe_duration_seconds(schedule.success_interval)?,
        probe_duration_seconds(schedule.failure_interval)?,
        now,
    )?;
    let Some(candidate) = candidate else {
        transaction.commit()?;
        return Ok(None);
    };

    let probe_id = Uuid::new_v4();
    let mut claim_token = [0_u8; 32];
    OsRng.fill_bytes(&mut claim_token);
    let claim_token_digest: [u8; 32] = Sha256::digest(claim_token).into();
    insert_tcp_probe_claim(
        &transaction,
        &candidate,
        probe_id,
        runner_id,
        &claim_token_digest,
        now,
        claim_expires_at,
    )?;
    transaction.commit()?;

    Ok(Some(TcpProbeJob {
        probe_id,
        runner_id,
        network_id: candidate.network_id,
        node_id: candidate.node_id,
        endpoint_id: candidate.endpoint_id,
        address: candidate.address,
        port: candidate.port,
        applied_revision: candidate.applied_revision,
        candidate_generation: candidate.candidate_generation,
        claim_expires_at,
        claim_token: Secret::new(claim_token),
    }))
}

fn expire_stale_probe_claims(
    transaction: &rusqlite::Transaction<'_>,
    now: i64,
) -> Result<(), DatabaseError> {
    transaction.execute(
        "UPDATE endpoint_probe_attempts
         SET status = 'expired', completed_at = ?1, result_code = 'claim_expired'
         WHERE status = 'claimed' AND claim_expires_at <= ?1",
        [now],
    )?;
    Ok(())
}

fn select_due_tcp_probe(
    transaction: &rusqlite::Transaction<'_>,
    online_cutoff: i64,
    claim_expires_at: i64,
    success_interval: i64,
    failure_interval: i64,
    now: i64,
) -> Result<Option<ProbeCandidate>, DatabaseError> {
    let stored = transaction
        .query_row(
            SELECT_DUE_TCP_PROBE_SQL,
            params![
                online_cutoff,
                claim_expires_at,
                success_interval,
                failure_interval,
                now,
            ],
            |row| {
                Ok(StoredProbeCandidate {
                    network_id: row.get(0)?,
                    node_id: row.get(1)?,
                    endpoint_id: row.get(2)?,
                    address: row.get(3)?,
                    port: row.get(4)?,
                    applied_revision: row.get(5)?,
                    candidate_generation: row.get(6)?,
                })
            },
        )
        .optional()?;
    stored.map(decode_probe_candidate).transpose()
}

fn decode_probe_candidate(stored: StoredProbeCandidate) -> Result<ProbeCandidate, DatabaseError> {
    if stored.candidate_generation <= 0 {
        return Err(DatabaseError::StoredProtocolValue);
    }
    Ok(ProbeCandidate {
        network_id: stored
            .network_id
            .parse()
            .map_err(|_| DatabaseError::StoredProtocolValue)?,
        node_id: stored
            .node_id
            .parse()
            .map_err(|_| DatabaseError::StoredProtocolValue)?,
        endpoint_id: stored
            .endpoint_id
            .parse()
            .map_err(|_| DatabaseError::StoredProtocolValue)?,
        address: stored.address,
        port: u16::try_from(stored.port).map_err(|_| DatabaseError::StoredProtocolValue)?,
        applied_revision: Revision::new(stored.applied_revision)
            .map_err(|_| DatabaseError::StoredProtocolValue)?,
        candidate_generation: stored.candidate_generation,
    })
}

fn insert_tcp_probe_claim(
    transaction: &rusqlite::Transaction<'_>,
    candidate: &ProbeCandidate,
    probe_id: Uuid,
    runner_id: Uuid,
    claim_token_digest: &[u8; 32],
    now: i64,
    claim_expires_at: i64,
) -> Result<(), DatabaseError> {
    transaction.execute(
        "INSERT INTO endpoint_probe_attempts(
            network_id, probe_id, node_id, endpoint_id, phase, status, runner_id,
            claim_token_sha256, candidate_generation, address, port,
            applied_revision, started_at, claim_expires_at
         ) VALUES (
            ?1, ?2, ?3, ?4, 'tcp', 'claimed', ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12
         )",
        params![
            candidate.network_id.to_string(),
            probe_id.to_string(),
            candidate.node_id.to_string(),
            candidate.endpoint_id.to_string(),
            runner_id.to_string(),
            claim_token_digest.as_slice(),
            candidate.candidate_generation,
            candidate.address,
            i64::from(candidate.port),
            candidate.applied_revision.get(),
            now,
            claim_expires_at,
        ],
    )?;
    Ok(())
}

struct StoredProbeClaim {
    status: String,
    node_id: String,
    endpoint_id: String,
    phase: String,
    runner_id: String,
    claim_digest: [u8; 32],
    candidate_generation: i64,
    address: String,
    port: i64,
    applied_revision: i64,
    claim_expires_at: i64,
}

impl StoredProbeClaim {
    fn authenticates(&self, job: &TcpProbeJob) -> bool {
        let submitted_digest: [u8; 32] = Sha256::digest(job.claim_token.expose_secret()).into();
        bool::from(
            self.claim_digest
                .as_slice()
                .ct_eq(submitted_digest.as_slice()),
        ) && self.node_id == job.node_id.to_string()
            && self.endpoint_id == job.endpoint_id.to_string()
            && self.phase == "tcp"
            && self.runner_id == job.runner_id.to_string()
            && self.candidate_generation == job.candidate_generation
            && self.address == job.address
            && self.port == i64::from(job.port)
            && self.applied_revision == job.applied_revision.get()
            && self.claim_expires_at == job.claim_expires_at
    }

    fn is_terminal(&self) -> bool {
        matches!(
            self.status.as_str(),
            "succeeded" | "failed" | "cancelled" | "expired"
        )
    }
}

struct ProbeTerminalResult {
    status: &'static str,
    resolved_address: Option<String>,
    latency_ms: Option<i64>,
    result_code: &'static str,
}

impl ProbeTerminalResult {
    const fn expired() -> Self {
        Self {
            status: "expired",
            resolved_address: None,
            latency_ms: None,
            result_code: "claim_expired",
        }
    }

    const fn candidate_changed() -> Self {
        Self {
            status: "cancelled",
            resolved_address: None,
            latency_ms: None,
            result_code: "candidate_changed",
        }
    }
}

fn complete_tcp_probe(
    connection: &mut Connection,
    job: &TcpProbeJob,
    result: &TcpProbeResult,
) -> Result<TcpProbeCompletion, DatabaseError> {
    let now = unix_timestamp()?;
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let stored = load_probe_claim(&transaction, job)?;
    if !stored.authenticates(job) {
        return Err(DatabaseError::ProbeClaimConflict);
    }
    if stored.status != "claimed" {
        if stored.is_terminal() {
            transaction.commit()?;
            return Ok(TcpProbeCompletion::AlreadyRecorded);
        }
        return Err(DatabaseError::StoredProtocolValue);
    }
    if now >= stored.claim_expires_at {
        finish_probe_attempt(&transaction, job, &ProbeTerminalResult::expired(), now)?;
        transaction.commit()?;
        return Ok(TcpProbeCompletion::ClaimExpired);
    }
    if !probe_candidate_is_current(&transaction, job, now)? {
        finish_probe_attempt(
            &transaction,
            job,
            &ProbeTerminalResult::candidate_changed(),
            now,
        )?;
        transaction.commit()?;
        return Ok(TcpProbeCompletion::CandidateChanged);
    }

    let prepared = prepare_probe_result(result)?;
    finish_probe_attempt(&transaction, job, &prepared, now)?;
    transaction.commit()?;
    Ok(TcpProbeCompletion::Recorded)
}

fn load_probe_claim(
    transaction: &rusqlite::Transaction<'_>,
    job: &TcpProbeJob,
) -> Result<StoredProbeClaim, DatabaseError> {
    transaction
        .query_row(
            "SELECT status, node_id, endpoint_id, phase, runner_id,
                    claim_token_sha256, candidate_generation, address, port,
                    applied_revision, claim_expires_at
             FROM endpoint_probe_attempts
             WHERE network_id = ?1 AND probe_id = ?2",
            params![job.network_id.to_string(), job.probe_id.to_string()],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, Vec<u8>>(5)?,
                    row.get::<_, i64>(6)?,
                    row.get::<_, String>(7)?,
                    row.get::<_, i64>(8)?,
                    row.get::<_, i64>(9)?,
                    row.get::<_, i64>(10)?,
                ))
            },
        )
        .optional()?
        .ok_or(DatabaseError::ProbeClaimNotFound)
        .and_then(decode_probe_claim)
}

type StoredProbeClaimTuple = (
    String,
    String,
    String,
    String,
    String,
    Vec<u8>,
    i64,
    String,
    i64,
    i64,
    i64,
);

fn decode_probe_claim(stored: StoredProbeClaimTuple) -> Result<StoredProbeClaim, DatabaseError> {
    Ok(StoredProbeClaim {
        status: stored.0,
        node_id: stored.1,
        endpoint_id: stored.2,
        phase: stored.3,
        runner_id: stored.4,
        claim_digest: stored
            .5
            .try_into()
            .map_err(|_| DatabaseError::StoredProtocolValue)?,
        candidate_generation: stored.6,
        address: stored.7,
        port: stored.8,
        applied_revision: stored.9,
        claim_expires_at: stored.10,
    })
}

fn probe_candidate_is_current(
    transaction: &rusqlite::Transaction<'_>,
    job: &TcpProbeJob,
    now: i64,
) -> Result<bool, DatabaseError> {
    transaction
        .query_row(
            "SELECT EXISTS(
                 SELECT 1
                 FROM node_endpoint_candidates AS c
                 JOIN nodes AS n
                   ON n.network_id = c.network_id AND n.node_id = c.node_id
                 JOIN config_revisions AS revision
                   ON revision.network_id = c.network_id
                  AND revision.node_id = c.node_id
                  AND revision.revision = c.applied_revision
                 JOIN node_endpoint_verifications AS verification
                   ON verification.network_id = c.network_id
                  AND verification.node_id = c.node_id
                  AND verification.endpoint_id = c.endpoint_id
                 WHERE c.network_id = ?1 AND c.node_id = ?2 AND c.endpoint_id = ?3
                   AND c.mode = 'direct'
                   AND c.address = ?4 AND c.port = ?5 AND c.applied_revision = ?6
                   AND c.last_report_generation = ?7
                   AND revision.schema_version = 2
                   AND json_type(
                       revision.artifact_json, '$.document.xray.publicPort'
                   ) = 'integer'
                   AND json_extract(
                       revision.artifact_json, '$.document.xray.publicPort'
                   ) = c.port
                   AND c.withdrawn_at IS NULL
                   AND (c.expires_at IS NULL OR c.expires_at > ?8)
                   AND verification.status != 'withdrawn'
                   AND n.status = 'active' AND n.runtime_state = 'serving'
                   AND n.provider_paused = 0
                   AND n.applied_revision = ?6
                   AND n.last_heartbeat_generation = ?7
             )",
            params![
                job.network_id.to_string(),
                job.node_id.to_string(),
                job.endpoint_id.to_string(),
                job.address,
                i64::from(job.port),
                job.applied_revision.get(),
                job.candidate_generation,
                now,
            ],
            |row| row.get(0),
        )
        .map_err(DatabaseError::from)
}

fn prepare_probe_result(result: &TcpProbeResult) -> Result<ProbeTerminalResult, DatabaseError> {
    match result {
        TcpProbeResult::Connected {
            resolved_address,
            latency,
        } => Ok(ProbeTerminalResult {
            status: "succeeded",
            resolved_address: Some(resolved_address.to_string()),
            latency_ms: Some(probe_duration_millis(*latency)?),
            result_code: "direct_tcp_connected",
        }),
        TcpProbeResult::Failed {
            code,
            resolved_address,
            latency,
        } => Ok(ProbeTerminalResult {
            status: "failed",
            resolved_address: resolved_address.map(|address| address.to_string()),
            latency_ms: latency.map(probe_duration_millis).transpose()?,
            result_code: code.as_str(),
        }),
    }
}

fn finish_probe_attempt(
    transaction: &rusqlite::Transaction<'_>,
    job: &TcpProbeJob,
    result: &ProbeTerminalResult,
    now: i64,
) -> Result<(), DatabaseError> {
    let updated = transaction.execute(
        "UPDATE endpoint_probe_attempts
         SET status = ?1, completed_at = ?2, resolved_address = ?3,
             latency_ms = ?4, result_code = ?5
         WHERE network_id = ?6 AND probe_id = ?7 AND status = 'claimed'",
        params![
            result.status,
            now,
            result.resolved_address.as_deref(),
            result.latency_ms,
            result.result_code,
            job.network_id.to_string(),
            job.probe_id.to_string(),
        ],
    )?;
    if updated == 1 {
        Ok(())
    } else {
        Err(DatabaseError::ProbeClaimConflict)
    }
}

fn probe_duration_seconds(duration: std::time::Duration) -> Result<i64, DatabaseError> {
    let seconds =
        i64::try_from(duration.as_secs()).map_err(|_| DatabaseError::InvalidProbeSchedule)?;
    if seconds == 0 {
        return Err(DatabaseError::InvalidProbeSchedule);
    }
    Ok(seconds)
}

fn probe_duration_millis(duration: std::time::Duration) -> Result<i64, DatabaseError> {
    i64::try_from(duration.as_millis()).map_err(|_| DatabaseError::ProbeResultOverflow)
}

fn record_endpoint_candidates(
    transaction: &rusqlite::Transaction<'_>,
    network_id: &str,
    node_id: NodeId,
    heartbeat: &NodeHeartbeat,
    report_generation: i64,
    now: i64,
) -> Result<(), DatabaseError> {
    let node_id = node_id.to_string();
    let mut new_candidates = Vec::new();
    for candidate in &heartbeat.endpoints {
        validate_endpoint_candidate_revision(transaction, network_id, &node_id, candidate)?;
        let prepared = PreparedEndpointCandidate::new(candidate)?;
        if !refresh_endpoint_candidate(
            transaction,
            network_id,
            &node_id,
            &prepared,
            report_generation,
            now,
        )? {
            new_candidates.push(prepared);
        }
    }

    withdraw_missing_candidates(transaction, network_id, &node_id, report_generation, now)?;

    for candidate in new_candidates {
        insert_endpoint_candidate(
            transaction,
            network_id,
            &node_id,
            &candidate,
            report_generation,
            now,
        )?;
    }
    Ok(())
}

fn validate_endpoint_candidate_revision(
    transaction: &rusqlite::Transaction<'_>,
    network_id: &str,
    node_id: &str,
    candidate: &EndpointCandidate,
) -> Result<(), DatabaseError> {
    if candidate.mode != EndpointMode::Direct {
        return Ok(());
    }
    let public_port = transaction
        .query_row(
            "SELECT CASE
                 WHEN schema_version = 2
                  AND json_type(artifact_json, '$.document.xray.publicPort') = 'integer'
                 THEN json_extract(artifact_json, '$.document.xray.publicPort')
             END
             FROM config_revisions
             WHERE network_id = ?1 AND node_id = ?2 AND revision = ?3",
            params![network_id, node_id, candidate.applied_revision.get()],
            |row| row.get::<_, Option<i64>>(0),
        )
        .optional()?
        .flatten();
    if public_port == Some(i64::from(candidate.port)) {
        Ok(())
    } else {
        Err(DatabaseError::EndpointCandidateRevisionConflict)
    }
}

struct PreparedEndpointCandidate<'a> {
    candidate: &'a EndpointCandidate,
    mode: String,
    source: String,
    observed_at: i64,
    expires_at: Option<i64>,
}

impl<'a> PreparedEndpointCandidate<'a> {
    fn new(candidate: &'a EndpointCandidate) -> Result<Self, DatabaseError> {
        Ok(Self {
            candidate,
            mode: enum_wire(&candidate.mode)?,
            source: enum_wire(&candidate.source)?,
            observed_at: candidate.observed_at.as_datetime().unix_timestamp(),
            expires_at: candidate
                .expires_at
                .map(|value| value.as_datetime().unix_timestamp()),
        })
    }
}

fn refresh_endpoint_candidate(
    transaction: &rusqlite::Transaction<'_>,
    network_id: &str,
    node_id: &str,
    prepared: &PreparedEndpointCandidate<'_>,
    report_generation: i64,
    now: i64,
) -> Result<bool, DatabaseError> {
    let candidate = prepared.candidate;
    let stored = transaction
        .query_row(
            "SELECT mode, source, address, port, applied_revision,
                    observed_at, expires_at, withdrawn_at
             FROM node_endpoint_candidates
             WHERE network_id = ?1 AND node_id = ?2 AND endpoint_id = ?3",
            params![network_id, node_id, candidate.endpoint_id.to_string()],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, i64>(5)?,
                    row.get::<_, Option<i64>>(6)?,
                    row.get::<_, Option<i64>>(7)?,
                ))
            },
        )
        .optional()?;
    let Some(stored) = stored else {
        return Ok(false);
    };
    let unchanged = stored.0 == prepared.mode
        && stored.1 == prepared.source
        && stored.2 == candidate.address
        && stored.3 == i64::from(candidate.port)
        && stored.4 == candidate.applied_revision.get()
        && stored.5 == prepared.observed_at
        && stored.6 == prepared.expires_at
        && stored.7.is_none();
    if !unchanged {
        return Err(DatabaseError::EndpointCandidateConflict);
    }
    transaction.execute(
        "UPDATE node_endpoint_candidates
         SET last_report_generation = ?1, last_reported_at = ?2
         WHERE network_id = ?3 AND node_id = ?4 AND endpoint_id = ?5
           AND withdrawn_at IS NULL",
        params![
            report_generation,
            now,
            network_id,
            node_id,
            candidate.endpoint_id.to_string(),
        ],
    )?;
    Ok(true)
}

fn withdraw_missing_candidates(
    transaction: &rusqlite::Transaction<'_>,
    network_id: &str,
    node_id: &str,
    report_generation: i64,
    now: i64,
) -> Result<(), DatabaseError> {
    transaction.execute(
        "UPDATE node_endpoint_candidates
         SET withdrawn_at = ?1
         WHERE network_id = ?2 AND node_id = ?3 AND withdrawn_at IS NULL
           AND last_report_generation < ?4",
        params![now, network_id, node_id, report_generation],
    )?;
    transaction.execute(
        "UPDATE node_endpoint_verifications
         SET status = 'withdrawn', updated_at = ?1
         WHERE network_id = ?2 AND node_id = ?3 AND status != 'withdrawn'
           AND endpoint_id IN (
               SELECT endpoint_id FROM node_endpoint_candidates
               WHERE network_id = ?2 AND node_id = ?3 AND withdrawn_at IS NOT NULL
           )",
        params![now, network_id, node_id],
    )?;
    Ok(())
}

fn insert_endpoint_candidate(
    transaction: &rusqlite::Transaction<'_>,
    network_id: &str,
    node_id: &str,
    prepared: &PreparedEndpointCandidate<'_>,
    report_generation: i64,
    now: i64,
) -> Result<(), DatabaseError> {
    let candidate = prepared.candidate;
    transaction.execute(
        "INSERT INTO node_endpoint_candidates(
            network_id, node_id, endpoint_id, mode, source, address, port,
            applied_revision, observed_at, expires_at, last_report_generation,
            first_reported_at, last_reported_at, withdrawn_at
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?12, NULL)",
        params![
            network_id,
            node_id,
            candidate.endpoint_id.to_string(),
            prepared.mode,
            prepared.source,
            candidate.address,
            i64::from(candidate.port),
            candidate.applied_revision.get(),
            prepared.observed_at,
            prepared.expires_at,
            report_generation,
            now,
        ],
    )?;
    transaction.execute(
        "INSERT INTO node_endpoint_verifications(
            network_id, node_id, endpoint_id, status, probe_attempts, updated_at
         ) VALUES (?1, ?2, ?3, 'pending', 0, ?4)",
        params![network_id, node_id, candidate.endpoint_id.to_string(), now],
    )?;
    Ok(())
}

fn validate_reported_progress(
    transaction: &rusqlite::Transaction<'_>,
    network_id: &str,
    node_id: NodeId,
    heartbeat: &NodeHeartbeat,
) -> Result<(), DatabaseError> {
    struct ReportedProgressRecord {
        status: String,
        target: Option<i64>,
        reported_target: Option<i64>,
        received: Option<i64>,
        validated: Option<i64>,
        applied: Option<i64>,
        telemetry_cursor: i64,
    }

    let previous = transaction
        .query_row(
            "SELECT status, desired_revision, reported_desired_revision,
                    received_revision, validated_revision, applied_revision,
                    telemetry_cursor
             FROM nodes WHERE network_id = ?1 AND node_id = ?2",
            params![network_id, node_id.to_string()],
            |row| {
                Ok(ReportedProgressRecord {
                    status: row.get(0)?,
                    target: row.get(1)?,
                    reported_target: row.get(2)?,
                    received: row.get(3)?,
                    validated: row.get(4)?,
                    applied: row.get(5)?,
                    telemetry_cursor: row.get(6)?,
                })
            },
        )
        .optional()?
        .ok_or(DatabaseError::NodeRevoked)?;
    if !matches!(previous.status.as_str(), "pending" | "active") {
        return Err(DatabaseError::NodeRevoked);
    }
    let reported_desired = heartbeat.revisions.desired_revision.map(Revision::get);
    validate_reported_desired_revision(
        transaction,
        network_id,
        node_id,
        previous.target,
        previous.reported_target,
        reported_desired,
    )?;
    for (authoritative, reported) in [
        (
            previous.received,
            heartbeat.revisions.received_revision.map(Revision::get),
        ),
        (
            previous.validated,
            heartbeat.revisions.validated_revision.map(Revision::get),
        ),
        (
            previous.applied,
            heartbeat.revisions.applied_revision.map(Revision::get),
        ),
    ] {
        ensure_authoritative_progress(authoritative, reported)?;
    }
    if heartbeat.telemetry_cursor.get() < previous.telemetry_cursor {
        return Err(DatabaseError::NodeProgressRegressed);
    }
    Ok(())
}

fn validate_reported_desired_revision(
    transaction: &rusqlite::Transaction<'_>,
    network_id: &str,
    node_id: NodeId,
    target: Option<i64>,
    previous_reported: Option<i64>,
    reported: Option<i64>,
) -> Result<(), DatabaseError> {
    ensure_monotonic_cursor(previous_reported, reported)?;
    let Some(reported) = reported else {
        return Ok(());
    };
    if match target {
        Some(target) => reported > target,
        None => true,
    } {
        return Err(DatabaseError::NodeProgressConflict);
    }
    let targeted = transaction.query_row(
        "SELECT EXISTS(
            SELECT 1 FROM node_revision_targets
            WHERE network_id = ?1 AND node_id = ?2 AND revision = ?3
         )",
        params![network_id, node_id.to_string(), reported],
        |row| row.get::<_, bool>(0),
    )?;
    if !targeted {
        return Err(DatabaseError::NodeProgressConflict);
    }
    Ok(())
}

fn ensure_authoritative_progress(
    authoritative: Option<i64>,
    reported: Option<i64>,
) -> Result<(), DatabaseError> {
    if authoritative == reported {
        return Ok(());
    }
    match (authoritative, reported) {
        (Some(_), None) => Err(DatabaseError::NodeProgressRegressed),
        (Some(authoritative), Some(reported)) if reported < authoritative => {
            Err(DatabaseError::NodeProgressRegressed)
        }
        _ => Err(DatabaseError::NodeProgressConflict),
    }
}

fn publish_desired_state(
    connection: &mut Connection,
    identity: &ControllerIdentity,
    node_id: NodeId,
    configuration: DesiredStateConfigurationDraft,
) -> Result<SignedDesiredState, DatabaseError> {
    let now = unix_timestamp()?;
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let mut network = load_network(&transaction)?;
    let node_id_text = node_id.to_string();
    let node_status = transaction
        .query_row(
            "SELECT status FROM nodes WHERE network_id = ?1 AND node_id = ?2",
            params![network.network_id, node_id_text],
            |row| row.get::<_, String>(0),
        )
        .optional()?
        .ok_or(DatabaseError::NodeNotFound)?;
    if node_status != "active" {
        insert_audit_event(
            &transaction,
            Some(&network.network_id),
            "admin",
            None,
            "node.desired-state-publication-rejected",
            "node",
            Some(&node_id_text),
            "rejected",
            &serde_json::json!({ "nodeStatus": node_status }),
            now,
        )?;
        transaction.commit()?;
        return Err(DatabaseError::DesiredStatePublicationConflict {
            current_status: node_status,
        });
    }

    let users = compile_desired_users(&transaction, &network.network_id, node_id)?;
    let desired = publish_compiled_desired_state(
        &transaction,
        identity,
        &mut network,
        node_id,
        configuration,
        &users,
        "operator-configuration",
        now,
    )?;
    transaction.commit()?;
    Ok(desired)
}

fn reconcile_node_desired_state(
    connection: &mut Connection,
    identity: &ControllerIdentity,
    node_id: NodeId,
) -> Result<DesiredStateReconcileResult, DatabaseError> {
    let now = unix_timestamp()?;
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let mut network = load_network(&transaction)?;
    let current = load_latest_node_desired(&transaction, identity, &network, node_id)?;
    let users = compile_desired_users(&transaction, &network.network_id, node_id)?;
    let mut expected_users = users
        .iter()
        .map(|compiled| compiled.user.clone())
        .collect::<Vec<_>>();
    expected_users.sort_by(|left, right| {
        left.user_id
            .cmp(&right.user_id)
            .then_with(|| left.credential_id.cmp(&right.credential_id))
    });
    let revision = current.document.revision;
    let member_snapshot_matches =
        member_snapshot_matches(&transaction, &network.network_id, node_id, revision, &users)?;
    let terminal_failure = transaction.query_row(
        "SELECT EXISTS(
            SELECT 1 FROM node_revision_results
            WHERE network_id = ?1 AND node_id = ?2 AND revision = ?3
              AND state IN ('rejected', 'rolledBack')
         )",
        params![network.network_id, node_id.to_string(), revision.get()],
        |row| row.get::<_, bool>(0),
    )?;
    if current.document.users == expected_users && member_snapshot_matches && !terminal_failure {
        insert_audit_event(
            &transaction,
            Some(&network.network_id),
            "bootstrap-admin",
            None,
            "node.desired-state-reconciled",
            "node",
            Some(&node_id.to_string()),
            "success",
            &serde_json::json!({ "created": false, "revision": revision }),
            now,
        )?;
        transaction.commit()?;
        return Ok(DesiredStateReconcileResult {
            desired: current,
            created: false,
        });
    }

    let configuration = DesiredStateConfigurationDraft {
        min_agent_version: current.document.min_agent_version,
        xray: current.document.xray,
    };
    let desired = publish_compiled_desired_state(
        &transaction,
        identity,
        &mut network,
        node_id,
        configuration,
        &users,
        "operator-reconcile",
        now,
    )?;
    transaction.commit()?;
    Ok(DesiredStateReconcileResult {
        desired,
        created: true,
    })
}

fn member_snapshot_matches(
    connection: &Connection,
    network_id: &str,
    node_id: NodeId,
    revision: Revision,
    users: &[CompiledDesiredUser],
) -> Result<bool, DatabaseError> {
    let marker_exists = connection.query_row(
        "SELECT EXISTS(
            SELECT 1 FROM node_revision_member_snapshots
            WHERE network_id = ?1 AND node_id = ?2 AND revision = ?3
         )",
        params![network_id, node_id.to_string(), revision.get()],
        |row| row.get::<_, bool>(0),
    )?;
    if !marker_exists {
        return Ok(false);
    }
    let mut statement = connection.prepare(
        "SELECT credential_id FROM node_revision_member_credentials
         WHERE network_id = ?1 AND node_id = ?2 AND revision = ?3
         ORDER BY credential_id",
    )?;
    let stored = statement
        .query_map(
            params![network_id, node_id.to_string(), revision.get()],
            |row| row.get::<_, String>(0),
        )?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    let mut expected = users
        .iter()
        .map(|compiled| compiled.user.credential_id.to_string())
        .collect::<Vec<_>>();
    expected.sort();
    Ok(stored == expected)
}

#[derive(Clone)]
struct CompiledDesiredUser {
    assignment_id: AssignmentId,
    user: DesiredUser,
}

#[allow(clippy::too_many_arguments)]
fn publish_compiled_desired_state(
    transaction: &rusqlite::Transaction<'_>,
    identity: &ControllerIdentity,
    network: &mut NetworkRecord,
    node_id: NodeId,
    configuration: DesiredStateConfigurationDraft,
    users: &[CompiledDesiredUser],
    reason: &'static str,
    now: i64,
) -> Result<SignedDesiredState, DatabaseError> {
    let next_revision = network
        .last_revision
        .checked_add(1)
        .and_then(|value| Revision::new(value).ok())
        .ok_or(DatabaseError::RevisionOverflow)?;
    let network_id = network
        .network_id
        .parse::<NetworkId>()
        .map_err(|_| DatabaseError::StoredProtocolValue)?;
    let controller_instance_id = network
        .controller_epoch
        .parse::<ControllerInstanceId>()
        .map_err(|_| DatabaseError::StoredProtocolValue)?;
    let artifact = build_signed_desired_state(
        identity,
        network_id,
        node_id,
        next_revision,
        timestamp(now)?,
        controller_instance_id,
        configuration.with_users(users.iter().map(|user| user.user.clone()).collect()),
    )
    .map_err(map_desired_state_publication_error)?;
    let node_id_text = node_id.to_string();
    insert_desired_revision(transaction, network, &node_id_text, &artifact, now)?;
    insert_member_revision_snapshot(
        transaction,
        &network.network_id,
        node_id,
        next_revision,
        users,
        now,
    )?;

    let revision = next_revision.get();
    let node_updated = transaction.execute(
        "UPDATE nodes SET desired_revision = ?1, updated_at = ?2
         WHERE network_id = ?3 AND node_id = ?4 AND status = 'active'",
        params![revision, now, network.network_id, node_id_text],
    )?;
    let network_updated = transaction.execute(
        "UPDATE networks SET last_revision = ?1, updated_at = ?2
         WHERE network_id = ?3 AND last_revision = ?4",
        params![revision, now, network.network_id, network.last_revision],
    )?;
    if node_updated != 1 || network_updated != 1 {
        let node_status = transaction
            .query_row(
                "SELECT status FROM nodes WHERE network_id = ?1 AND node_id = ?2",
                params![network.network_id, node_id_text],
                |row| row.get::<_, String>(0),
            )
            .optional()?
            .unwrap_or_else(|| "missing".to_string());
        return Err(DatabaseError::DesiredStatePublicationConflict {
            current_status: node_status,
        });
    }
    insert_audit_event(
        transaction,
        Some(&network.network_id),
        "admin",
        None,
        "node.desired-state-published",
        "node",
        Some(&node_id_text),
        "success",
        &serde_json::json!({
            "parentRevision": (revision > 1).then_some(revision - 1),
            "reason": reason,
            "revision": revision,
            "schemaVersion": artifact.envelope.document.schema_version,
            "userCount": users.len(),
        }),
        now,
    )?;
    network.last_revision = revision;
    network.updated_at = now;
    Ok(artifact.envelope)
}

fn compile_desired_users(
    connection: &Connection,
    network_id: &str,
    node_id: NodeId,
) -> Result<Vec<CompiledDesiredUser>, DatabaseError> {
    let mut statement = connection.prepare(
        "SELECT credential.credential_id, credential.assignment_id,
                credential.user_id, credential.vless_uuid
         FROM user_node_credentials AS credential
         JOIN user_node_assignments AS assignment
           ON assignment.network_id = credential.network_id
          AND assignment.assignment_id = credential.assignment_id
         JOIN users AS account
           ON account.network_id = credential.network_id
          AND account.user_id = credential.user_id
         WHERE credential.network_id = ?1 AND credential.node_id = ?2
           AND credential.status IN ('pending', 'active')
           AND assignment.status = 'enabled' AND account.status = 'active'
         ORDER BY credential.user_id, credential.version DESC",
    )?;
    let rows = statement.query_map(params![network_id, node_id.to_string()], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, String>(3)?,
        ))
    })?;
    let mut users = Vec::new();
    let mut user_ids = BTreeSet::new();
    let mut assignment_ids = BTreeSet::new();
    for row in rows {
        let (credential_id, assignment_id, user_id, vless_uuid) = row?;
        let credential_id = credential_id
            .parse::<CredentialId>()
            .map_err(|_| DatabaseError::StoredProtocolValue)?;
        let assignment_id = assignment_id
            .parse::<AssignmentId>()
            .map_err(|_| DatabaseError::StoredProtocolValue)?;
        let user_id = user_id
            .parse::<UserId>()
            .map_err(|_| DatabaseError::StoredProtocolValue)?;
        if !user_ids.insert(user_id) || !assignment_ids.insert(assignment_id) {
            return Err(DatabaseError::StoredProtocolValue);
        }
        users.push(CompiledDesiredUser {
            assignment_id,
            user: DesiredUser {
                user_id,
                credential_id,
                vless_uuid: Secret::new(vless_uuid),
                enabled: true,
            },
        });
    }
    Ok(users)
}

fn insert_member_revision_snapshot(
    connection: &Connection,
    network_id: &str,
    node_id: NodeId,
    revision: Revision,
    users: &[CompiledDesiredUser],
    now: i64,
) -> Result<(), DatabaseError> {
    connection.execute(
        "INSERT INTO node_revision_member_snapshots(network_id, node_id, revision, created_at)
         VALUES (?1, ?2, ?3, ?4)",
        params![network_id, node_id.to_string(), revision.get(), now],
    )?;
    for user in users {
        connection.execute(
            "INSERT INTO node_revision_member_credentials(
                network_id, node_id, revision, credential_id, assignment_id, user_id
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                network_id,
                node_id.to_string(),
                revision.get(),
                user.user.credential_id.to_string(),
                user.assignment_id.to_string(),
                user.user.user_id.to_string(),
            ],
        )?;
    }
    Ok(())
}

fn publish_account_revisions(
    transaction: &rusqlite::Transaction<'_>,
    identity: &ControllerIdentity,
    network: &mut NetworkRecord,
    node_ids: &BTreeSet<NodeId>,
    reason: &'static str,
    now: i64,
) -> Result<Vec<(NodeId, Revision)>, DatabaseError> {
    let mut revisions = Vec::with_capacity(node_ids.len());
    for node_id in node_ids {
        let configuration =
            load_node_desired_configuration(transaction, identity, network, *node_id)?;
        let users = compile_desired_users(transaction, &network.network_id, *node_id)?;
        let desired = publish_compiled_desired_state(
            transaction,
            identity,
            network,
            *node_id,
            configuration,
            &users,
            reason,
            now,
        )?;
        revisions.push((*node_id, desired.document.revision));
    }
    Ok(revisions)
}

fn load_node_desired_configuration(
    connection: &Connection,
    identity: &ControllerIdentity,
    network: &NetworkRecord,
    node_id: NodeId,
) -> Result<DesiredStateConfigurationDraft, DatabaseError> {
    let desired = load_latest_node_desired(connection, identity, network, node_id)?;
    Ok(DesiredStateConfigurationDraft {
        min_agent_version: desired.document.min_agent_version,
        xray: desired.document.xray,
    })
}

fn load_latest_node_desired(
    connection: &Connection,
    identity: &ControllerIdentity,
    network: &NetworkRecord,
    node_id: NodeId,
) -> Result<SignedDesiredState, DatabaseError> {
    let node_id_text = node_id.to_string();
    let (status, desired_revision) = connection
        .query_row(
            "SELECT status, desired_revision FROM nodes
             WHERE network_id = ?1 AND node_id = ?2",
            params![network.network_id, node_id_text],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, Option<i64>>(1)?)),
        )
        .optional()?
        .ok_or(DatabaseError::NodeNotFound)?;
    if status != "active" {
        return Err(DatabaseError::DesiredStatePublicationConflict {
            current_status: status,
        });
    }
    let desired_revision = desired_revision.ok_or(DatabaseError::NodeConfigurationMissing)?;
    let stored = load_stored_desired_revision(
        connection,
        &network.network_id,
        &node_id_text,
        desired_revision,
    )?
    .ok_or(DatabaseError::StoredDesiredStateCorrupt)?;
    verify_desired_revision(identity, network, node_id, &stored)
}

fn load_publishable_account_nodes(
    connection: &Connection,
    network_id: &str,
    user_id: UserId,
) -> Result<BTreeSet<NodeId>, DatabaseError> {
    let mut statement = connection.prepare(
        "SELECT assignment.node_id
         FROM user_node_assignments AS assignment
         JOIN nodes AS node
           ON node.network_id = assignment.network_id
          AND node.node_id = assignment.node_id
         WHERE assignment.network_id = ?1 AND assignment.user_id = ?2
           AND assignment.status = 'enabled' AND node.status = 'active'",
    )?;
    let node_ids = statement
        .query_map(params![network_id, user_id.to_string()], |row| {
            row.get::<_, String>(0)
        })?
        .map(|row| {
            row?.parse::<NodeId>()
                .map_err(|_| DatabaseError::StoredProtocolValue)
        })
        .collect();
    node_ids
}

fn revision_audit_details(revisions: &[(NodeId, Revision)]) -> Vec<serde_json::Value> {
    revisions
        .iter()
        .map(|(node_id, revision)| serde_json::json!({ "nodeId": node_id, "revision": revision }))
        .collect()
}

fn insert_desired_revision(
    transaction: &rusqlite::Transaction<'_>,
    network: &NetworkRecord,
    node_id: &str,
    artifact: &crate::desired::PublishedDesiredState,
    now: i64,
) -> Result<(), DatabaseError> {
    let document = &artifact.envelope.document;
    let revision = document.revision.get();
    transaction.execute(
        "INSERT INTO config_revisions(
            network_id, revision, parent_revision, schema_version, node_id,
            artifact_json, artifact_sha256, transcript_sha256, signature,
            signing_key_id, controller_instance_id, created_at
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
        params![
            network.network_id,
            revision,
            (revision > 1).then_some(revision - 1),
            i64::from(document.schema_version),
            node_id,
            artifact.artifact_json,
            artifact.artifact_digest.as_str(),
            artifact.transcript_digest.as_str(),
            artifact.envelope.signature.as_str(),
            document.signing_key_id.to_string(),
            document.controller_instance_id.to_string(),
            now,
        ],
    )?;
    transaction.execute(
        "INSERT INTO node_revision_targets(network_id, node_id, revision, created_at)
         VALUES (?1, ?2, ?3, ?4)",
        params![network.network_id, node_id, revision, now],
    )?;
    Ok(())
}

fn map_desired_state_publication_error(error: DesiredStateError) -> DatabaseError {
    match error {
        DesiredStateError::Validation(error) => DatabaseError::Validation(error),
        error => DatabaseError::DesiredState(error),
    }
}

struct StoredDesiredRevision {
    schema_version: i64,
    node_id: String,
    revision: i64,
    artifact_json: String,
    artifact_digest: String,
    transcript_digest: String,
    signature: String,
    signing_key_id: String,
    controller_instance_id: String,
    created_at: i64,
}

fn desired_state_after(
    connection: &Connection,
    identity: &ControllerIdentity,
    node_id: NodeId,
    after_revision: i64,
) -> Result<Option<SignedDesiredState>, DatabaseError> {
    let network = load_network(connection)?;
    let node_id_text = node_id.to_string();
    let desired_revision = connection
        .query_row(
            "SELECT desired_revision FROM nodes
             WHERE network_id = ?1 AND node_id = ?2 AND status IN ('pending', 'active')",
            params![network.network_id, node_id_text],
            |row| row.get::<_, Option<i64>>(0),
        )
        .optional()?
        .ok_or(DatabaseError::NodeRevoked)?;
    let Some(desired_revision) = desired_revision.filter(|value| *value > after_revision) else {
        return Ok(None);
    };
    let stored = load_stored_desired_revision(
        connection,
        &network.network_id,
        &node_id_text,
        desired_revision,
    )?
    .ok_or(DatabaseError::StoredDesiredStateCorrupt)?;
    verify_desired_revision(identity, &network, node_id, &stored).map(Some)
}

fn load_stored_desired_revision(
    connection: &Connection,
    network_id: &str,
    node_id: &str,
    revision: i64,
) -> Result<Option<StoredDesiredRevision>, DatabaseError> {
    connection
        .query_row(
            "SELECT c.schema_version, c.node_id, c.revision, c.artifact_json,
                    c.artifact_sha256, c.transcript_sha256, c.signature,
                    c.signing_key_id, c.controller_instance_id, c.created_at
             FROM node_revision_targets AS t
             JOIN config_revisions AS c
               ON c.network_id = t.network_id AND c.revision = t.revision
              AND c.node_id = t.node_id
             WHERE t.network_id = ?1 AND t.node_id = ?2 AND t.revision = ?3",
            params![network_id, node_id, revision],
            |row| {
                Ok(StoredDesiredRevision {
                    schema_version: row.get(0)?,
                    node_id: row.get(1)?,
                    revision: row.get(2)?,
                    artifact_json: row.get(3)?,
                    artifact_digest: row.get(4)?,
                    transcript_digest: row.get(5)?,
                    signature: row.get(6)?,
                    signing_key_id: row.get(7)?,
                    controller_instance_id: row.get(8)?,
                    created_at: row.get(9)?,
                })
            },
        )
        .optional()
        .map_err(DatabaseError::from)
}

fn verify_desired_revision(
    identity: &ControllerIdentity,
    network: &NetworkRecord,
    node_id: NodeId,
    stored: &StoredDesiredRevision,
) -> Result<SignedDesiredState, DatabaseError> {
    let stored_schema_version = u16::try_from(stored.schema_version)
        .map_err(|_| DatabaseError::StoredDesiredStateCorrupt)?;
    if !SUPPORTED_DESIRED_STATE_SCHEMA_VERSIONS.contains(&stored_schema_version)
        || stored.node_id != node_id.to_string()
        || stored.controller_instance_id != network.controller_epoch
    {
        return Err(DatabaseError::StoredDesiredStateCorrupt);
    }
    let network_id = network
        .network_id
        .parse::<NetworkId>()
        .map_err(|_| DatabaseError::StoredProtocolValue)?;
    let revision =
        Revision::new(stored.revision).map_err(|_| DatabaseError::StoredDesiredStateCorrupt)?;
    let controller_instance_id = stored
        .controller_instance_id
        .parse::<ControllerInstanceId>()
        .map_err(|_| DatabaseError::StoredDesiredStateCorrupt)?;
    let signing_key_id = stored
        .signing_key_id
        .parse::<SigningKeyId>()
        .map_err(|_| DatabaseError::StoredDesiredStateCorrupt)?;
    verify_stored_desired_state(
        identity,
        &StoredDesiredState {
            schema_version: stored_schema_version,
            network_id,
            node_id,
            revision,
            created_at: timestamp(stored.created_at)?,
            controller_instance_id,
            signing_key_id,
            artifact_json: &stored.artifact_json,
            artifact_digest: &stored.artifact_digest,
            transcript_digest: &stored.transcript_digest,
            signature: &stored.signature,
        },
    )
    .map_err(DatabaseError::DesiredState)
}

fn record_revision_result(
    connection: &mut Connection,
    node_id: NodeId,
    revision: Revision,
    result: &RevisionResult,
) -> Result<(), DatabaseError> {
    result.validate(revision)?;
    let now = unix_timestamp()?;
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let network = load_network(&transaction)?;
    validate_result_target(&transaction, &network.network_id, node_id, revision)?;
    let previous =
        load_latest_revision_result(&transaction, &network.network_id, node_id, revision)?;
    result
        .validate_transition_from(previous.as_ref())
        .map_err(|_| DatabaseError::RevisionResultConflict)?;
    if previous.as_ref() == Some(result) {
        transaction.commit()?;
        return Ok(());
    }
    validate_result_dependencies(&transaction, &network.network_id, node_id, revision, result)?;
    append_revision_result(
        &transaction,
        &network.network_id,
        node_id,
        revision,
        result,
        now,
    )?;
    update_revision_progress_cache(
        &transaction,
        &network.network_id,
        node_id,
        revision,
        result,
        now,
    )?;
    if matches!(
        result.state,
        RevisionResultState::Applied | RevisionResultState::RolledBack
    ) {
        reconcile_applied_member_credentials(&transaction, &network.network_id, node_id, now)?;
    }
    transaction.commit()?;
    Ok(())
}

fn reconcile_applied_member_credentials(
    transaction: &rusqlite::Transaction<'_>,
    network_id: &str,
    node_id: NodeId,
    now: i64,
) -> Result<(), DatabaseError> {
    let node_id_text = node_id.to_string();
    let applied_revision = transaction
        .query_row(
            "SELECT applied_revision FROM nodes WHERE network_id = ?1 AND node_id = ?2",
            params![network_id, node_id_text],
            |row| row.get::<_, Option<i64>>(0),
        )?
        .ok_or(DatabaseError::RevisionResultConflict)?;
    let has_authoritative_snapshot = transaction.query_row(
        "SELECT EXISTS(
            SELECT 1 FROM node_revision_member_snapshots
            WHERE network_id = ?1 AND node_id = ?2 AND revision = ?3
         )",
        params![network_id, node_id_text, applied_revision],
        |row| row.get::<_, bool>(0),
    )?;
    if !has_authoritative_snapshot {
        return Ok(());
    }

    let activated = transaction.execute(
        "UPDATE user_node_credentials AS credential
         SET status = 'active', activated_at = COALESCE(activated_at, ?1)
         WHERE credential.network_id = ?2 AND credential.node_id = ?3
           AND credential.status = 'pending' AND EXISTS(
                SELECT 1 FROM node_revision_member_credentials AS snapshot
                WHERE snapshot.network_id = credential.network_id
                  AND snapshot.node_id = credential.node_id
                  AND snapshot.revision = ?4
                  AND snapshot.credential_id = credential.credential_id
           )",
        params![now, network_id, node_id_text, applied_revision],
    )?;
    let revoked = transaction.execute(
        "UPDATE user_node_credentials AS credential
         SET status = 'revoked', revoked_at = ?1, retire_after = NULL
         WHERE credential.network_id = ?2 AND credential.node_id = ?3
           AND credential.status IN ('active', 'retiring') AND NOT EXISTS(
                SELECT 1 FROM node_revision_member_credentials AS snapshot
                WHERE snapshot.network_id = credential.network_id
                  AND snapshot.node_id = credential.node_id
                  AND snapshot.revision = ?4
                  AND snapshot.credential_id = credential.credential_id
           )",
        params![now, network_id, node_id_text, applied_revision],
    )?;
    let policy_violations: i64 = transaction.query_row(
        "SELECT COUNT(*)
         FROM node_revision_member_credentials AS snapshot
         JOIN user_node_credentials AS credential
           ON credential.network_id = snapshot.network_id
          AND credential.credential_id = snapshot.credential_id
         JOIN user_node_assignments AS assignment
           ON assignment.network_id = credential.network_id
          AND assignment.assignment_id = credential.assignment_id
         JOIN users AS account
           ON account.network_id = credential.network_id
          AND account.user_id = credential.user_id
         WHERE snapshot.network_id = ?1 AND snapshot.node_id = ?2
           AND snapshot.revision = ?3
           AND (credential.status != 'active' OR assignment.status != 'enabled'
                OR account.status != 'active')",
        params![network_id, node_id_text, applied_revision],
        |row| row.get(0),
    )?;
    insert_audit_event(
        transaction,
        Some(network_id),
        "node",
        Some(&node_id_text),
        "node.member-credentials-reconciled",
        "node",
        Some(&node_id_text),
        "success",
        &serde_json::json!({
            "activated": activated,
            "appliedRevision": applied_revision,
            "policyViolations": policy_violations,
            "revoked": revoked,
        }),
        now,
    )?;
    Ok(())
}

fn validate_result_target(
    transaction: &rusqlite::Transaction<'_>,
    network_id: &str,
    node_id: NodeId,
    revision: Revision,
) -> Result<(), DatabaseError> {
    let desired_revision = transaction
        .query_row(
            "SELECT desired_revision FROM nodes
             WHERE network_id = ?1 AND node_id = ?2 AND status IN ('pending', 'active')",
            params![network_id, node_id.to_string()],
            |row| row.get::<_, Option<i64>>(0),
        )
        .optional()?
        .ok_or(DatabaseError::NodeRevoked)?;
    if desired_revision.is_some_and(|target| revision.get() > target) {
        return Err(DatabaseError::RevisionResultConflict);
    }
    let targeted = transaction.query_row(
        "SELECT EXISTS(
            SELECT 1 FROM node_revision_targets
            WHERE network_id = ?1 AND node_id = ?2 AND revision = ?3
         )",
        params![network_id, node_id.to_string(), revision.get()],
        |row| row.get::<_, bool>(0),
    )?;
    if !targeted {
        return Err(DatabaseError::RevisionTargetNotFound);
    }
    Ok(())
}

fn validate_result_dependencies(
    transaction: &rusqlite::Transaction<'_>,
    network_id: &str,
    node_id: NodeId,
    revision: Revision,
    result: &RevisionResult,
) -> Result<(), DatabaseError> {
    if matches!(
        result.state,
        RevisionResultState::Applied | RevisionResultState::RolledBack
    ) {
        let validated = load_revision_result_state(
            transaction,
            network_id,
            node_id,
            revision,
            RevisionResultState::Validated,
        )?
        .ok_or(DatabaseError::RevisionResultConflict)?;
        if result.state == RevisionResultState::Applied
            && validated.config_digest != result.config_digest
        {
            return Err(DatabaseError::RevisionResultConflict);
        }
    }
    if result.state == RevisionResultState::RolledBack {
        let rollback = result
            .rollback_revision
            .ok_or(DatabaseError::RevisionResultConflict)?;
        let applied = load_revision_result_state(
            transaction,
            network_id,
            node_id,
            rollback,
            RevisionResultState::Applied,
        )?
        .ok_or(DatabaseError::RevisionResultConflict)?;
        if applied.config_digest != result.config_digest {
            return Err(DatabaseError::RevisionResultConflict);
        }
    }
    Ok(())
}

struct StoredRevisionResult {
    state: String,
    state_rank: i64,
    result_json: String,
    config_digest: Option<String>,
    rollback_revision: Option<i64>,
}

fn load_latest_revision_result(
    transaction: &rusqlite::Transaction<'_>,
    network_id: &str,
    node_id: NodeId,
    revision: Revision,
) -> Result<Option<RevisionResult>, DatabaseError> {
    let row = transaction
        .query_row(
            "SELECT state, state_rank, result_json, config_digest, rollback_revision
             FROM node_revision_results
             WHERE network_id = ?1 AND node_id = ?2 AND revision = ?3
             ORDER BY state_rank DESC LIMIT 1",
            params![network_id, node_id.to_string(), revision.get()],
            stored_revision_result,
        )
        .optional()?;
    row.as_ref()
        .map(|row| parse_stored_revision_result(row, revision))
        .transpose()
}

fn load_revision_result_state(
    transaction: &rusqlite::Transaction<'_>,
    network_id: &str,
    node_id: NodeId,
    revision: Revision,
    state: RevisionResultState,
) -> Result<Option<RevisionResult>, DatabaseError> {
    let state = enum_wire(&state)?;
    let row = transaction
        .query_row(
            "SELECT state, state_rank, result_json, config_digest, rollback_revision
             FROM node_revision_results
             WHERE network_id = ?1 AND node_id = ?2 AND revision = ?3 AND state = ?4",
            params![network_id, node_id.to_string(), revision.get(), state],
            stored_revision_result,
        )
        .optional()?;
    row.as_ref()
        .map(|row| parse_stored_revision_result(row, revision))
        .transpose()
}

fn stored_revision_result(row: &rusqlite::Row<'_>) -> rusqlite::Result<StoredRevisionResult> {
    Ok(StoredRevisionResult {
        state: row.get(0)?,
        state_rank: row.get(1)?,
        result_json: row.get(2)?,
        config_digest: row.get(3)?,
        rollback_revision: row.get(4)?,
    })
}

fn parse_stored_revision_result(
    stored: &StoredRevisionResult,
    revision: Revision,
) -> Result<RevisionResult, DatabaseError> {
    let result: RevisionResult = serde_json::from_str(&stored.result_json)
        .map_err(|_| DatabaseError::StoredRevisionResultCorrupt)?;
    result
        .validate(revision)
        .map_err(|_| DatabaseError::StoredRevisionResultCorrupt)?;
    let config_digest = result
        .config_digest
        .as_ref()
        .map(|digest| digest.as_str().to_owned());
    if enum_wire(&result.state)? != stored.state
        || revision_result_rank(result.state) != stored.state_rank
        || config_digest != stored.config_digest
        || result.rollback_revision.map(Revision::get) != stored.rollback_revision
    {
        return Err(DatabaseError::StoredRevisionResultCorrupt);
    }
    Ok(result)
}

fn append_revision_result(
    transaction: &rusqlite::Transaction<'_>,
    network_id: &str,
    node_id: NodeId,
    revision: Revision,
    result: &RevisionResult,
    now: i64,
) -> Result<(), DatabaseError> {
    transaction.execute(
        "INSERT INTO node_revision_results(
            network_id, node_id, revision, state, state_rank, result_json,
            config_digest, rollback_revision, created_at
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        params![
            network_id,
            node_id.to_string(),
            revision.get(),
            enum_wire(&result.state)?,
            revision_result_rank(result.state),
            serde_json::to_string(result)?,
            result.config_digest.as_ref().map(Sha256Digest::as_str),
            result.rollback_revision.map(Revision::get),
            now,
        ],
    )?;
    Ok(())
}

fn update_revision_progress_cache(
    transaction: &rusqlite::Transaction<'_>,
    network_id: &str,
    node_id: NodeId,
    revision: Revision,
    result: &RevisionResult,
    now: i64,
) -> Result<(), DatabaseError> {
    let revision = revision.get();
    transaction.execute(
        "UPDATE nodes
         SET reported_desired_revision = max(COALESCE(reported_desired_revision, 0), ?1),
             received_revision = max(COALESCE(received_revision, 0), ?1),
             updated_at = ?2
         WHERE network_id = ?3 AND node_id = ?4",
        params![revision, now, network_id, node_id.to_string()],
    )?;
    if matches!(
        result.state,
        RevisionResultState::Validated
            | RevisionResultState::Applied
            | RevisionResultState::RolledBack
    ) {
        transaction.execute(
            "UPDATE nodes
             SET validated_revision = max(COALESCE(validated_revision, 0), ?1)
             WHERE network_id = ?2 AND node_id = ?3",
            params![revision, network_id, node_id.to_string()],
        )?;
    }
    match result.state {
        RevisionResultState::Applied => {
            transaction.execute(
                "UPDATE nodes
                 SET applied_revision = max(COALESCE(applied_revision, 0), ?1)
                 WHERE network_id = ?2 AND node_id = ?3",
                params![revision, network_id, node_id.to_string()],
            )?;
        }
        RevisionResultState::RolledBack => {
            let rollback = result
                .rollback_revision
                .ok_or(DatabaseError::RevisionResultConflict)?;
            transaction.execute(
                "UPDATE nodes SET applied_revision = ?1
                 WHERE network_id = ?2 AND node_id = ?3",
                params![rollback.get(), network_id, node_id.to_string()],
            )?;
        }
        RevisionResultState::Received
        | RevisionResultState::Validated
        | RevisionResultState::Rejected => {}
    }
    Ok(())
}

const fn revision_result_rank(state: RevisionResultState) -> i64 {
    match state {
        RevisionResultState::Received => 10,
        RevisionResultState::Validated => 20,
        RevisionResultState::Applied
        | RevisionResultState::Rejected
        | RevisionResultState::RolledBack => 30,
    }
}

fn ensure_monotonic_cursor(
    previous: Option<i64>,
    reported: Option<i64>,
) -> Result<(), DatabaseError> {
    if matches!((previous, reported), (Some(_), None))
        || matches!((previous, reported), (Some(previous), Some(reported)) if reported < previous)
    {
        return Err(DatabaseError::NodeProgressRegressed);
    }
    Ok(())
}

fn enum_wire<T: serde::Serialize>(value: &T) -> Result<String, DatabaseError> {
    serde_json::to_value(value)?
        .as_str()
        .map(ToOwned::to_owned)
        .ok_or(DatabaseError::StoredProtocolValue)
}

fn prepare_parent(path: &Path) -> Result<(), DatabaseError> {
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs::create_dir_all(parent)?;
    }
    Ok(())
}

fn acquire_lock(path: &Path) -> Result<File, DatabaseError> {
    let lock_path = lock_path(path);
    let lock = owner_only_open_options()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(&lock_path)?;
    set_owner_only(&lock_path)?;
    lock.try_lock_exclusive()
        .map_err(|source| DatabaseError::DatabaseLocked { lock_path, source })?;
    Ok(lock)
}

fn prepare_owner_only_file(path: &Path) -> Result<(), DatabaseError> {
    let file = owner_only_open_options()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(path)?;
    file.sync_all()?;
    set_owner_only(path)?;
    Ok(())
}

#[cfg(unix)]
fn owner_only_open_options() -> OpenOptions {
    use std::os::unix::fs::OpenOptionsExt as _;

    let mut options = OpenOptions::new();
    options.mode(0o600);
    options
}

#[cfg(not(unix))]
fn owner_only_open_options() -> OpenOptions {
    OpenOptions::new()
}

fn lock_path(path: &Path) -> PathBuf {
    let mut value = path.as_os_str().to_os_string();
    value.push(".lock");
    PathBuf::from(value)
}

fn configure_connection(connection: &Connection) -> Result<(), DatabaseError> {
    connection.execute_batch(
        "PRAGMA foreign_keys = ON;
         PRAGMA journal_mode = WAL;
         PRAGMA synchronous = FULL;
         PRAGMA busy_timeout = 5000;
         PRAGMA trusted_schema = OFF;
         PRAGMA secure_delete = FAST;",
    )?;
    Ok(())
}

fn validate_application_id(connection: &Connection) -> Result<(), DatabaseError> {
    let current: i64 = connection.query_row("PRAGMA application_id", [], |row| row.get(0))?;
    match current {
        0 => connection.pragma_update(None, "application_id", APPLICATION_ID)?,
        APPLICATION_ID => {}
        actual => {
            return Err(DatabaseError::WrongApplicationId {
                expected: APPLICATION_ID,
                actual,
            });
        }
    }
    Ok(())
}

fn migrate(connection: &mut Connection) -> Result<(), DatabaseError> {
    connection.execute_batch(
        "CREATE TABLE IF NOT EXISTS schema_migrations (
            version INTEGER PRIMARY KEY,
            name TEXT NOT NULL UNIQUE,
            checksum TEXT NOT NULL,
            applied_at INTEGER NOT NULL
        ) STRICT;",
    )?;

    let applied = load_applied_migrations(connection)?;
    let user_version: i64 = connection.query_row("PRAGMA user_version", [], |row| row.get(0))?;
    let highest_applied = applied.keys().next_back().copied().unwrap_or(0);

    if highest_applied > SCHEMA_VERSION || user_version > SCHEMA_VERSION {
        return Err(DatabaseError::SchemaTooNew {
            supported: SCHEMA_VERSION,
            actual: highest_applied.max(user_version),
        });
    }
    if user_version != highest_applied {
        return Err(DatabaseError::MigrationMirrorMismatch {
            source_version: highest_applied,
            user_version,
        });
    }

    for expected_version in 1..=highest_applied {
        if !applied.contains_key(&expected_version) {
            return Err(DatabaseError::MigrationGap {
                version: expected_version,
            });
        }
    }

    let mut current_version = highest_applied;
    for migration in MIGRATIONS {
        let expected_checksum = migration_checksum(migration);
        if let Some((name, checksum)) = applied.get(&migration.version) {
            if name != migration.name || checksum != &expected_checksum {
                return Err(DatabaseError::MigrationChecksumMismatch {
                    version: migration.version,
                });
            }
            continue;
        }

        if migration.version != current_version + 1 {
            return Err(DatabaseError::MigrationGap {
                version: migration.version,
            });
        }

        let transaction = connection.transaction_with_behavior(TransactionBehavior::Exclusive)?;
        transaction.execute_batch(migration.sql)?;
        transaction.execute(
            "INSERT INTO schema_migrations(version, name, checksum, applied_at)
             VALUES (?1, ?2, ?3, ?4)",
            params![
                migration.version,
                migration.name,
                expected_checksum,
                unix_timestamp()?
            ],
        )?;
        transaction.pragma_update(None, "user_version", migration.version)?;
        transaction.commit()?;
        current_version = migration.version;
    }

    Ok(())
}

fn load_applied_migrations(
    connection: &Connection,
) -> Result<BTreeMap<i64, (String, String)>, DatabaseError> {
    let mut statement = connection
        .prepare("SELECT version, name, checksum FROM schema_migrations ORDER BY version ASC")?;
    let rows = statement.query_map([], |row| {
        Ok((
            row.get::<_, i64>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
        ))
    })?;
    let mut applied = BTreeMap::new();
    for row in rows {
        let (version, name, checksum) = row?;
        applied.insert(version, (name, checksum));
    }
    Ok(applied)
}

fn migration_checksum(migration: &Migration) -> String {
    let mut hasher = Sha256::new();
    hasher.update(migration.version.to_be_bytes());
    hasher.update(migration.name.as_bytes());
    hasher.update(migration.sql.as_bytes());
    hasher
        .finalize()
        .iter()
        .fold(String::with_capacity(64), |mut checksum, byte| {
            write!(checksum, "{byte:02x}").expect("writing to a string cannot fail");
            checksum
        })
}

fn bootstrap_network(
    connection: &mut Connection,
    network_display_name: &str,
) -> Result<(), DatabaseError> {
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let count: i64 =
        transaction.query_row("SELECT COUNT(*) FROM networks", [], |row| row.get(0))?;
    match count {
        0 => {
            let now = unix_timestamp()?;
            transaction.execute(
                "INSERT INTO networks(
                    network_id, display_name, status, last_revision, controller_epoch,
                    created_at, updated_at
                 ) VALUES (?1, ?2, 'active', 0, ?3, ?4, ?4)",
                params![
                    Uuid::new_v4().hyphenated().to_string(),
                    network_display_name,
                    Uuid::new_v4().hyphenated().to_string(),
                    now
                ],
            )?;
        }
        1 => {}
        actual => return Err(DatabaseError::MultipleNetworks(actual)),
    }
    transaction.commit()?;
    Ok(())
}

fn load_network(connection: &Connection) -> Result<NetworkRecord, DatabaseError> {
    connection
        .query_row(
            "SELECT network_id, display_name, status, last_revision, controller_epoch,
                    created_at, updated_at
             FROM networks",
            [],
            |row| {
                Ok(NetworkRecord {
                    network_id: row.get(0)?,
                    display_name: row.get(1)?,
                    status: row.get(2)?,
                    last_revision: row.get(3)?,
                    controller_epoch: row.get(4)?,
                    created_at: row.get(5)?,
                    updated_at: row.get(6)?,
                })
            },
        )
        .optional()?
        .ok_or(DatabaseError::NetworkMissing)
}

struct RawNodeSummary {
    node_id: String,
    network_id: String,
    display_name: String,
    status: String,
    platform: String,
    agent_version: String,
    xray_version: Option<String>,
    public_material_ready: i64,
    capabilities_json: String,
    consent_policy_version: String,
    consent_host_owner: i64,
    consent_exit_ip: i64,
    consent_router_mapping: i64,
    consent_accepted_at: i64,
    last_seen_at: Option<i64>,
    runtime_state: Option<String>,
    provider_paused: i64,
    desired_revision: Option<i64>,
    received_revision: Option<i64>,
    validated_revision: Option<i64>,
    applied_revision: Option<i64>,
    telemetry_cursor: i64,
    created_at: i64,
    updated_at: i64,
}

fn load_nodes(connection: &Connection) -> Result<Vec<NodeSummaryRecord>, DatabaseError> {
    let network = load_network(connection)?;
    let mut statement = connection.prepare(
        "SELECT node_id, network_id, display_name, status, platform, agent_version,
                xray_version,
                CASE WHEN reality_public_key IS NOT NULL AND reality_short_id IS NOT NULL
                     THEN 1 ELSE 0 END,
                capabilities_json, consent_policy_version,
                consent_host_owner, consent_exit_ip, consent_router_mapping,
                consent_accepted_at,
                last_seen_at, runtime_state, provider_paused, desired_revision,
                received_revision, validated_revision, applied_revision,
                telemetry_cursor, created_at, updated_at
         FROM nodes
         WHERE network_id = ?1
         ORDER BY created_at ASC, node_id ASC",
    )?;
    let rows = statement.query_map([&network.network_id], |row| {
        Ok(RawNodeSummary {
            node_id: row.get(0)?,
            network_id: row.get(1)?,
            display_name: row.get(2)?,
            status: row.get(3)?,
            platform: row.get(4)?,
            agent_version: row.get(5)?,
            xray_version: row.get(6)?,
            public_material_ready: row.get(7)?,
            capabilities_json: row.get(8)?,
            consent_policy_version: row.get(9)?,
            consent_host_owner: row.get(10)?,
            consent_exit_ip: row.get(11)?,
            consent_router_mapping: row.get(12)?,
            consent_accepted_at: row.get(13)?,
            last_seen_at: row.get(14)?,
            runtime_state: row.get(15)?,
            provider_paused: row.get(16)?,
            desired_revision: row.get(17)?,
            received_revision: row.get(18)?,
            validated_revision: row.get(19)?,
            applied_revision: row.get(20)?,
            telemetry_cursor: row.get(21)?,
            created_at: row.get(22)?,
            updated_at: row.get(23)?,
        })
    })?;

    let mut summaries = Vec::new();
    for row in rows {
        let row = row?;
        let onboarding_state = derive_node_onboarding_state(connection, &network.network_id, &row)?;
        summaries.push(NodeSummaryRecord {
            node_id: row
                .node_id
                .parse()
                .map_err(|_| DatabaseError::StoredProtocolValue)?,
            network_id: row.network_id,
            display_name: row.display_name,
            status: row.status,
            platform: row.platform,
            agent_version: row.agent_version,
            xray_version: row.xray_version,
            public_material_ready: row.public_material_ready != 0,
            onboarding_state,
            capabilities: serde_json::from_str(&row.capabilities_json)?,
            provider_consent: NodeProviderConsentRecord {
                policy_version: row.consent_policy_version,
                host_owner: row.consent_host_owner != 0,
                exit_ip: row.consent_exit_ip != 0,
                router_mapping: row.consent_router_mapping != 0,
                accepted_at: row.consent_accepted_at,
            },
            last_seen_at: row.last_seen_at,
            runtime_state: row.runtime_state,
            provider_paused: row.provider_paused != 0,
            desired_revision: row.desired_revision,
            received_revision: row.received_revision,
            validated_revision: row.validated_revision,
            applied_revision: row.applied_revision,
            telemetry_cursor: row.telemetry_cursor,
            created_at: row.created_at,
            updated_at: row.updated_at,
        });
    }
    Ok(summaries)
}

fn derive_node_onboarding_state(
    connection: &Connection,
    network_id: &str,
    node: &RawNodeSummary,
) -> Result<String, DatabaseError> {
    let state = if matches!(node.status.as_str(), "disabled" | "revoked") {
        "unavailable"
    } else if node.provider_paused != 0 {
        "paused"
    } else if node.status == "pending" {
        "awaitingApproval"
    } else if node.last_seen_at.is_none() {
        "awaitingHeartbeat"
    } else if node.desired_revision.is_none() {
        "awaitingConfiguration"
    } else if node.applied_revision != node.desired_revision {
        let terminal_failure = connection.query_row(
            "SELECT EXISTS(
                SELECT 1 FROM node_revision_results
                WHERE network_id = ?1 AND node_id = ?2 AND revision = ?3
                  AND state IN ('rejected', 'rolledBack')
             )",
            params![network_id, node.node_id, node.desired_revision],
            |row| row.get::<_, bool>(0),
        )?;
        if terminal_failure {
            "needsAttention"
        } else {
            "applyingConfiguration"
        }
    } else if matches!(
        node.runtime_state.as_deref(),
        Some("degraded" | "quarantined")
    ) {
        "needsAttention"
    } else if node.runtime_state.as_deref() != Some("serving") {
        "applyingConfiguration"
    } else {
        let endpoint_state = connection.query_row(
            "SELECT
                EXISTS(
                    SELECT 1
                    FROM node_endpoint_candidates AS candidate
                    JOIN node_endpoint_verifications AS verification
                      ON verification.network_id = candidate.network_id
                     AND verification.node_id = candidate.node_id
                     AND verification.endpoint_id = candidate.endpoint_id
                    WHERE candidate.network_id = ?1 AND candidate.node_id = ?2
                      AND candidate.applied_revision = ?3
                      AND candidate.withdrawn_at IS NULL
                      AND verification.status = 'verified'
                      AND verification.verification_expires_at > ?4
                ),
                EXISTS(
                    SELECT 1 FROM node_endpoint_candidates AS candidate
                    WHERE candidate.network_id = ?1 AND candidate.node_id = ?2
                      AND candidate.applied_revision = ?3
                      AND candidate.withdrawn_at IS NULL
                )",
            params![
                network_id,
                node.node_id,
                node.applied_revision,
                unix_timestamp()?
            ],
            |row| Ok((row.get::<_, bool>(0)?, row.get::<_, bool>(1)?)),
        )?;
        match endpoint_state {
            (true, _) => "ready",
            (false, true) => "checkingEndpoint",
            (false, false) => "awaitingEndpoint",
        }
    };
    Ok(state.to_string())
}

fn create_account(
    connection: &mut Connection,
    request: &CreateAccountRequest,
    idempotency_key: &IdempotencyKey,
) -> Result<AccountSummary, DatabaseError> {
    request.validate()?;
    let now = unix_timestamp()?;
    let expires_at = now
        .checked_add(IDEMPOTENCY_LIFETIME_SECONDS)
        .ok_or(DatabaseError::TimestampOverflow)?;
    let idempotency_key_sha256: [u8; 32] =
        Sha256::digest(idempotency_key.as_str().as_bytes()).into();
    let request_sha256 = create_account_request_digest(request)?;
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let network = load_network(&transaction)?;
    if let Some(summary) = load_create_account_replay(
        &transaction,
        &network.network_id,
        &idempotency_key_sha256,
        &request_sha256,
    )? {
        transaction.commit()?;
        return Ok(summary);
    }

    let user_id = UserId::new();
    let user_id_text = user_id.to_string();
    transaction.execute(
        "INSERT INTO users(
            network_id, user_id, display_name, status, credential_version,
            created_at, updated_at
         ) VALUES (?1, ?2, ?3, 'active', 1, ?4, ?4)",
        params![network.network_id, user_id_text, request.display_name, now,],
    )?;
    insert_audit_event(
        &transaction,
        Some(&network.network_id),
        "bootstrap-admin",
        None,
        "account.created",
        "account",
        Some(&user_id_text),
        "success",
        &serde_json::json!({
            "displayName": request.display_name,
            "idempotencyKeyHash": Sha256Digest::from_bytes(idempotency_key_sha256),
        }),
        now,
    )?;
    let summary = load_account(&transaction, &network.network_id, user_id)?;
    let response_json = serde_json::to_string(&summary)?;
    let response_sha256: [u8; 32] = Sha256::digest(response_json.as_bytes()).into();
    transaction.execute(
        "INSERT INTO idempotency_records(
            network_id, principal_type, principal_id, route_id,
            idempotency_key_sha256, request_sha256, state, response_status,
            response_json, response_sha256, created_at, completed_at, expires_at
         ) VALUES (?1, ?2, ?2, ?3, ?4, ?5, 'completed', ?6, ?7, ?8, ?9, ?9, ?10)",
        params![
            network.network_id,
            BOOTSTRAP_ADMIN_PRINCIPAL,
            CREATE_ACCOUNT_ROUTE_ID,
            idempotency_key_sha256.as_slice(),
            request_sha256.as_slice(),
            HTTP_CREATED_STATUS,
            response_json,
            response_sha256.as_slice(),
            now,
            expires_at,
        ],
    )?;
    transaction.commit()?;
    Ok(summary)
}

fn load_create_account_replay(
    connection: &Connection,
    network_id: &str,
    idempotency_key_sha256: &[u8; 32],
    request_sha256: &[u8; 32],
) -> Result<Option<AccountSummary>, DatabaseError> {
    let existing = connection
        .query_row(
            "SELECT request_sha256, state, response_status, response_json, response_sha256
             FROM idempotency_records
             WHERE network_id = ?1 AND principal_type = 'bootstrap-admin'
               AND principal_id = 'bootstrap-admin' AND route_id = ?2
               AND idempotency_key_sha256 = ?3",
            params![
                network_id,
                CREATE_ACCOUNT_ROUTE_ID,
                idempotency_key_sha256.as_slice()
            ],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Option<i64>>(2)?,
                    row.get::<_, Option<String>>(3)?,
                    row.get::<_, Option<Vec<u8>>>(4)?,
                ))
            },
        )
        .optional()?;
    let Some((stored_request, state, status, response_json, stored_response_digest)) = existing
    else {
        return Ok(None);
    };
    if stored_request.as_slice() != request_sha256 {
        return Err(DatabaseError::IdempotencyKeyConflict);
    }
    let (Some(status), Some(response_json), Some(stored_response_digest)) =
        (status, response_json, stored_response_digest)
    else {
        return Err(DatabaseError::StoredProtocolValue);
    };
    let response_digest: [u8; 32] = Sha256::digest(response_json.as_bytes()).into();
    if state != "completed"
        || status != HTTP_CREATED_STATUS
        || stored_response_digest.as_slice() != response_digest
    {
        return Err(DatabaseError::StoredProtocolValue);
    }
    Ok(Some(serde_json::from_str(&response_json)?))
}

fn create_account_request_digest(
    request: &CreateAccountRequest,
) -> Result<[u8; 32], DatabaseError> {
    let body = serde_json::to_vec(request)?;
    let mut hasher = Sha256::new();
    hasher.update(b"private-network-idempotency-v1\0");
    hasher.update(BOOTSTRAP_ADMIN_PRINCIPAL.as_bytes());
    hasher.update(b"\0POST\0/v1/admin/accounts\0");
    hasher.update(body);
    Ok(hasher.finalize().into())
}

fn load_accounts(connection: &Connection) -> Result<Vec<AccountSummary>, DatabaseError> {
    let network = load_network(connection)?;
    let mut statement = connection.prepare(
        "SELECT user_id FROM users
         WHERE network_id = ?1 ORDER BY created_at ASC, user_id ASC",
    )?;
    let user_ids = statement
        .query_map([&network.network_id], |row| row.get::<_, String>(0))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    drop(statement);
    user_ids
        .into_iter()
        .map(|value| {
            let user_id = value
                .parse::<UserId>()
                .map_err(|_| DatabaseError::StoredProtocolValue)?;
            load_account(connection, &network.network_id, user_id)
        })
        .collect()
}

fn load_account(
    connection: &Connection,
    network_id: &str,
    user_id: UserId,
) -> Result<AccountSummary, DatabaseError> {
    let stored = connection
        .query_row(
            "SELECT display_name, status, created_at, updated_at
             FROM users WHERE network_id = ?1 AND user_id = ?2",
            params![network_id, user_id.to_string()],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?,
                ))
            },
        )
        .optional()?
        .ok_or(DatabaseError::AccountNotFound)?;
    let mut statement = connection.prepare(
        "SELECT assignment.assignment_id, assignment.node_id, assignment.status,
                CASE
                    WHEN ?3 = 'active' AND assignment.status = 'enabled' THEN
                        CASE WHEN EXISTS(
                            SELECT 1
                            FROM node_revision_member_credentials AS snapshot
                            JOIN user_node_credentials AS credential
                              ON credential.network_id = snapshot.network_id
                             AND credential.credential_id = snapshot.credential_id
                            WHERE snapshot.network_id = assignment.network_id
                              AND snapshot.node_id = assignment.node_id
                              AND snapshot.revision = node.applied_revision
                              AND snapshot.assignment_id = assignment.assignment_id
                              AND credential.status IN ('pending', 'active')
                        ) THEN 'applied' ELSE 'pending' END
                    WHEN EXISTS(
                        SELECT 1 FROM node_revision_member_credentials AS snapshot
                        WHERE snapshot.network_id = assignment.network_id
                          AND snapshot.node_id = assignment.node_id
                          AND snapshot.revision = node.applied_revision
                          AND snapshot.assignment_id = assignment.assignment_id
                    ) THEN 'removal_pending'
                    WHEN EXISTS(
                        SELECT 1
                        FROM node_revision_member_credentials AS historical
                        JOIN node_revision_results AS result
                          ON result.network_id = historical.network_id
                         AND result.node_id = historical.node_id
                         AND result.revision = historical.revision
                         AND result.state = 'applied'
                        WHERE historical.network_id = assignment.network_id
                          AND historical.assignment_id = assignment.assignment_id
                    ) THEN 'removed'
                    ELSE 'not_provisioned'
                END
         FROM user_node_assignments AS assignment
         JOIN nodes AS node
           ON node.network_id = assignment.network_id
          AND node.node_id = assignment.node_id
         WHERE assignment.network_id = ?1 AND assignment.user_id = ?2
         ORDER BY assignment.node_id ASC",
    )?;
    let assignments = statement
        .query_map(
            params![network_id, user_id.to_string(), stored.1.as_str()],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                ))
            },
        )?
        .map(|row| {
            let (assignment_id, node_id, status, provisioning_state) = row?;
            Ok(AccountNodeAssignment {
                assignment_id: assignment_id
                    .parse::<AssignmentId>()
                    .map_err(|_| DatabaseError::StoredProtocolValue)?,
                node_id: node_id
                    .parse::<NodeId>()
                    .map_err(|_| DatabaseError::StoredProtocolValue)?,
                status: parse_assignment_status(&status)?,
                provisioning_state: parse_assignment_provisioning_state(&provisioning_state)?,
            })
        })
        .collect::<Result<Vec<_>, DatabaseError>>()?;
    Ok(AccountSummary {
        account: AccountMetadata {
            user_id,
            display_name: stored.0,
            status: parse_account_status(&stored.1)?,
        },
        assignments,
        created_at: timestamp(stored.2)?,
        updated_at: timestamp(stored.3)?,
    })
}

fn replace_account_nodes(
    connection: &mut Connection,
    identity: &ControllerIdentity,
    user_id: UserId,
    request: &ReplaceAccountNodesRequest,
) -> Result<AccountSummary, DatabaseError> {
    request.validate()?;
    let now = unix_timestamp()?;
    let retire_after = now
        .checked_add(3_600)
        .ok_or(DatabaseError::TimestampOverflow)?;
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let mut network = load_network(&transaction)?;
    let account_status = load_account_status(&transaction, &network.network_id, user_id)?;
    if account_status != "active" {
        return Err(DatabaseError::AccountLifecycleConflict {
            current_status: account_status,
            requested_status: "replace-nodes".to_string(),
        });
    }

    let requested = request.node_ids.iter().copied().collect::<BTreeSet<_>>();
    validate_assignment_nodes(&transaction, &network.network_id, &requested)?;
    let existing = load_stored_assignments(&transaction, &network.network_id, user_id)?;
    let mut affected_nodes = enable_requested_assignments(
        &transaction,
        &network.network_id,
        user_id,
        &requested,
        &existing,
        now,
    )?;
    affected_nodes.extend(disable_omitted_assignments(
        &transaction,
        &network.network_id,
        &requested,
        &existing,
        now,
        retire_after,
    )?);
    let changed = !affected_nodes.is_empty();
    if changed {
        transaction.execute(
            "UPDATE users SET updated_at = ?1 WHERE network_id = ?2 AND user_id = ?3",
            params![now, network.network_id, user_id.to_string()],
        )?;
    }
    let revisions = publish_account_revisions(
        &transaction,
        identity,
        &mut network,
        &affected_nodes,
        "account-node-assignment",
        now,
    )?;
    insert_audit_event(
        &transaction,
        Some(&network.network_id),
        "bootstrap-admin",
        None,
        "account.nodes-replaced",
        "account",
        Some(&user_id.to_string()),
        "success",
        &serde_json::json!({
            "changed": changed,
            "nodeCount": requested.len(),
            "publishedRevisions": revision_audit_details(&revisions),
        }),
        now,
    )?;
    let summary = load_account(&transaction, &network.network_id, user_id)?;
    transaction.commit()?;
    Ok(summary)
}

fn enable_requested_assignments(
    connection: &Connection,
    network_id: &str,
    user_id: UserId,
    requested: &BTreeSet<NodeId>,
    existing: &BTreeMap<NodeId, StoredAssignment>,
    now: i64,
) -> Result<BTreeSet<NodeId>, DatabaseError> {
    let mut changed = BTreeSet::new();
    for node_id in requested {
        match existing.get(node_id) {
            None => {
                let assignment_id = AssignmentId::new();
                connection.execute(
                    "INSERT INTO user_node_assignments(
                        network_id, assignment_id, user_id, node_id, status,
                        created_at, updated_at
                     ) VALUES (?1, ?2, ?3, ?4, 'enabled', ?5, ?5)",
                    params![
                        network_id,
                        assignment_id.to_string(),
                        user_id.to_string(),
                        node_id.to_string(),
                        now,
                    ],
                )?;
                issue_assignment_credential(
                    connection,
                    network_id,
                    assignment_id,
                    user_id,
                    *node_id,
                    now,
                )?;
                changed.insert(*node_id);
            }
            Some(assignment) if assignment.status == "disabled" => {
                revoke_assignment_credentials(
                    connection,
                    network_id,
                    assignment.assignment_id,
                    now,
                )?;
                connection.execute(
                    "UPDATE user_node_assignments
                     SET status = 'enabled', disabled_at = NULL, updated_at = ?1
                     WHERE network_id = ?2 AND assignment_id = ?3 AND status = 'disabled'",
                    params![now, network_id, assignment.assignment_id.to_string()],
                )?;
                issue_assignment_credential(
                    connection,
                    network_id,
                    assignment.assignment_id,
                    user_id,
                    *node_id,
                    now,
                )?;
                changed.insert(*node_id);
            }
            Some(assignment) if assignment.status == "enabled" => {}
            Some(assignment) => {
                return Err(DatabaseError::AccountAssignmentConflict {
                    node_id: *node_id,
                    current_status: assignment.status.clone(),
                });
            }
        }
    }
    Ok(changed)
}

fn disable_omitted_assignments(
    connection: &Connection,
    network_id: &str,
    requested: &BTreeSet<NodeId>,
    existing: &BTreeMap<NodeId, StoredAssignment>,
    now: i64,
    retire_after: i64,
) -> Result<BTreeSet<NodeId>, DatabaseError> {
    let mut changed = BTreeSet::new();
    for (node_id, assignment) in existing {
        if assignment.status == "enabled" && !requested.contains(node_id) {
            disable_assignment(
                connection,
                network_id,
                assignment.assignment_id,
                now,
                retire_after,
            )?;
            changed.insert(*node_id);
        }
    }
    Ok(changed)
}

#[derive(Clone)]
struct StoredAssignment {
    assignment_id: AssignmentId,
    status: String,
}

fn load_stored_assignments(
    connection: &Connection,
    network_id: &str,
    user_id: UserId,
) -> Result<BTreeMap<NodeId, StoredAssignment>, DatabaseError> {
    let mut statement = connection.prepare(
        "SELECT assignment_id, node_id, status FROM user_node_assignments
         WHERE network_id = ?1 AND user_id = ?2",
    )?;
    let rows = statement.query_map(params![network_id, user_id.to_string()], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
        ))
    })?;
    let mut assignments = BTreeMap::new();
    for row in rows {
        let (assignment_id, node_id, status) = row?;
        assignments.insert(
            node_id
                .parse::<NodeId>()
                .map_err(|_| DatabaseError::StoredProtocolValue)?,
            StoredAssignment {
                assignment_id: assignment_id
                    .parse::<AssignmentId>()
                    .map_err(|_| DatabaseError::StoredProtocolValue)?,
                status,
            },
        );
    }
    Ok(assignments)
}

fn validate_assignment_nodes(
    connection: &Connection,
    network_id: &str,
    node_ids: &BTreeSet<NodeId>,
) -> Result<(), DatabaseError> {
    for node_id in node_ids {
        let status = connection
            .query_row(
                "SELECT status FROM nodes WHERE network_id = ?1 AND node_id = ?2",
                params![network_id, node_id.to_string()],
                |row| row.get::<_, String>(0),
            )
            .optional()?
            .ok_or(DatabaseError::NodeNotFound)?;
        if status != "active" {
            return Err(DatabaseError::NodeUnavailableForAssignment {
                node_id: *node_id,
                current_status: status,
            });
        }
    }
    Ok(())
}

fn issue_assignment_credential(
    connection: &Connection,
    network_id: &str,
    assignment_id: AssignmentId,
    user_id: UserId,
    node_id: NodeId,
    now: i64,
) -> Result<CredentialId, DatabaseError> {
    let previous_version: i64 = connection.query_row(
        "SELECT COALESCE(MAX(version), 0) FROM user_node_credentials
         WHERE network_id = ?1 AND assignment_id = ?2",
        params![network_id, assignment_id.to_string()],
        |row| row.get(0),
    )?;
    let version = previous_version
        .checked_add(1)
        .ok_or(DatabaseError::CredentialVersionOverflow)?;
    let credential_id = CredentialId::new();
    let xray_email = format!("{user_id}.{credential_id}@member");
    connection.execute(
        "INSERT INTO user_node_credentials(
            network_id, credential_id, assignment_id, user_id, node_id,
            xray_email, vless_uuid, version, status, created_at
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 'pending', ?9)",
        params![
            network_id,
            credential_id.to_string(),
            assignment_id.to_string(),
            user_id.to_string(),
            node_id.to_string(),
            xray_email,
            Uuid::new_v4().hyphenated().to_string(),
            version,
            now,
        ],
    )?;
    Ok(credential_id)
}

fn revoke_assignment_credentials(
    connection: &Connection,
    network_id: &str,
    assignment_id: AssignmentId,
    now: i64,
) -> Result<(), DatabaseError> {
    connection.execute(
        "UPDATE user_node_credentials
         SET status = 'revoked', revoked_at = ?1, retire_after = NULL
         WHERE network_id = ?2 AND assignment_id = ?3 AND status != 'revoked'",
        params![now, network_id, assignment_id.to_string()],
    )?;
    Ok(())
}

fn disable_assignment(
    connection: &Connection,
    network_id: &str,
    assignment_id: AssignmentId,
    now: i64,
    retire_after: i64,
) -> Result<(), DatabaseError> {
    connection.execute(
        "UPDATE user_node_assignments
         SET status = 'disabled', disabled_at = ?1, updated_at = ?1
         WHERE network_id = ?2 AND assignment_id = ?3 AND status = 'enabled'",
        params![now, network_id, assignment_id.to_string()],
    )?;
    connection.execute(
        "UPDATE user_node_credentials
         SET status = CASE WHEN status = 'pending' THEN 'revoked' ELSE 'retiring' END,
             retire_after = CASE WHEN status = 'pending' THEN NULL ELSE ?1 END,
             revoked_at = CASE WHEN status = 'pending' THEN ?2 ELSE NULL END
         WHERE network_id = ?3 AND assignment_id = ?4
           AND status IN ('pending', 'active')",
        params![retire_after, now, network_id, assignment_id.to_string()],
    )?;
    Ok(())
}

fn set_account_status(
    connection: &mut Connection,
    identity: &ControllerIdentity,
    user_id: UserId,
    requested: AccountStatus,
) -> Result<AccountSummary, DatabaseError> {
    let now = unix_timestamp()?;
    let retire_after = now
        .checked_add(3_600)
        .ok_or(DatabaseError::TimestampOverflow)?;
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let mut network = load_network(&transaction)?;
    let current = load_account_status(&transaction, &network.network_id, user_id)?;
    let requested_wire = enum_wire(&requested)?;
    if current == "deleted" && requested_wire != "deleted" {
        return Err(DatabaseError::AccountLifecycleConflict {
            current_status: current,
            requested_status: requested_wire,
        });
    }
    let changed = current != requested_wire;
    let affected_nodes = if changed {
        load_publishable_account_nodes(&transaction, &network.network_id, user_id)?
    } else {
        BTreeSet::new()
    };
    if changed {
        apply_account_status_transition(
            &transaction,
            &network.network_id,
            user_id,
            requested,
            now,
            retire_after,
        )?;
    }
    let revisions = publish_account_revisions(
        &transaction,
        identity,
        &mut network,
        &affected_nodes,
        "account-lifecycle",
        now,
    )?;
    insert_audit_event(
        &transaction,
        Some(&network.network_id),
        "bootstrap-admin",
        None,
        "account.status-changed",
        "account",
        Some(&user_id.to_string()),
        "success",
        &serde_json::json!({
            "fromStatus": current,
            "publishedRevisions": revision_audit_details(&revisions),
            "toStatus": requested_wire,
            "changed": changed,
        }),
        now,
    )?;
    let summary = load_account(&transaction, &network.network_id, user_id)?;
    transaction.commit()?;
    Ok(summary)
}

fn load_account_status(
    connection: &Connection,
    network_id: &str,
    user_id: UserId,
) -> Result<String, DatabaseError> {
    connection
        .query_row(
            "SELECT status FROM users WHERE network_id = ?1 AND user_id = ?2",
            params![network_id, user_id.to_string()],
            |row| row.get(0),
        )
        .optional()?
        .ok_or(DatabaseError::AccountNotFound)
}

fn apply_account_status_transition(
    connection: &Connection,
    network_id: &str,
    user_id: UserId,
    requested: AccountStatus,
    now: i64,
    retire_after: i64,
) -> Result<(), DatabaseError> {
    match requested {
        AccountStatus::Active => reactivate_account(connection, network_id, user_id, now),
        AccountStatus::Disabled => {
            connection.execute(
                "UPDATE users
                 SET status = 'disabled', credential_version = credential_version + 1,
                     disabled_at = ?1, deleted_at = NULL, updated_at = ?1
                 WHERE network_id = ?2 AND user_id = ?3",
                params![now, network_id, user_id.to_string()],
            )?;
            let assignments = load_stored_assignments(connection, network_id, user_id)?;
            for assignment in assignments.values() {
                if assignment.status == "enabled" {
                    connection.execute(
                        "UPDATE user_node_credentials
                         SET status = CASE
                                WHEN status = 'pending' THEN 'revoked' ELSE 'retiring' END,
                             retire_after = CASE
                                WHEN status = 'pending' THEN NULL ELSE ?1 END,
                             revoked_at = CASE
                                WHEN status = 'pending' THEN ?2 ELSE NULL END
                         WHERE network_id = ?3 AND assignment_id = ?4
                           AND status IN ('pending', 'active')",
                        params![
                            retire_after,
                            now,
                            network_id,
                            assignment.assignment_id.to_string()
                        ],
                    )?;
                }
            }
            Ok(())
        }
        AccountStatus::Deleted => {
            connection.execute(
                "UPDATE users
                 SET status = 'deleted', credential_version = credential_version + 1,
                     disabled_at = COALESCE(disabled_at, ?1), deleted_at = ?1, updated_at = ?1
                 WHERE network_id = ?2 AND user_id = ?3",
                params![now, network_id, user_id.to_string()],
            )?;
            connection.execute(
                "UPDATE user_node_assignments
                 SET status = 'deleted', deleted_at = ?1,
                     disabled_at = COALESCE(disabled_at, ?1), updated_at = ?1
                 WHERE network_id = ?2 AND user_id = ?3 AND status != 'deleted'",
                params![now, network_id, user_id.to_string()],
            )?;
            connection.execute(
                "UPDATE user_node_credentials
                 SET status = 'revoked', revoked_at = ?1, retire_after = NULL
                 WHERE network_id = ?2 AND user_id = ?3 AND status != 'revoked'",
                params![now, network_id, user_id.to_string()],
            )?;
            Ok(())
        }
    }
}

fn reactivate_account(
    connection: &Connection,
    network_id: &str,
    user_id: UserId,
    now: i64,
) -> Result<(), DatabaseError> {
    connection.execute(
        "UPDATE users
         SET status = 'active', disabled_at = NULL, deleted_at = NULL, updated_at = ?1
         WHERE network_id = ?2 AND user_id = ?3 AND status = 'disabled'",
        params![now, network_id, user_id.to_string()],
    )?;
    let assignments = load_stored_assignments(connection, network_id, user_id)?;
    for (node_id, assignment) in assignments {
        if assignment.status == "enabled" {
            revoke_assignment_credentials(connection, network_id, assignment.assignment_id, now)?;
            issue_assignment_credential(
                connection,
                network_id,
                assignment.assignment_id,
                user_id,
                node_id,
                now,
            )?;
        }
    }
    Ok(())
}

fn parse_account_status(value: &str) -> Result<AccountStatus, DatabaseError> {
    match value {
        "active" => Ok(AccountStatus::Active),
        "disabled" => Ok(AccountStatus::Disabled),
        "deleted" => Ok(AccountStatus::Deleted),
        _ => Err(DatabaseError::StoredProtocolValue),
    }
}

fn parse_assignment_status(value: &str) -> Result<AccountNodeAssignmentStatus, DatabaseError> {
    match value {
        "enabled" => Ok(AccountNodeAssignmentStatus::Enabled),
        "disabled" => Ok(AccountNodeAssignmentStatus::Disabled),
        "deleted" => Ok(AccountNodeAssignmentStatus::Deleted),
        _ => Err(DatabaseError::StoredProtocolValue),
    }
}

fn parse_assignment_provisioning_state(
    value: &str,
) -> Result<AccountNodeProvisioningState, DatabaseError> {
    match value {
        "pending" => Ok(AccountNodeProvisioningState::Pending),
        "applied" => Ok(AccountNodeProvisioningState::Applied),
        "removal_pending" => Ok(AccountNodeProvisioningState::RemovalPending),
        "removed" => Ok(AccountNodeProvisioningState::Removed),
        "not_provisioned" => Ok(AccountNodeProvisioningState::NotProvisioned),
        _ => Err(DatabaseError::StoredProtocolValue),
    }
}

fn transition_node(
    connection: &mut Connection,
    node_id: NodeId,
    action: NodeLifecycleAction,
) -> Result<(), DatabaseError> {
    let now = unix_timestamp()?;
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let network = load_network(&transaction)?;
    let node_id = node_id.to_string();
    let current_status = transaction
        .query_row(
            "SELECT status FROM nodes WHERE network_id = ?1 AND node_id = ?2",
            params![network.network_id, node_id],
            |row| row.get::<_, String>(0),
        )
        .optional()?
        .ok_or(DatabaseError::NodeNotFound)?;

    let Some(target_status) = node_lifecycle_target(action, &current_status)? else {
        insert_node_lifecycle_audit(
            &transaction,
            &network.network_id,
            &node_id,
            action,
            "rejected",
            &serde_json::json!({
                "action": action.wire_name(),
                "fromStatus": current_status,
                "reason": "invalid-state-transition"
            }),
            now,
        )?;
        transaction.commit()?;
        return Err(DatabaseError::NodeLifecycleConflict {
            action: action.wire_name(),
            current_status,
        });
    };

    let status_changed = current_status != target_status;
    if status_changed {
        let updated = transaction.execute(
            "UPDATE nodes SET status = ?1, updated_at = ?2
             WHERE network_id = ?3 AND node_id = ?4 AND status = ?5",
            params![
                target_status,
                now,
                network.network_id,
                node_id,
                current_status
            ],
        )?;
        if updated != 1 {
            return Err(DatabaseError::NodeLifecycleConflict {
                action: action.wire_name(),
                current_status,
            });
        }
    }

    let credentials_revoked =
        revoke_node_credentials(&transaction, &network.network_id, &node_id, action, now)?;
    let (member_assignments_closed, member_credentials_revoked) =
        close_node_member_access(&transaction, &network.network_id, &node_id, action, now)?;
    if (credentials_revoked > 0 || member_assignments_closed > 0 || member_credentials_revoked > 0)
        && !status_changed
    {
        transaction.execute(
            "UPDATE nodes SET updated_at = ?1 WHERE network_id = ?2 AND node_id = ?3",
            params![now, network.network_id, node_id],
        )?;
    }

    insert_node_lifecycle_audit(
        &transaction,
        &network.network_id,
        &node_id,
        action,
        "success",
        &serde_json::json!({
            "action": action.wire_name(),
            "credentialsRevoked": credentials_revoked,
            "fromStatus": current_status,
            "idempotent": !status_changed
                && credentials_revoked == 0
                && member_assignments_closed == 0
                && member_credentials_revoked == 0,
            "memberAssignmentsClosed": member_assignments_closed,
            "memberCredentialsRevoked": member_credentials_revoked,
            "toStatus": target_status
        }),
        now,
    )?;
    transaction.commit()?;
    Ok(())
}

fn node_lifecycle_target(
    action: NodeLifecycleAction,
    current_status: &str,
) -> Result<Option<&'static str>, DatabaseError> {
    match action {
        NodeLifecycleAction::Approve if matches!(current_status, "pending" | "active") => {
            Ok(Some("active"))
        }
        NodeLifecycleAction::Disable
            if matches!(current_status, "pending" | "active" | "disabled") =>
        {
            Ok(Some("disabled"))
        }
        NodeLifecycleAction::Revoke
            if matches!(
                current_status,
                "pending" | "active" | "disabled" | "revoked"
            ) =>
        {
            Ok(Some("revoked"))
        }
        _ if matches!(
            current_status,
            "pending" | "active" | "disabled" | "revoked"
        ) =>
        {
            Ok(None)
        }
        _ => Err(DatabaseError::StoredProtocolValue),
    }
}

fn revoke_node_credentials(
    transaction: &rusqlite::Transaction<'_>,
    network_id: &str,
    node_id: &str,
    action: NodeLifecycleAction,
    now: i64,
) -> Result<usize, DatabaseError> {
    if action != NodeLifecycleAction::Revoke {
        return Ok(0);
    }
    transaction
        .execute(
            "UPDATE node_auth_credentials SET revoked_at = ?1
             WHERE network_id = ?2 AND node_id = ?3 AND revoked_at IS NULL",
            params![now, network_id, node_id],
        )
        .map_err(DatabaseError::from)
}

fn close_node_member_access(
    transaction: &rusqlite::Transaction<'_>,
    network_id: &str,
    node_id: &str,
    action: NodeLifecycleAction,
    now: i64,
) -> Result<(usize, usize), DatabaseError> {
    let assignment_filter = match action {
        NodeLifecycleAction::Approve => return Ok((0, 0)),
        NodeLifecycleAction::Disable => "status = 'enabled'",
        NodeLifecycleAction::Revoke => "status != 'deleted'",
    };
    transaction.execute(
        &format!(
            "UPDATE users SET updated_at = ?1
             WHERE network_id = ?2 AND EXISTS(
                SELECT 1 FROM user_node_assignments AS assignment
                WHERE assignment.network_id = users.network_id
                  AND assignment.user_id = users.user_id
                  AND assignment.node_id = ?3 AND {assignment_filter}
             )"
        ),
        params![now, network_id, node_id],
    )?;
    let assignments_closed = match action {
        NodeLifecycleAction::Approve => 0,
        NodeLifecycleAction::Disable => transaction.execute(
            "UPDATE user_node_assignments
             SET status = 'disabled', disabled_at = ?1, updated_at = ?1
             WHERE network_id = ?2 AND node_id = ?3 AND status = 'enabled'",
            params![now, network_id, node_id],
        )?,
        NodeLifecycleAction::Revoke => transaction.execute(
            "UPDATE user_node_assignments
             SET status = 'deleted', disabled_at = COALESCE(disabled_at, ?1),
                 deleted_at = ?1, updated_at = ?1
             WHERE network_id = ?2 AND node_id = ?3 AND status != 'deleted'",
            params![now, network_id, node_id],
        )?,
    };
    let credentials_revoked = transaction.execute(
        "UPDATE user_node_credentials
         SET status = 'revoked', revoked_at = ?1, retire_after = NULL
         WHERE network_id = ?2 AND node_id = ?3 AND status != 'revoked'",
        params![now, network_id, node_id],
    )?;
    Ok((assignments_closed, credentials_revoked))
}

fn insert_node_lifecycle_audit(
    transaction: &rusqlite::Transaction<'_>,
    network_id: &str,
    node_id: &str,
    action: NodeLifecycleAction,
    outcome: &str,
    details: &serde_json::Value,
    now: i64,
) -> Result<(), DatabaseError> {
    insert_audit_event(
        transaction,
        Some(network_id),
        "admin",
        None,
        action.audit_event(),
        "node",
        Some(node_id),
        outcome,
        details,
        now,
    )
}

fn create_node_invitation(
    connection: &mut Connection,
    identity: &ControllerIdentity,
    request: &CreateNodeInvitationRequest,
    controller_origin: &str,
    idempotency_key: &IdempotencyKey,
) -> Result<CreateNodeInvitationResponse, DatabaseError> {
    let now = unix_timestamp()?;
    let expires_at = now
        .checked_add(i64::from(request.expires_in_seconds))
        .ok_or(DatabaseError::TimestampOverflow)?;
    let idempotency_key_sha256: [u8; 32] =
        Sha256::digest(idempotency_key.as_str().as_bytes()).into();
    let request_sha256: [u8; 32] = Sha256::digest(serde_json::to_vec(request)?).into();
    let initial_configuration_json = request
        .initial_configuration
        .as_ref()
        .map(serde_json::to_string)
        .transpose()?;

    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let network = load_network(&transaction)?;
    if let Some(invitation) = load_node_invitation_replay(
        &transaction,
        identity,
        &network.network_id,
        &idempotency_key_sha256,
        &request_sha256,
    )? {
        transaction.commit()?;
        return Ok(invitation);
    }
    let invitation_id = NodeInvitationId::new();
    let invitation_secret = derive_invitation_secret(
        identity,
        &network.network_id,
        &idempotency_key_sha256,
        &request_sha256,
    )?;
    let secret_verifier = Sha256::digest(invitation_secret.as_bytes());
    let fingerprint = identity.fingerprint();
    transaction.execute(
        "INSERT INTO node_invitations(
            invitation_id, network_id, purpose, intended_display_name, secret_verifier,
            controller_origin, controller_fingerprint, expires_at, created_at,
            initial_configuration_json, idempotency_key_sha256, request_sha256
         ) VALUES (
            ?1, ?2, 'node-enrollment', ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11
         )",
        params![
            invitation_id.to_string(),
            network.network_id,
            request.display_name,
            secret_verifier.as_slice(),
            controller_origin,
            fingerprint.as_str(),
            expires_at,
            now,
            initial_configuration_json,
            idempotency_key_sha256.as_slice(),
            request_sha256.as_slice(),
        ],
    )?;
    insert_audit_event(
        &transaction,
        Some(&network.network_id),
        "admin",
        None,
        "node-invitation.created",
        "node-invitation",
        Some(&invitation_id.to_string()),
        "success",
        &serde_json::json!({
            "expiresAt": timestamp(expires_at)?.to_string(),
            "intendedDisplayName": request.display_name,
            "purpose": "node-enrollment",
            "automaticBootstrap": request.initial_configuration.is_some(),
            "idempotencyKeyHash": Sha256Digest::from_bytes(idempotency_key_sha256)
        }),
        now,
    )?;
    transaction.commit()?;

    Ok(CreateNodeInvitationResponse {
        invitation_id,
        purpose: PairingPurpose::NodeEnrollment,
        expires_at: timestamp(expires_at)?,
        invitation_secret: Secret::new(invitation_secret),
        controller_origin: controller_origin.to_string(),
        controller_fingerprint: fingerprint,
    })
}

fn derive_invitation_secret(
    identity: &ControllerIdentity,
    network_id: &str,
    idempotency_key_sha256: &[u8; 32],
    request_sha256: &[u8; 32],
) -> Result<String, DatabaseError> {
    let mut transcript = Sha256::new();
    transcript.update(NODE_INVITATION_SECRET_DOMAIN);
    transcript.update(network_id.as_bytes());
    transcript.update(idempotency_key_sha256);
    transcript.update(request_sha256);
    let proof = identity.sign(&transcript.finalize())?;
    let secret: [u8; INVITATION_SECRET_BYTES] = Sha256::digest(proof.as_str().as_bytes()).into();
    Ok(URL_SAFE_NO_PAD.encode(secret))
}

fn load_node_invitation_replay(
    connection: &Connection,
    identity: &ControllerIdentity,
    network_id: &str,
    idempotency_key_sha256: &[u8; 32],
    request_sha256: &[u8; 32],
) -> Result<Option<CreateNodeInvitationResponse>, DatabaseError> {
    let stored = connection
        .query_row(
            "SELECT request_sha256, invitation_id, expires_at, controller_origin,
                    controller_fingerprint, secret_verifier
             FROM node_invitations
             WHERE network_id = ?1 AND idempotency_key_sha256 = ?2",
            params![network_id, idempotency_key_sha256.as_slice()],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, Vec<u8>>(5)?,
                ))
            },
        )
        .optional()?;
    let Some((stored_request, invitation_id, expires_at, origin, fingerprint, secret_verifier)) =
        stored
    else {
        return Ok(None);
    };
    if stored_request.as_slice() != request_sha256 {
        return Err(DatabaseError::IdempotencyKeyConflict);
    }
    let invitation_secret =
        derive_invitation_secret(identity, network_id, idempotency_key_sha256, request_sha256)?;
    let expected_verifier = Sha256::digest(invitation_secret.as_bytes());
    if secret_verifier.len() != expected_verifier.len()
        || secret_verifier
            .as_slice()
            .ct_eq(expected_verifier.as_slice())
            .unwrap_u8()
            != 1
    {
        return Err(DatabaseError::StoredProtocolValue);
    }
    Ok(Some(CreateNodeInvitationResponse {
        invitation_id: invitation_id
            .parse()
            .map_err(|_| DatabaseError::StoredProtocolValue)?,
        purpose: PairingPurpose::NodeEnrollment,
        expires_at: timestamp(expires_at)?,
        invitation_secret: Secret::new(invitation_secret),
        controller_origin: origin,
        controller_fingerprint: fingerprint
            .parse()
            .map_err(|_| DatabaseError::StoredProtocolValue)?,
    }))
}

fn enroll_node(
    connection: &mut Connection,
    identity: &ControllerIdentity,
    request: &EnrollNodeRequest,
) -> Result<NodeEnrollmentResult, DatabaseError> {
    let now = unix_timestamp()?;
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let mut network = load_network(&transaction)?;
    let validated =
        match validate_enrollment_attempt(&transaction, &network, identity, request, now) {
            Ok(validated) => validated,
            Err(error) if error.is_audited_enrollment_rejection() => {
                transaction.commit()?;
                return Err(error);
            }
            Err(error) => return Err(error),
        };
    if let ValidatedEnrollment::Existing {
        created,
        request_transcript,
    } = validated
    {
        let response =
            build_enrollment_response(&network, identity, &created, &request_transcript)?;
        transaction.commit()?;
        return Ok(NodeEnrollmentResult {
            response,
            created: false,
        });
    }
    let ValidatedEnrollment::New {
        invitation_id,
        request_transcript,
        initial_configuration,
    } = validated
    else {
        unreachable!("existing enrollment returned above");
    };
    let created = insert_node_records(&transaction, &network.network_id, request, now)?;
    consume_invitation(&transaction, &invitation_id, created.node_id, now)?;
    let automatic_bootstrap = apply_invitation_bootstrap(
        &transaction,
        identity,
        &mut network,
        created.node_id,
        initial_configuration,
        &invitation_id,
        now,
    )?;
    let response = build_enrollment_response(&network, identity, &created, &request_transcript)?;

    insert_audit_event(
        &transaction,
        Some(&network.network_id),
        "node",
        Some(&created.node_id.to_string()),
        "node.enrolled",
        "node",
        Some(&created.node_id.to_string()),
        "success",
        &serde_json::json!({
            "agentVersion": request.agent_version,
            "invitationId": invitation_id,
            "platform": request.platform,
            "providerConsentPolicyVersion": request.provider_consent.policy_version,
            "routerMappingAccepted": request.provider_consent.router_mapping_accepted,
            "automaticBootstrap": automatic_bootstrap,
            "publicMaterialReady": request.public_material.is_some()
        }),
        now,
    )?;
    transaction.commit()?;
    Ok(NodeEnrollmentResult {
        response,
        created: true,
    })
}

fn apply_invitation_bootstrap(
    transaction: &rusqlite::Transaction<'_>,
    identity: &ControllerIdentity,
    network: &mut NetworkRecord,
    node_id: NodeId,
    configuration: Option<NodeInitialConfiguration>,
    invitation_id: &str,
    now: i64,
) -> Result<bool, DatabaseError> {
    let Some(configuration) = configuration else {
        return Ok(false);
    };
    let updated = transaction.execute(
        "UPDATE nodes SET status = 'active', updated_at = ?1
         WHERE network_id = ?2 AND node_id = ?3 AND status = 'pending'",
        params![now, network.network_id, node_id.to_string()],
    )?;
    if updated != 1 {
        return Err(DatabaseError::DesiredStatePublicationConflict {
            current_status: "pending-transition-failed".to_string(),
        });
    }
    publish_compiled_desired_state(
        transaction,
        identity,
        network,
        node_id,
        DesiredStateConfigurationDraft {
            min_agent_version: configuration.min_agent_version,
            xray: configuration.xray,
        },
        &[],
        "invitation-bootstrap",
        now,
    )?;
    insert_audit_event(
        transaction,
        Some(&network.network_id),
        "admin",
        None,
        "node.approved",
        "node",
        Some(&node_id.to_string()),
        "success",
        &serde_json::json!({
            "automatic": true,
            "invitationId": invitation_id,
        }),
        now,
    )?;
    Ok(true)
}

enum ValidatedEnrollment {
    New {
        invitation_id: String,
        request_transcript: Vec<u8>,
        initial_configuration: Option<NodeInitialConfiguration>,
    },
    Existing {
        created: CreatedNode,
        request_transcript: Vec<u8>,
    },
}

fn validate_enrollment_attempt(
    transaction: &rusqlite::Transaction<'_>,
    network: &NetworkRecord,
    identity: &ControllerIdentity,
    request: &EnrollNodeRequest,
    now: i64,
) -> Result<ValidatedEnrollment, DatabaseError> {
    let verifier = Sha256::digest(request.invitation_secret.expose_secret().as_bytes());
    let invitation = load_invitation(transaction, verifier.as_slice())?;
    let Some(invitation) = invitation else {
        // Unknown random secrets are intentionally not persisted, avoiding an
        // unauthenticated audit-log amplification path.
        return Err(DatabaseError::InvitationInvalid);
    };
    if invitation
        .initial_configuration
        .as_ref()
        .is_some_and(|configuration| configuration.validate().is_err())
    {
        return Err(DatabaseError::StoredProtocolValue);
    }

    validate_invitation_state(transaction, network, identity, &invitation, now)?;
    let invitation_id = invitation
        .invitation_id
        .parse()
        .map_err(|_| DatabaseError::StoredProtocolValue)?;
    let fingerprint = invitation
        .controller_fingerprint
        .parse()
        .map_err(|_| DatabaseError::StoredProtocolValue)?;
    let context = EnrollmentInvitation {
        invitation_id,
        purpose: PairingPurpose::NodeEnrollment,
        expires_at: timestamp(invitation.expires_at)?,
        controller_origin: &invitation.controller_origin,
        controller_fingerprint: &fingerprint,
    };
    let request_transcript = enrollment_request_transcript(&context, request)?;
    if verify_enrollment_proof(request, &request_transcript).is_err() {
        return reject_enrollment(
            transaction,
            &network.network_id,
            Some(&invitation.invitation_id),
            "signature-invalid",
            DatabaseError::InvalidEnrollmentProof,
            now,
        );
    }
    if request.display_name != invitation.intended_display_name {
        return reject_enrollment(
            transaction,
            &network.network_id,
            Some(&invitation.invitation_id),
            "display-name-mismatch",
            DatabaseError::EnrollmentDisplayNameMismatch,
            now,
        );
    }
    if invitation.initial_configuration.is_some() && request.public_material.is_none() {
        return reject_enrollment(
            transaction,
            &network.network_id,
            Some(&invitation.invitation_id),
            "public-material-required",
            DatabaseError::NodePublicMaterialRequired,
            now,
        );
    }
    if invitation.initial_configuration.is_some()
        && (!request.capabilities.contains(&NodeCapability::Xray)
            || !request.capabilities.contains(&NodeCapability::DirectTcp))
    {
        return reject_enrollment(
            transaction,
            &network.network_id,
            Some(&invitation.invitation_id),
            "bootstrap-capabilities-required",
            DatabaseError::NodeBootstrapCapabilitiesRequired,
            now,
        );
    }
    if let Some(consumed_node_id) = invitation.consumed_node_id.as_deref() {
        if let Some(created) =
            load_existing_enrollment(transaction, &network.network_id, consumed_node_id, request)?
        {
            return Ok(ValidatedEnrollment::Existing {
                created,
                request_transcript,
            });
        }
        return reject_enrollment(
            transaction,
            &network.network_id,
            Some(&invitation.invitation_id),
            "invitation-consumed",
            DatabaseError::InvitationConsumed,
            now,
        );
    }
    Ok(ValidatedEnrollment::New {
        invitation_id: invitation.invitation_id,
        request_transcript,
        initial_configuration: invitation.initial_configuration,
    })
}

fn validate_invitation_state(
    transaction: &rusqlite::Transaction<'_>,
    network: &NetworkRecord,
    identity: &ControllerIdentity,
    invitation: &InvitationRecord,
    now: i64,
) -> Result<(), DatabaseError> {
    let rejection = if invitation.cancelled_at.is_some() {
        Some(("invitation-cancelled", DatabaseError::InvitationCancelled))
    } else if invitation.consumed_node_id.is_none() && invitation.expires_at <= now {
        Some(("invitation-expired", DatabaseError::InvitationExpired))
    } else if invitation.controller_fingerprint != identity.fingerprint().as_str() {
        Some((
            "controller-identity-mismatch",
            DatabaseError::ControllerIdentityMismatch,
        ))
    } else {
        None
    };
    if let Some((reason, error)) = rejection {
        return reject_enrollment(
            transaction,
            &network.network_id,
            Some(&invitation.invitation_id),
            reason,
            error,
            now,
        );
    }
    Ok(())
}

#[derive(Clone, Copy)]
struct CreatedNode {
    node_id: NodeId,
    key_id: NodeKeyId,
    credential_expires_at: i64,
}

fn load_existing_enrollment(
    transaction: &rusqlite::Transaction<'_>,
    network_id: &str,
    node_id: &str,
    request: &EnrollNodeRequest,
) -> Result<Option<CreatedNode>, DatabaseError> {
    let capabilities_json = serde_json::to_string(&request.capabilities)?;
    transaction
        .query_row(
            "SELECT n.node_id, c.node_credential_id, c.expires_at
             FROM nodes AS n
             JOIN node_auth_credentials AS c
               ON c.network_id = n.network_id AND c.node_id = n.node_id
             WHERE n.network_id = ?1 AND n.node_id = ?2
               AND n.identity_public_key = ?3 AND n.encryption_public_key = ?4
               AND COALESCE(n.reality_public_key, '') = COALESCE(?5, '')
               AND COALESCE(n.reality_short_id, '') = COALESCE(?6, '')
               AND n.platform = ?7 AND n.capabilities_json = ?8
               AND n.consent_policy_version = ?9
               AND n.consent_host_owner = ?10 AND n.consent_exit_ip = ?11
               AND n.consent_router_mapping = ?12 AND n.consent_accepted_at = ?13
               AND c.identity_public_key = ?3 AND c.revoked_at IS NULL
             ORDER BY c.created_at DESC LIMIT 1",
            params![
                network_id,
                node_id,
                request.identity_public_key.as_str(),
                request.encryption_public_key.as_str(),
                request
                    .public_material
                    .as_ref()
                    .map(|material| material.reality_public_key.as_str()),
                request
                    .public_material
                    .as_ref()
                    .map(|material| material.reality_short_id.as_str()),
                request.platform,
                capabilities_json,
                request.provider_consent.policy_version,
                i64::from(request.provider_consent.host_owner_consented),
                i64::from(request.provider_consent.exit_ip_disclosure_accepted),
                i64::from(request.provider_consent.router_mapping_accepted),
                request
                    .provider_consent
                    .accepted_at
                    .as_datetime()
                    .unix_timestamp(),
            ],
            |row| {
                let node_id = row.get::<_, String>(0)?;
                let key_id = row.get::<_, String>(1)?;
                Ok((node_id, key_id, row.get::<_, i64>(2)?))
            },
        )
        .optional()?
        .map(|(node_id, key_id, credential_expires_at)| {
            Ok(CreatedNode {
                node_id: node_id
                    .parse()
                    .map_err(|_| DatabaseError::StoredProtocolValue)?,
                key_id: key_id
                    .parse()
                    .map_err(|_| DatabaseError::StoredProtocolValue)?,
                credential_expires_at,
            })
        })
        .transpose()
}

fn insert_node_records(
    transaction: &rusqlite::Transaction<'_>,
    network_id: &str,
    request: &EnrollNodeRequest,
    now: i64,
) -> Result<CreatedNode, DatabaseError> {
    let created = CreatedNode {
        node_id: NodeId::new(),
        key_id: NodeKeyId::new(),
        credential_expires_at: OffsetDateTime::from_unix_timestamp(now)?
            .checked_add(Duration::days(NODE_CREDENTIAL_LIFETIME_DAYS))
            .ok_or(DatabaseError::TimestampOverflow)?
            .unix_timestamp(),
    };
    transaction.execute(
        "INSERT INTO nodes(
            node_id, network_id, display_name, status, agent_version, platform,
            capabilities_json, identity_public_key, encryption_public_key,
            consent_policy_version, consent_host_owner, consent_exit_ip,
            consent_router_mapping, consent_accepted_at, created_at, updated_at,
            reality_public_key, reality_short_id
         ) VALUES (
            ?1, ?2, ?3, 'pending', ?4, ?5, ?6, ?7, ?8, ?9, 1, 1,
            ?10, ?11, ?12, ?12, ?13, ?14
         )",
        params![
            created.node_id.to_string(),
            network_id,
            request.display_name,
            request.agent_version,
            request.platform,
            serde_json::to_string(&request.capabilities)?,
            request.identity_public_key.as_str(),
            request.encryption_public_key.as_str(),
            request.provider_consent.policy_version,
            i64::from(request.provider_consent.router_mapping_accepted),
            request
                .provider_consent
                .accepted_at
                .as_datetime()
                .unix_timestamp(),
            now,
            request
                .public_material
                .as_ref()
                .map(|material| material.reality_public_key.as_str()),
            request
                .public_material
                .as_ref()
                .map(|material| material.reality_short_id.as_str()),
        ],
    )?;
    transaction.execute(
        "INSERT INTO node_auth_credentials(
            network_id, node_credential_id, node_id, identity_public_key,
            auth_mode, not_before, expires_at, created_at
         ) VALUES (?1, ?2, ?3, ?4, 'signedRequest', ?5, ?6, ?5)",
        params![
            network_id,
            created.key_id.to_string(),
            created.node_id.to_string(),
            request.identity_public_key.as_str(),
            now,
            created.credential_expires_at,
        ],
    )?;
    Ok(created)
}

fn consume_invitation(
    transaction: &rusqlite::Transaction<'_>,
    invitation_id: &str,
    node_id: NodeId,
    now: i64,
) -> Result<(), DatabaseError> {
    let consumed = transaction.execute(
        "UPDATE node_invitations SET consumed_at = ?1, consumed_node_id = ?2
         WHERE invitation_id = ?3 AND consumed_at IS NULL AND cancelled_at IS NULL",
        params![now, node_id.to_string(), invitation_id],
    )?;
    if consumed == 1 {
        Ok(())
    } else {
        Err(DatabaseError::InvitationConsumed)
    }
}

fn build_enrollment_response(
    network: &NetworkRecord,
    identity: &ControllerIdentity,
    created: &CreatedNode,
    request_transcript: &[u8],
) -> Result<EnrollNodeResponse, DatabaseError> {
    let mut response = EnrollNodeResponse {
        network_id: network
            .network_id
            .parse::<NetworkId>()
            .map_err(|_| DatabaseError::StoredProtocolValue)?,
        node_id: created.node_id,
        controller_instance_id: network
            .controller_epoch
            .parse::<ControllerInstanceId>()
            .map_err(|_| DatabaseError::StoredProtocolValue)?,
        credential: NodeCredential {
            key_id: created.key_id,
            mode: NodeAuthenticationMode::SignedRequest,
            expires_at: timestamp(created.credential_expires_at)?,
            client_certificate_pem: None,
        },
        desired_state_signing_public_key: identity.public_key(),
        controller_nonce: random_nonce()?,
        proof: zero_signature()?,
    };
    let transcript = enrollment_response_transcript(request_transcript, &response)?;
    response.proof = identity.sign(&transcript)?;
    Ok(response)
}

fn reject_enrollment<T>(
    transaction: &rusqlite::Transaction<'_>,
    network_id: &str,
    invitation_id: Option<&str>,
    reason: &str,
    error: DatabaseError,
    now: i64,
) -> Result<T, DatabaseError> {
    insert_enrollment_rejection(transaction, network_id, invitation_id, reason, now)?;
    Err(error)
}

struct InvitationRecord {
    invitation_id: String,
    intended_display_name: String,
    controller_origin: String,
    controller_fingerprint: String,
    expires_at: i64,
    consumed_node_id: Option<String>,
    cancelled_at: Option<i64>,
    initial_configuration: Option<NodeInitialConfiguration>,
}

fn load_invitation(
    transaction: &rusqlite::Transaction<'_>,
    verifier: &[u8],
) -> Result<Option<InvitationRecord>, DatabaseError> {
    transaction
        .query_row(
            "SELECT invitation_id, intended_display_name, controller_origin,
                    controller_fingerprint, expires_at, consumed_node_id, cancelled_at,
                    initial_configuration_json
             FROM node_invitations
             WHERE secret_verifier = ?1 AND purpose = 'node-enrollment'",
            [verifier],
            |row| {
                let initial_configuration_json = row.get::<_, Option<String>>(7)?;
                Ok(InvitationRecord {
                    invitation_id: row.get(0)?,
                    intended_display_name: row.get(1)?,
                    controller_origin: row.get(2)?,
                    controller_fingerprint: row.get(3)?,
                    expires_at: row.get(4)?,
                    consumed_node_id: row.get(5)?,
                    cancelled_at: row.get(6)?,
                    initial_configuration: initial_configuration_json
                        .map(|json| serde_json::from_str(&json))
                        .transpose()
                        .map_err(|error| {
                            rusqlite::Error::FromSqlConversionFailure(
                                7,
                                rusqlite::types::Type::Text,
                                Box::new(error),
                            )
                        })?,
                })
            },
        )
        .optional()
        .map_err(DatabaseError::from)
}

fn insert_enrollment_rejection(
    transaction: &rusqlite::Transaction<'_>,
    network_id: &str,
    invitation_id: Option<&str>,
    reason: &str,
    now: i64,
) -> Result<(), DatabaseError> {
    insert_audit_event(
        transaction,
        Some(network_id),
        "anonymous-node",
        None,
        "node.enrollment-rejected",
        "node-invitation",
        invitation_id,
        "rejected",
        &serde_json::json!({ "reason": reason }),
        now,
    )
}

#[allow(clippy::too_many_arguments)]
fn insert_audit_event(
    transaction: &rusqlite::Transaction<'_>,
    network_id: Option<&str>,
    actor_type: &str,
    actor_id: Option<&str>,
    event_type: &str,
    target_type: &str,
    target_id: Option<&str>,
    outcome: &str,
    details: &serde_json::Value,
    now: i64,
) -> Result<(), DatabaseError> {
    transaction.execute(
        "INSERT INTO audit_events(
            network_id, actor_type, actor_id, event_type, target_type,
            target_id, outcome, details_json, created_at
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        params![
            network_id,
            actor_type,
            actor_id,
            event_type,
            target_type,
            target_id,
            outcome,
            serde_json::to_string(details)?,
            now,
        ],
    )?;
    Ok(())
}

fn random_nonce() -> Result<control_protocol::crypto::Nonce, DatabaseError> {
    let mut bytes = [0_u8; 32];
    OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD
        .encode(bytes)
        .parse()
        .map_err(|_| DatabaseError::StoredProtocolValue)
}

fn zero_signature() -> Result<control_protocol::crypto::Ed25519Signature, DatabaseError> {
    URL_SAFE_NO_PAD
        .encode([0_u8; 64])
        .parse()
        .map_err(|_| DatabaseError::StoredProtocolValue)
}

fn timestamp(value: i64) -> Result<Timestamp, DatabaseError> {
    Ok(Timestamp::from_datetime(
        OffsetDateTime::from_unix_timestamp(value)?,
    ))
}

fn verify_database(connection: &Connection) -> Result<(), DatabaseError> {
    let foreign_key_violation = connection.prepare("PRAGMA foreign_key_check")?.exists([])?;
    if foreign_key_violation {
        return Err(DatabaseError::ForeignKeyViolation);
    }

    let quick_check: String = connection.query_row("PRAGMA quick_check", [], |row| row.get(0))?;
    if quick_check != "ok" {
        return Err(DatabaseError::IntegrityCheckFailed(quick_check));
    }
    Ok(())
}

fn unix_timestamp() -> Result<i64, DatabaseError> {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(DatabaseError::Clock)?
        .as_secs();
    i64::try_from(seconds).map_err(|_| DatabaseError::TimestampOverflow)
}

#[derive(Debug, Error)]
pub enum DatabaseError {
    #[error(transparent)]
    Sqlite(#[from] rusqlite::Error),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    InvalidConfiguration(#[from] ConfigError),
    #[error(transparent)]
    Identity(#[from] IdentityError),
    #[error(transparent)]
    Validation(#[from] ProtocolValidationError),
    #[error(transparent)]
    EnrollmentCrypto(#[from] EnrollmentCryptoError),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    TimestampComponent(#[from] time::error::ComponentRange),
    #[error("database is already owned by another process: {lock_path}")]
    DatabaseLocked {
        lock_path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("database belongs to another application (expected {expected}, found {actual})")]
    WrongApplicationId { expected: i64, actual: i64 },
    #[error("database schema {actual} is newer than supported schema {supported}")]
    SchemaTooNew { supported: i64, actual: i64 },
    #[error(
        "schema_migrations version {source_version} does not match PRAGMA user_version {user_version}"
    )]
    MigrationMirrorMismatch {
        source_version: i64,
        user_version: i64,
    },
    #[error("migration {version} checksum or name does not match this binary")]
    MigrationChecksumMismatch { version: i64 },
    #[error("migration history has a gap before version {version}")]
    MigrationGap { version: i64 },
    #[error("expected one network but found {0}")]
    MultipleNetworks(i64),
    #[error("the bootstrapped network is missing")]
    NetworkMissing,
    #[error("database foreign key validation failed")]
    ForeignKeyViolation,
    #[error("database quick_check failed: {0}")]
    IntegrityCheckFailed(String),
    #[error("database worker failed")]
    Worker(#[source] tokio::task::JoinError),
    #[error("database mutex was poisoned")]
    LockPoisoned,
    #[error("system clock is before the Unix epoch")]
    Clock(#[source] std::time::SystemTimeError),
    #[error("current timestamp does not fit in SQLite INTEGER")]
    TimestampOverflow,
    #[error("the invitation is invalid")]
    InvitationInvalid,
    #[error("the invitation has expired")]
    InvitationExpired,
    #[error("the invitation was already consumed")]
    InvitationConsumed,
    #[error("the invitation was cancelled")]
    InvitationCancelled,
    #[error("the node enrollment proof is invalid")]
    InvalidEnrollmentProof,
    #[error("the enrollment display name does not match the invitation")]
    EnrollmentDisplayNameMismatch,
    #[error("automatic node bootstrap requires verified public REALITY material")]
    NodePublicMaterialRequired,
    #[error("automatic node bootstrap requires Xray and direct TCP capabilities")]
    NodeBootstrapCapabilitiesRequired,
    #[error("node authentication failed")]
    NodeAuthenticationFailed,
    #[error("the node or node credential is revoked")]
    NodeRevoked,
    #[error("the node request timestamp is outside the accepted clock window")]
    NodeRequestClockSkew,
    #[error("the node request nonce was already used")]
    NodeRequestNonceReplayed,
    #[error("the node reported progress older than its durable progress")]
    NodeProgressRegressed,
    #[error("the node heartbeat is older than its durable heartbeat generation")]
    NodeHeartbeatStale,
    #[error("the node reused a heartbeat generation for a different snapshot")]
    NodeHeartbeatConflict,
    #[error("the node reported progress not supported by the revision journal")]
    NodeProgressConflict,
    #[error("the node reused an endpoint candidate identity with different or withdrawn state")]
    EndpointCandidateConflict,
    #[error("the endpoint candidate does not match its applied signed revision")]
    EndpointCandidateRevisionConflict,
    #[error("the TCP probe schedule is invalid")]
    InvalidProbeSchedule,
    #[error("the endpoint probe claim was not found")]
    ProbeClaimNotFound,
    #[error("the endpoint probe claim does not match its durable identity or token")]
    ProbeClaimConflict,
    #[error("the endpoint probe result exceeds durable storage limits")]
    ProbeResultOverflow,
    #[error("the node request signature is invalid")]
    InvalidNodeRequestSignature,
    #[error("the node was not found")]
    NodeNotFound,
    #[error("the member account was not found")]
    AccountNotFound,
    #[error("the idempotency key was already used for a different request")]
    IdempotencyKeyConflict,
    #[error("cannot change account from {current_status} to {requested_status}")]
    AccountLifecycleConflict {
        current_status: String,
        requested_status: String,
    },
    #[error("node {node_id} in status {current_status} cannot be assigned")]
    NodeUnavailableForAssignment {
        node_id: NodeId,
        current_status: String,
    },
    #[error("node {node_id} has a terminal assignment in status {current_status}")]
    AccountAssignmentConflict {
        node_id: NodeId,
        current_status: String,
    },
    #[error("the per-assignment credential version sequence is exhausted")]
    CredentialVersionOverflow,
    #[error("cannot {action} a node in status {current_status}")]
    NodeLifecycleConflict {
        action: &'static str,
        current_status: String,
    },
    #[error("cannot publish desired state for a node in status {current_status}")]
    DesiredStatePublicationConflict { current_status: String },
    #[error("the node has no baseline desired Xray configuration")]
    NodeConfigurationMissing,
    #[error("the revision is not targeted to this node")]
    RevisionTargetNotFound,
    #[error("the revision result conflicts with its durable result journal")]
    RevisionResultConflict,
    #[error("the stored desired-state artifact is corrupt")]
    StoredDesiredStateCorrupt,
    #[error("the stored revision result is corrupt")]
    StoredRevisionResultCorrupt,
    #[error("the network revision sequence is exhausted")]
    RevisionOverflow,
    #[error(transparent)]
    DesiredState(#[from] DesiredStateError),
    #[error("the controller identity no longer matches the invitation")]
    ControllerIdentityMismatch,
    #[error("a stored protocol value is invalid")]
    StoredProtocolValue,
}

impl DatabaseError {
    fn is_audited_enrollment_rejection(&self) -> bool {
        matches!(
            self,
            Self::InvitationExpired
                | Self::InvitationConsumed
                | Self::InvitationCancelled
                | Self::InvalidEnrollmentProof
                | Self::EnrollmentDisplayNameMismatch
                | Self::NodePublicMaterialRequired
                | Self::NodeBootstrapCapabilitiesRequired
                | Self::ControllerIdentityMismatch
        )
    }
}

#[cfg(test)]
mod tests {
    use super::{
        lock_path, migration_checksum, Database, DatabaseError, MIGRATIONS, SCHEMA_VERSION,
    };
    use rusqlite::{params, Connection, TransactionBehavior};
    use tempfile::TempDir;

    type OptionalRevisionProgress = (
        Option<i64>,
        Option<i64>,
        Option<i64>,
        Option<i64>,
        Option<i64>,
    );

    fn database_path(temp: &TempDir) -> std::path::PathBuf {
        temp.path().join("control.sqlite3")
    }

    fn create_legacy_v3_database(path: &std::path::Path) -> String {
        let mut connection = Connection::open(path).unwrap();
        super::configure_connection(&connection).unwrap();
        super::validate_application_id(&connection).unwrap();
        connection
            .execute_batch(
                "CREATE TABLE schema_migrations (
                    version INTEGER PRIMARY KEY,
                    name TEXT NOT NULL UNIQUE,
                    checksum TEXT NOT NULL,
                    applied_at INTEGER NOT NULL
                 ) STRICT;",
            )
            .unwrap();
        for migration in MIGRATIONS.iter().take(3) {
            let transaction = connection
                .transaction_with_behavior(TransactionBehavior::Exclusive)
                .unwrap();
            transaction.execute_batch(migration.sql).unwrap();
            transaction
                .execute(
                    "INSERT INTO schema_migrations(version, name, checksum, applied_at)
                     VALUES (?1, ?2, ?3, 1)",
                    params![
                        migration.version,
                        migration.name,
                        migration_checksum(migration)
                    ],
                )
                .unwrap();
            transaction
                .pragma_update(None, "user_version", migration.version)
                .unwrap();
            transaction.commit().unwrap();
        }
        super::bootstrap_network(&mut connection, "Friends").unwrap();
        let network_id: String = connection
            .query_row("SELECT network_id FROM networks", [], |row| row.get(0))
            .unwrap();
        let node_id = uuid::Uuid::new_v4().to_string();
        connection
            .execute(
                "INSERT INTO nodes(
                    node_id, network_id, display_name, status, agent_version, platform,
                    capabilities_json, identity_public_key, encryption_public_key,
                    consent_policy_version, consent_host_owner, consent_exit_ip,
                    consent_accepted_at, created_at, updated_at, xray_version,
                    runtime_state, provider_paused, last_seen_at, desired_revision,
                    received_revision, validated_revision, applied_revision, telemetry_cursor
                 ) VALUES (
                    ?1, ?2, 'Legacy node', 'active', '0.1.0', 'macos-arm64',
                    '[\"xray\"]', 'legacy-identity', 'legacy-encryption',
                    'legacy-policy', 1, 1, 1, 1, 1, 'legacy-xray',
                    'serving', 0, 1, 7, 7, 7, 7, 9
                 )",
                params![node_id, network_id],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO node_reported_endpoints(
                    network_id, node_id, mode, address, port, status, created_at, updated_at
                 ) VALUES (?1, ?2, 'direct', 'legacy.example.test', 443, 'verified', 1, 1)",
                params![network_id, node_id],
            )
            .unwrap();
        node_id
    }

    fn create_legacy_v4_database(path: &std::path::Path) -> (String, String) {
        let node_id = create_legacy_v3_database(path);
        let mut connection = Connection::open(path).unwrap();
        super::configure_connection(&connection).unwrap();
        let migration = &MIGRATIONS[3];
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Exclusive)
            .unwrap();
        transaction.execute_batch(migration.sql).unwrap();
        transaction
            .execute(
                "INSERT INTO schema_migrations(version, name, checksum, applied_at)
                 VALUES (?1, ?2, ?3, 1)",
                params![
                    migration.version,
                    migration.name,
                    migration_checksum(migration)
                ],
            )
            .unwrap();
        transaction
            .pragma_update(None, "user_version", migration.version)
            .unwrap();
        transaction.commit().unwrap();

        let (network_id, controller_instance_id): (String, String) = connection
            .query_row(
                "SELECT network_id, controller_epoch FROM networks",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        let digest = format!("sha256:{}", "0".repeat(64));
        let signature = "A".repeat(86);
        let signing_key_id = uuid::Uuid::new_v4().to_string();
        connection
            .execute(
                "INSERT INTO config_revisions(
                    network_id, revision, parent_revision, schema_version, node_id,
                    artifact_json, artifact_sha256, transcript_sha256, signature,
                    signing_key_id, controller_instance_id, created_at
                 ) VALUES (?1, 1, NULL, 1, ?2, '{}', ?3, ?3, ?4, ?5, ?6, 1)",
                params![
                    network_id,
                    node_id,
                    digest,
                    signature,
                    signing_key_id,
                    controller_instance_id
                ],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO node_revision_targets(network_id, node_id, revision, created_at)
                 VALUES (?1, ?2, 1, 1)",
                params![network_id, node_id],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO node_revision_results(
                    network_id, node_id, revision, state, state_rank, result_json,
                    config_digest, rollback_revision, created_at
                 ) VALUES (?1, ?2, 1, 'received', 10, '{}', NULL, NULL, 1)",
                params![network_id, node_id],
            )
            .unwrap();
        connection
            .execute("UPDATE networks SET last_revision = 1", [])
            .unwrap();
        connection
            .execute(
                "UPDATE nodes
                 SET desired_revision = 1, reported_desired_revision = 1,
                     received_revision = 1
                 WHERE node_id = ?1",
                [node_id.as_str()],
            )
            .unwrap();
        (network_id, node_id)
    }

    #[test]
    fn applies_required_pragmas_and_records_authoritative_migration() {
        let temp = TempDir::new().unwrap();
        let path = database_path(&temp);
        let database = Database::open(&path, "Friends").unwrap();
        let guard = database.inner.lock().unwrap();
        let connection = &guard.connection;

        assert_eq!(
            connection
                .query_row("PRAGMA foreign_keys", [], |row| row.get::<_, i64>(0))
                .unwrap(),
            1
        );
        assert_eq!(
            connection
                .query_row("PRAGMA journal_mode", [], |row| row.get::<_, String>(0))
                .unwrap(),
            "wal"
        );
        assert_eq!(
            connection
                .query_row("PRAGMA synchronous", [], |row| row.get::<_, i64>(0))
                .unwrap(),
            2
        );
        assert_eq!(
            connection
                .query_row("PRAGMA busy_timeout", [], |row| row.get::<_, i64>(0))
                .unwrap(),
            5000
        );
        assert_eq!(
            connection
                .query_row("PRAGMA trusted_schema", [], |row| row.get::<_, i64>(0))
                .unwrap(),
            0
        );
        assert_eq!(
            connection
                .query_row("PRAGMA secure_delete", [], |row| row.get::<_, i64>(0))
                .unwrap(),
            2
        );
        assert_eq!(
            connection
                .query_row("PRAGMA user_version", [], |row| row.get::<_, i64>(0))
                .unwrap(),
            SCHEMA_VERSION
        );

        for migration in MIGRATIONS {
            let stored: (String, String) = connection
                .query_row(
                    "SELECT name, checksum FROM schema_migrations WHERE version = ?1",
                    [migration.version],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .unwrap();
            assert_eq!(stored.0, migration.name);
            assert_eq!(stored.1, migration_checksum(migration));
        }
    }

    #[test]
    fn v3_upgrade_discards_untrusted_heartbeat_progress_and_builds_revision_journal() {
        let temp = TempDir::new().unwrap();
        let path = database_path(&temp);
        let node_id = create_legacy_v3_database(&path);

        let database = Database::open(&path, "Friends").unwrap();
        let guard = database.inner.lock().unwrap();
        let progress: OptionalRevisionProgress = guard
            .connection
            .query_row(
                "SELECT desired_revision, reported_desired_revision, received_revision,
                        validated_revision, applied_revision
                 FROM nodes WHERE node_id = ?1",
                [node_id],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                    ))
                },
            )
            .unwrap();
        assert_eq!(progress, (None, None, None, None, None));
        let schema: (i64, i64, i64) = guard
            .connection
            .query_row(
                "SELECT
                    (SELECT user_version FROM pragma_user_version),
                    (SELECT COUNT(*) FROM schema_migrations),
                    (SELECT COUNT(*) FROM sqlite_schema
                     WHERE type = 'table' AND name IN (
                        'config_revisions', 'node_revision_targets', 'node_revision_results'
                     ))",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert_eq!(schema, (SCHEMA_VERSION, SCHEMA_VERSION, 3));
        let endpoint_state: (i64, i64, i64) = guard
            .connection
            .query_row(
                "SELECT
                    (SELECT COUNT(*) FROM sqlite_schema
                     WHERE type = 'table' AND name = 'node_reported_endpoints'),
                    (SELECT COUNT(*) FROM node_endpoint_candidates),
                    (SELECT COUNT(*) FROM node_endpoint_verifications)",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert_eq!(endpoint_state, (0, 0, 0));
        let immutable_triggers: i64 = guard
            .connection
            .query_row(
                "SELECT COUNT(*) FROM sqlite_schema
                 WHERE type = 'trigger' AND name IN (
                    'config_revisions_no_update', 'config_revisions_no_delete',
                    'node_revision_targets_no_update', 'node_revision_targets_no_delete',
                    'node_revision_results_no_update', 'node_revision_results_no_delete'
                 )",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(immutable_triggers, 6);
    }

    #[test]
    fn v4_upgrade_preserves_revision_graph_and_accepts_schema_two() {
        let temp = TempDir::new().unwrap();
        let path = database_path(&temp);
        let (network_id, node_id) = create_legacy_v4_database(&path);

        let database = Database::open(&path, "Friends").unwrap();
        let guard = database.inner.lock().unwrap();
        let connection = &guard.connection;
        let preserved: (i64, i64, String) = connection
            .query_row(
                "SELECT
                    (SELECT schema_version FROM config_revisions WHERE revision = 1),
                    (SELECT COUNT(*) FROM node_revision_targets WHERE revision = 1),
                    (SELECT state FROM node_revision_results WHERE revision = 1)",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert_eq!(preserved, (1, 1, "received".to_string()));
        let foreign_key_errors: i64 = connection
            .query_row("SELECT COUNT(*) FROM pragma_foreign_key_check", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(foreign_key_errors, 0);

        let digest = format!("sha256:{}", "1".repeat(64));
        let signature = "B".repeat(86);
        let signing_key_id = uuid::Uuid::new_v4().to_string();
        let controller_instance_id: String = connection
            .query_row("SELECT controller_epoch FROM networks", [], |row| {
                row.get(0)
            })
            .unwrap();
        connection
            .execute(
                "INSERT INTO config_revisions(
                    network_id, revision, parent_revision, schema_version, node_id,
                    artifact_json, artifact_sha256, transcript_sha256, signature,
                    signing_key_id, controller_instance_id, created_at
                 ) VALUES (?1, 2, 1, 2, ?2, '{}', ?3, ?3, ?4, ?5, ?6, 2)",
                params![
                    network_id,
                    node_id,
                    digest,
                    signature,
                    signing_key_id,
                    controller_instance_id
                ],
            )
            .unwrap();
        assert!(connection
            .execute(
                "INSERT INTO config_revisions(
                    network_id, revision, parent_revision, schema_version, node_id,
                    artifact_json, artifact_sha256, transcript_sha256, signature,
                    signing_key_id, controller_instance_id, created_at
                 ) VALUES (?1, 3, 2, 3, ?2, '{}', ?3, ?3, ?4, ?5, ?6, 3)",
                params![
                    network_id,
                    node_id,
                    digest,
                    signature,
                    signing_key_id,
                    controller_instance_id
                ],
            )
            .is_err());
    }

    #[test]
    fn bootstrap_is_idempotent_and_preserves_network_identity() {
        let temp = TempDir::new().unwrap();
        let path = database_path(&temp);
        let first = Database::open(&path, "Friends").unwrap();
        let first_network = {
            let guard = first.inner.lock().unwrap();
            super::load_network(&guard.connection).unwrap()
        };
        drop(first);

        let reopened = Database::open(&path, "A changed startup label").unwrap();
        let reopened_network = {
            let guard = reopened.inner.lock().unwrap();
            super::load_network(&guard.connection).unwrap()
        };

        assert_eq!(reopened_network, first_network);
        assert_eq!(reopened_network.display_name, "Friends");
    }

    #[test]
    fn rejects_a_modified_migration_history() {
        let temp = TempDir::new().unwrap();
        let path = database_path(&temp);
        let database = Database::open(&path, "Friends").unwrap();
        drop(database);

        let connection = Connection::open(&path).unwrap();
        connection
            .execute(
                "UPDATE schema_migrations SET checksum = 'tampered' WHERE version = 2",
                [],
            )
            .unwrap();
        drop(connection);

        let error = Database::open(&path, "Friends")
            .err()
            .expect("tampered migration must fail");
        assert!(matches!(
            error,
            DatabaseError::MigrationChecksumMismatch { version: 2 }
        ));
    }

    #[test]
    fn rejects_migration_gaps_and_future_schemas() {
        let temp = TempDir::new().unwrap();
        let path = database_path(&temp);
        let database = Database::open(&path, "Friends").unwrap();
        drop(database);

        let connection = Connection::open(&path).unwrap();
        connection
            .execute("DELETE FROM schema_migrations WHERE version = 1", [])
            .unwrap();
        drop(connection);
        let gap = Database::open(&path, "Friends")
            .err()
            .expect("migration gap must fail");
        assert!(matches!(gap, DatabaseError::MigrationGap { version: 1 }));

        let second_temp = TempDir::new().unwrap();
        let second_path = database_path(&second_temp);
        let database = Database::open(&second_path, "Friends").unwrap();
        drop(database);
        let connection = Connection::open(&second_path).unwrap();
        connection.pragma_update(None, "user_version", 99).unwrap();
        drop(connection);
        let future = Database::open(&second_path, "Friends")
            .err()
            .expect("future schema must fail");
        assert!(matches!(
            future,
            DatabaseError::SchemaTooNew {
                supported: SCHEMA_VERSION,
                actual: 99
            }
        ));
    }

    #[cfg(unix)]
    #[test]
    fn database_and_lock_files_are_owner_only() {
        use std::os::unix::fs::PermissionsExt as _;

        let temp = TempDir::new().unwrap();
        let path = database_path(&temp);
        let _database = Database::open(&path, "Friends").unwrap();

        for secure_path in [&path, &lock_path(&path)] {
            let mode = std::fs::metadata(secure_path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "{} was not owner-only", secure_path.display());
        }
    }

    #[test]
    fn enforces_single_process_ownership() {
        let temp = TempDir::new().unwrap();
        let path = database_path(&temp);
        let _first = Database::open(&path, "Friends").unwrap();

        let error = Database::open(&path, "Friends")
            .err()
            .expect("a second owner must fail");
        assert!(matches!(error, DatabaseError::DatabaseLocked { .. }));
    }
}
