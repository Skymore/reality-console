use crate::config::{validate_network_name, ConfigError};
use crate::desired::{
    build_signed_desired_state, verify_stored_desired_state, DesiredStateDraft, DesiredStateError,
    StoredDesiredState, SUPPORTED_DESIRED_STATE_SCHEMA_VERSIONS,
};
use crate::identity::{set_owner_only, ControllerIdentity, IdentityError};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use control_protocol::crypto::{Ed25519PublicKey, Sha256Digest};
use control_protocol::enrollment::{
    enrollment_request_transcript, enrollment_response_transcript, verify_enrollment_proof,
    EnrollmentCryptoError, EnrollmentInvitation,
};
use control_protocol::id::{
    ControllerInstanceId, NetworkId, NodeId, NodeInvitationId, NodeKeyId, Revision, SigningKeyId,
    Timestamp,
};
use control_protocol::node::{
    CreateNodeInvitationRequest, CreateNodeInvitationResponse, EndpointCandidate,
    EnrollNodeRequest, EnrollNodeResponse, NodeAuthenticationMode, NodeCapability, NodeCredential,
    NodeHeartbeat, PairingPurpose, RevisionResult, RevisionResultState, SignedDesiredState,
};
use control_protocol::request_auth::{
    verify_node_request_signature, NodeRequestAuthHeaders, NodeRequestSigningInput,
};
use control_protocol::secret::Secret;
use control_protocol::validation::ProtocolValidationError;
use fs2::FileExt;
use rand_core::{OsRng, RngCore as _};
use rusqlite::{params, Connection, OpenFlags, OptionalExtension, TransactionBehavior};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::fs::{self, File, OpenOptions};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

pub const SCHEMA_VERSION: i64 = 6;
const APPLICATION_ID: i64 = 0x5243_4F4E;
const INVITATION_SECRET_BYTES: usize = 32;
const NODE_CREDENTIAL_LIFETIME_DAYS: i64 = 90;
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AuthenticatedNode {
    pub node_id: NodeId,
    pub key_id: NodeKeyId,
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
    pub capabilities: Vec<NodeCapability>,
    pub consent_policy_version: String,
    pub consent_host_owner: bool,
    pub consent_exit_ip: bool,
    pub consent_accepted_at: i64,
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
    ) -> Result<(), DatabaseError> {
        let inner = Arc::clone(&self.inner);
        tokio::task::spawn_blocking(move || {
            let mut guard = inner.lock().map_err(|_| DatabaseError::LockPoisoned)?;
            record_heartbeat(&mut guard.connection, node_id, &heartbeat)
        })
        .await
        .map_err(DatabaseError::Worker)?
    }

    /// Publishes one immutable signed desired-state revision for an active node.
    pub(crate) async fn publish_desired_state(
        &self,
        node_id: NodeId,
        draft: DesiredStateDraft,
    ) -> Result<SignedDesiredState, DatabaseError> {
        let identity = self.controller_identity.clone();
        let inner = Arc::clone(&self.inner);
        tokio::task::spawn_blocking(move || {
            let mut guard = inner.lock().map_err(|_| DatabaseError::LockPoisoned)?;
            publish_desired_state(&mut guard.connection, &identity, node_id, draft)
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
    node_id: NodeId,
    heartbeat: &NodeHeartbeat,
) -> Result<(), DatabaseError> {
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
                transaction.commit()?;
                return Ok(());
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
    transaction.commit()?;
    Ok(())
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
    draft: DesiredStateDraft,
) -> Result<SignedDesiredState, DatabaseError> {
    let now = unix_timestamp()?;
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let network = load_network(&transaction)?;
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
        draft,
    )
    .map_err(map_desired_state_publication_error)?;
    insert_desired_revision(&transaction, &network, &node_id_text, &artifact, now)?;

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
        return Err(DatabaseError::DesiredStatePublicationConflict {
            current_status: node_status,
        });
    }
    insert_audit_event(
        &transaction,
        Some(&network.network_id),
        "admin",
        None,
        "node.desired-state-published",
        "node",
        Some(&node_id_text),
        "success",
        &serde_json::json!({
            "parentRevision": (revision > 1).then_some(revision - 1),
            "revision": revision,
            "schemaVersion": artifact.envelope.document.schema_version
        }),
        now,
    )?;
    transaction.commit()?;
    Ok(artifact.envelope)
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
    transaction.commit()?;
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

fn owner_only_open_options() -> OpenOptions {
    let mut options = OpenOptions::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    options
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
    capabilities_json: String,
    consent_policy_version: String,
    consent_host_owner: i64,
    consent_exit_ip: i64,
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
                xray_version, capabilities_json, consent_policy_version,
                consent_host_owner, consent_exit_ip, consent_accepted_at,
                last_seen_at, runtime_state, provider_paused, desired_revision,
                received_revision, validated_revision, applied_revision,
                telemetry_cursor, created_at, updated_at
         FROM nodes
         WHERE network_id = ?1
         ORDER BY created_at ASC, node_id ASC",
    )?;
    let rows = statement.query_map([network.network_id], |row| {
        Ok(RawNodeSummary {
            node_id: row.get(0)?,
            network_id: row.get(1)?,
            display_name: row.get(2)?,
            status: row.get(3)?,
            platform: row.get(4)?,
            agent_version: row.get(5)?,
            xray_version: row.get(6)?,
            capabilities_json: row.get(7)?,
            consent_policy_version: row.get(8)?,
            consent_host_owner: row.get(9)?,
            consent_exit_ip: row.get(10)?,
            consent_accepted_at: row.get(11)?,
            last_seen_at: row.get(12)?,
            runtime_state: row.get(13)?,
            provider_paused: row.get(14)?,
            desired_revision: row.get(15)?,
            received_revision: row.get(16)?,
            validated_revision: row.get(17)?,
            applied_revision: row.get(18)?,
            telemetry_cursor: row.get(19)?,
            created_at: row.get(20)?,
            updated_at: row.get(21)?,
        })
    })?;

    let mut summaries = Vec::new();
    for row in rows {
        let row = row?;
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
            capabilities: serde_json::from_str(&row.capabilities_json)?,
            consent_policy_version: row.consent_policy_version,
            consent_host_owner: row.consent_host_owner != 0,
            consent_exit_ip: row.consent_exit_ip != 0,
            consent_accepted_at: row.consent_accepted_at,
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
    if credentials_revoked > 0 && !status_changed {
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
            "idempotent": !status_changed && credentials_revoked == 0,
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
) -> Result<CreateNodeInvitationResponse, DatabaseError> {
    let now = unix_timestamp()?;
    let expires_at = now
        .checked_add(i64::from(request.expires_in_seconds))
        .ok_or(DatabaseError::TimestampOverflow)?;
    let invitation_id = NodeInvitationId::new();
    let mut secret_bytes = [0_u8; INVITATION_SECRET_BYTES];
    OsRng.fill_bytes(&mut secret_bytes);
    let invitation_secret = URL_SAFE_NO_PAD.encode(secret_bytes);
    let secret_verifier = Sha256::digest(invitation_secret.as_bytes());
    let fingerprint = identity.fingerprint();
    let network = load_network(connection)?;

    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    transaction.execute(
        "INSERT INTO node_invitations(
            invitation_id, network_id, purpose, intended_display_name, secret_verifier,
            controller_origin, controller_fingerprint, expires_at, created_at
         ) VALUES (?1, ?2, 'node-enrollment', ?3, ?4, ?5, ?6, ?7, ?8)",
        params![
            invitation_id.to_string(),
            network.network_id,
            request.display_name,
            secret_verifier.as_slice(),
            controller_origin,
            fingerprint.as_str(),
            expires_at,
            now,
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
            "purpose": "node-enrollment"
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

fn enroll_node(
    connection: &mut Connection,
    identity: &ControllerIdentity,
    request: &EnrollNodeRequest,
) -> Result<NodeEnrollmentResult, DatabaseError> {
    let now = unix_timestamp()?;
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let network = load_network(&transaction)?;
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
    } = validated
    else {
        unreachable!("existing enrollment returned above");
    };
    let created = insert_node_records(&transaction, &network.network_id, request, now)?;
    consume_invitation(&transaction, &invitation_id, created.node_id, now)?;
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
            "providerConsentPolicyVersion": request.provider_consent.policy_version
        }),
        now,
    )?;
    transaction.commit()?;
    Ok(NodeEnrollmentResult {
        response,
        created: true,
    })
}

enum ValidatedEnrollment {
    New {
        invitation_id: String,
        request_transcript: Vec<u8>,
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
    transaction
        .query_row(
            "SELECT n.node_id, c.node_credential_id, c.expires_at
             FROM nodes AS n
             JOIN node_auth_credentials AS c
               ON c.network_id = n.network_id AND c.node_id = n.node_id
             WHERE n.network_id = ?1 AND n.node_id = ?2
               AND n.identity_public_key = ?3 AND n.encryption_public_key = ?4
               AND c.identity_public_key = ?3 AND c.revoked_at IS NULL
             ORDER BY c.created_at DESC LIMIT 1",
            params![
                network_id,
                node_id,
                request.identity_public_key.as_str(),
                request.encryption_public_key.as_str(),
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
            consent_accepted_at, created_at, updated_at
         ) VALUES (?1, ?2, ?3, 'pending', ?4, ?5, ?6, ?7, ?8, ?9, 1, 1, ?10, ?11, ?11)",
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
            request
                .provider_consent
                .accepted_at
                .as_datetime()
                .unix_timestamp(),
            now,
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
    controller_origin: String,
    controller_fingerprint: String,
    expires_at: i64,
    consumed_node_id: Option<String>,
    cancelled_at: Option<i64>,
}

fn load_invitation(
    transaction: &rusqlite::Transaction<'_>,
    verifier: &[u8],
) -> Result<Option<InvitationRecord>, DatabaseError> {
    transaction
        .query_row(
            "SELECT invitation_id, controller_origin, controller_fingerprint,
                    expires_at, consumed_node_id, cancelled_at
             FROM node_invitations
             WHERE secret_verifier = ?1 AND purpose = 'node-enrollment'",
            [verifier],
            |row| {
                Ok(InvitationRecord {
                    invitation_id: row.get(0)?,
                    controller_origin: row.get(1)?,
                    controller_fingerprint: row.get(2)?,
                    expires_at: row.get(3)?,
                    consumed_node_id: row.get(4)?,
                    cancelled_at: row.get(5)?,
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
    #[error("the node request signature is invalid")]
    InvalidNodeRequestSignature,
    #[error("the node was not found")]
    NodeNotFound,
    #[error("cannot {action} a node in status {current_status}")]
    NodeLifecycleConflict {
        action: &'static str,
        current_status: String,
    },
    #[error("cannot publish desired state for a node in status {current_status}")]
    DesiredStatePublicationConflict { current_status: String },
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
