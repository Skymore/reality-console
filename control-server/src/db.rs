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
use crate::protocol_canary::{ProtocolCanaryJob, ProtocolCanaryLoopOptions, ProtocolCanaryResult};
use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::Argon2;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use control_protocol::account::{
    AccountMetadata, AccountNodeAssignment, AccountNodeAssignmentStatus,
    AccountNodeProvisioningState, AccountStatus, AccountSummary, ConsumeAccountResetTokenRequest,
    ConsumeAccountResetTokenResponse, ConsumeDeviceActivationRequest, CreateAccountRequest,
    CreateDeviceActivationRequest, CreateDeviceSessionResponse, CreateSessionRequest,
    DeviceEnrollment, EncryptedProfilePayload, IssueAccountResetTokenRequest,
    IssueAccountResetTokenResponse, MemberSetupActivation, NodeProfile, ProfileBundleManifest,
    ProfileDescriptor, ProfileEndpoint, RealityConnectionParameters, RefreshSessionRequest,
    RefreshSessionResponse, ReplaceAccountNodesRequest, ResetAccountSessionsResponse,
    SelectionHints, SessionCredentials, SetAccountPasswordRequest, SignedProfileBundle,
};
use control_protocol::account_crypto::{
    device_activation_proof_transcript, device_login_proof_transcript, encrypt_profile,
    encrypted_profile_digest, profile_bundle_signature_transcript, verify_device_activation_proof,
    AccountCryptoError,
};
use control_protocol::crypto::{Ed25519PublicKey, Sha256Digest};
use control_protocol::enrollment::{
    enrollment_request_transcript, enrollment_response_transcript, verify_enrollment_proof,
    EnrollmentCryptoError, EnrollmentInvitation,
};
use control_protocol::id::{
    AssignmentId, BundleGeneration, BundleId, ControllerInstanceId, CredentialId,
    DeviceActivationId, DeviceId, EndpointId, NetworkId, NodeId, NodeInvitationId, NodeKeyId,
    RelayGeneration, RelayGrantId, RelayRouteId, Revision, SequenceNumber, SessionId, SigningKeyId,
    Timestamp, UserId,
};
use control_protocol::idempotency::IdempotencyKey;
use control_protocol::node::{
    CreateNodeInvitationRequest, CreateNodeInvitationResponse, DesiredUser, EndpointCandidate,
    EndpointMode, EndpointReadiness, EnrollNodeRequest, EnrollNodeResponse, NodeAuthenticationMode,
    NodeCapability, NodeCredential, NodeEndpointStatus, NodeHeartbeat, NodeHeartbeatStatus,
    NodeInitialConfiguration, NodeLifecycleState, NodeRevisionFailureSummary,
    OperatorCohortRollbackRequest, OperatorNodeRollbackRequest, OperatorRollbackPublication,
    OperatorRollbackReason, OperatorRollbackResponse, OperatorRollbackTarget, PairingPurpose,
    RevisionResult, RevisionResultState, SignedDesiredState, SignedNodeHeartbeatStatus,
};
use control_protocol::node_status::node_heartbeat_status_transcript;
use control_protocol::relay::{
    AcknowledgeRelayAssignmentRequest, RelayAssignmentHeader, SignedRelayAssignment,
    SignedRelayRoute,
};
use control_protocol::request_auth::{
    verify_node_request_signature, NodeRequestAuthHeaders, NodeRequestSigningInput,
};
use control_protocol::secret::Secret;
use control_protocol::telemetry::{
    NetworkProtocol, TelemetryBatch, TelemetryBatchAcknowledgement, TelemetryCursor,
    TelemetryEventKind, TelemetryRetentionResult, TrafficAggregate, TELEMETRY_SCHEMA_VERSION,
};
use control_protocol::validation::ProtocolValidationError;
use fs2::FileExt;
use rand_core::{OsRng, RngCore as _};
use rusqlite::{params, Connection, OpenFlags, OptionalExtension, TransactionBehavior};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::fs::{self, File, OpenOptions};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};
use subtle::ConstantTimeEq as _;
use thiserror::Error;
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

pub const SCHEMA_VERSION: i64 = 15;
pub(crate) const APPLICATION_ID: i64 = 0x5243_4F4E;
const INVITATION_SECRET_BYTES: usize = 32;
const NODE_CREDENTIAL_LIFETIME_DAYS: i64 = 90;
const IDEMPOTENCY_LIFETIME_SECONDS: i64 = 24 * 60 * 60;
const BOOTSTRAP_ADMIN_PRINCIPAL: &str = "bootstrap-admin";
const CREATE_ACCOUNT_ROUTE_ID: &str = "v1.admin.accounts.create";
const NODE_ROLLBACK_ROUTE_ID: &str = "v1.admin.nodes.rollback";
const COHORT_ROLLBACK_ROUTE_ID: &str = "v1.admin.rollbacks.create";
const NODE_INVITATION_SECRET_DOMAIN: &[u8] = b"private-network/node-invitation-secret/v1\0";
const HTTP_CREATED_STATUS: i64 = 201;
const NODE_REQUEST_CLOCK_SKEW_SECONDS: i64 = 5 * 60;
const ACTIVATION_SECRET_DOMAIN: &[u8] = b"private-network/device-activation-secret/v1\0";
const ACCOUNT_RESET_SECRET_DOMAIN: &[u8] = b"private-network/account-reset-secret/v1\0";
const ACCESS_TOKEN_DOMAIN: &[u8] = b"private-network/member-access-token/v1\0";
const REFRESH_TOKEN_DOMAIN: &[u8] = b"private-network/member-refresh-token/v1\0";
const LOGIN_REQUEST_DOMAIN: &[u8] = b"private-network/member-login-request/v1\0";
const REFRESH_REQUEST_DOMAIN: &[u8] = b"private-network/member-refresh-request/v1\0";
const ACCESS_TOKEN_LIFETIME_SECONDS: i64 = 15 * 60;
const REFRESH_TOKEN_LIFETIME_SECONDS: i64 = 30 * 24 * 60 * 60;
const BUNDLE_REFRESH_SECONDS: i64 = 6 * 60 * 60;
const BUNDLE_OFFLINE_SECONDS: i64 = 7 * 24 * 60 * 60;
const TELEMETRY_HEALTH_RETENTION_DAYS: i64 = 30;
const TELEMETRY_HOURLY_RETENTION_DAYS: i64 = 90;
const TELEMETRY_DAILY_RETENTION_DAYS: i64 = 365;

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

const MIGRATION_12_SQL: &str = r"
ALTER TABLE users ADD COLUMN password_verifier TEXT
    CHECK(password_verifier IS NULL OR length(password_verifier) BETWEEN 40 AND 512);
ALTER TABLE users ADD COLUMN password_updated_at INTEGER;

CREATE TABLE device_activations (
    network_id TEXT NOT NULL,
    activation_id TEXT NOT NULL CHECK(length(activation_id) = 36),
    user_id TEXT NOT NULL,
    account_display_name TEXT NOT NULL CHECK(length(account_display_name) BETWEEN 1 AND 128),
    controller_origin TEXT NOT NULL CHECK(length(controller_origin) BETWEEN 1 AND 2048),
    controller_instance_id TEXT NOT NULL CHECK(length(controller_instance_id) = 36),
    bundle_signing_public_key TEXT NOT NULL CHECK(length(bundle_signing_public_key) = 43),
    secret_verifier BLOB NOT NULL CHECK(length(secret_verifier) = 32),
    idempotency_key_sha256 BLOB NOT NULL CHECK(length(idempotency_key_sha256) = 32),
    request_sha256 BLOB NOT NULL CHECK(length(request_sha256) = 32),
    expires_at INTEGER NOT NULL,
    consumed_at INTEGER,
    consumed_by_device_id TEXT,
    consume_request_sha256 BLOB CHECK(
        consume_request_sha256 IS NULL OR length(consume_request_sha256) = 32
    ),
    issued_session_id TEXT,
    response_account_json TEXT CHECK(
        response_account_json IS NULL OR (json_valid(response_account_json)
            AND length(response_account_json) BETWEEN 2 AND 2048)
    ),
    created_by_admin_id TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    PRIMARY KEY(network_id, activation_id),
    UNIQUE(network_id, secret_verifier),
    UNIQUE(network_id, user_id, idempotency_key_sha256),
    CHECK(expires_at > created_at),
    CHECK(
        (consumed_at IS NULL AND consumed_by_device_id IS NULL
            AND consume_request_sha256 IS NULL AND issued_session_id IS NULL
            AND response_account_json IS NULL)
        OR (consumed_at IS NOT NULL AND consumed_by_device_id IS NOT NULL
            AND consume_request_sha256 IS NOT NULL AND issued_session_id IS NOT NULL
            AND response_account_json IS NOT NULL)
    ),
    FOREIGN KEY(network_id, user_id) REFERENCES users(network_id, user_id) ON DELETE RESTRICT
) STRICT, WITHOUT ROWID;

CREATE TABLE devices (
    network_id TEXT NOT NULL,
    device_id TEXT NOT NULL CHECK(length(device_id) = 36),
    user_id TEXT NOT NULL,
    display_name TEXT NOT NULL CHECK(length(display_name) BETWEEN 1 AND 128),
    platform TEXT NOT NULL CHECK(length(platform) BETWEEN 1 AND 64),
    client_version TEXT NOT NULL CHECK(length(client_version) BETWEEN 1 AND 64),
    identity_public_key TEXT NOT NULL CHECK(length(identity_public_key) = 43),
    encryption_public_key TEXT NOT NULL CHECK(length(encryption_public_key) = 43),
    status TEXT NOT NULL CHECK(status IN ('active', 'revoked', 'deleted')),
    created_at INTEGER NOT NULL,
    last_seen_at INTEGER NOT NULL,
    revoked_at INTEGER,
    deleted_at INTEGER,
    PRIMARY KEY(network_id, device_id),
    UNIQUE(network_id, identity_public_key),
    UNIQUE(network_id, encryption_public_key),
    UNIQUE(network_id, device_id, user_id),
    CHECK(last_seen_at >= created_at),
    CHECK(
        (status = 'active' AND revoked_at IS NULL AND deleted_at IS NULL)
        OR (status = 'revoked' AND revoked_at IS NOT NULL AND deleted_at IS NULL)
        OR (status = 'deleted' AND deleted_at IS NOT NULL)
    ),
    FOREIGN KEY(network_id, user_id) REFERENCES users(network_id, user_id) ON DELETE RESTRICT
) STRICT, WITHOUT ROWID;

CREATE TABLE refresh_sessions (
    network_id TEXT NOT NULL,
    session_id TEXT NOT NULL CHECK(length(session_id) = 36),
    user_id TEXT NOT NULL,
    device_id TEXT NOT NULL,
    generation INTEGER NOT NULL CHECK(generation >= 0),
    current_refresh_verifier BLOB NOT NULL CHECK(length(current_refresh_verifier) = 32),
    previous_refresh_verifier BLOB CHECK(
        previous_refresh_verifier IS NULL OR length(previous_refresh_verifier) = 32
    ),
    current_access_verifier BLOB NOT NULL CHECK(length(current_access_verifier) = 32),
    access_expires_at INTEGER NOT NULL,
    credential_version INTEGER NOT NULL CHECK(credential_version > 0),
    created_at INTEGER NOT NULL,
    rotated_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    revoked_at INTEGER,
    revoke_reason TEXT CHECK(revoke_reason IS NULL OR length(revoke_reason) BETWEEN 1 AND 64),
    PRIMARY KEY(network_id, session_id),
    UNIQUE(network_id, current_refresh_verifier),
    UNIQUE(network_id, current_access_verifier),
    CHECK(access_expires_at > rotated_at AND expires_at > access_expires_at),
    CHECK((revoked_at IS NULL AND revoke_reason IS NULL)
        OR (revoked_at IS NOT NULL AND revoke_reason IS NOT NULL)),
    FOREIGN KEY(network_id, device_id, user_id)
        REFERENCES devices(network_id, device_id, user_id) ON DELETE RESTRICT
) STRICT, WITHOUT ROWID;

CREATE TABLE login_idempotency_records (
    network_id TEXT NOT NULL,
    idempotency_key_sha256 BLOB NOT NULL CHECK(length(idempotency_key_sha256) = 32),
    request_sha256 BLOB NOT NULL CHECK(length(request_sha256) = 32),
    user_id TEXT NOT NULL,
    device_id TEXT NOT NULL,
    session_id TEXT NOT NULL,
    response_account_json TEXT NOT NULL CHECK(
        json_valid(response_account_json) AND length(response_account_json) BETWEEN 2 AND 2048
    ),
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    PRIMARY KEY(network_id, idempotency_key_sha256),
    CHECK(expires_at > created_at),
    FOREIGN KEY(network_id, device_id, user_id)
        REFERENCES devices(network_id, device_id, user_id) ON DELETE RESTRICT,
    FOREIGN KEY(network_id, session_id)
        REFERENCES refresh_sessions(network_id, session_id) ON DELETE RESTRICT
) STRICT, WITHOUT ROWID;

CREATE TABLE refresh_idempotency_records (
    network_id TEXT NOT NULL,
    session_id TEXT NOT NULL,
    source_generation INTEGER NOT NULL CHECK(source_generation >= 0),
    idempotency_key_sha256 BLOB NOT NULL CHECK(length(idempotency_key_sha256) = 32),
    request_sha256 BLOB NOT NULL CHECK(length(request_sha256) = 32),
    response_account_json TEXT NOT NULL CHECK(
        json_valid(response_account_json) AND length(response_account_json) BETWEEN 2 AND 2048
    ),
    issued_at INTEGER NOT NULL,
    access_expires_at INTEGER NOT NULL,
    refresh_expires_at INTEGER NOT NULL,
    PRIMARY KEY(network_id, session_id, source_generation, idempotency_key_sha256),
    CHECK(issued_at < access_expires_at AND access_expires_at < refresh_expires_at),
    FOREIGN KEY(network_id, session_id)
        REFERENCES refresh_sessions(network_id, session_id) ON DELETE RESTRICT
) STRICT, WITHOUT ROWID;

CREATE TABLE profile_bundles (
    network_id TEXT NOT NULL,
    bundle_id TEXT NOT NULL CHECK(length(bundle_id) = 36),
    user_id TEXT NOT NULL,
    device_id TEXT NOT NULL,
    generation INTEGER NOT NULL CHECK(generation > 0),
    source_sha256 BLOB NOT NULL CHECK(length(source_sha256) = 32),
    artifact_json TEXT NOT NULL CHECK(json_valid(artifact_json) AND length(artifact_json) <= 1048576),
    artifact_sha256 BLOB NOT NULL CHECK(length(artifact_sha256) = 32),
    signature TEXT NOT NULL CHECK(length(signature) = 86),
    etag TEXT NOT NULL CHECK(length(etag) BETWEEN 10 AND 96),
    issued_at INTEGER NOT NULL,
    refresh_after INTEGER NOT NULL,
    offline_expires_at INTEGER NOT NULL,
    superseded_at INTEGER,
    PRIMARY KEY(network_id, bundle_id),
    UNIQUE(network_id, device_id, generation),
    UNIQUE(network_id, etag),
    CHECK(issued_at < refresh_after AND refresh_after < offline_expires_at),
    FOREIGN KEY(network_id, device_id, user_id)
        REFERENCES devices(network_id, device_id, user_id) ON DELETE RESTRICT
) STRICT, WITHOUT ROWID;

CREATE INDEX device_activations_expiry ON device_activations(network_id, expires_at)
    WHERE consumed_at IS NULL;
CREATE INDEX refresh_sessions_refresh_lookup
    ON refresh_sessions(network_id, current_refresh_verifier, previous_refresh_verifier);
CREATE INDEX login_idempotency_expiry
    ON login_idempotency_records(network_id, expires_at);
CREATE INDEX refresh_idempotency_expiry
    ON refresh_idempotency_records(network_id, refresh_expires_at);
CREATE INDEX profile_bundles_current_device
    ON profile_bundles(network_id, device_id, generation DESC) WHERE superseded_at IS NULL;
";

const MIGRATION_13_SQL: &str = r"
CREATE TABLE node_telemetry_cursors (
    network_id TEXT NOT NULL,
    node_id TEXT NOT NULL,
    acknowledged_sequence INTEGER NOT NULL DEFAULT 0
        CHECK(acknowledged_sequence >= 0),
    updated_at INTEGER NOT NULL,
    PRIMARY KEY(network_id, node_id),
    FOREIGN KEY(network_id, node_id)
        REFERENCES nodes(network_id, node_id) ON DELETE CASCADE
) STRICT, WITHOUT ROWID;

CREATE TABLE node_telemetry_events (
    network_id TEXT NOT NULL,
    node_id TEXT NOT NULL,
    sequence INTEGER NOT NULL CHECK(sequence > 0),
    event_type TEXT NOT NULL CHECK(event_type IN (
        'trafficDelta', 'connection', 'collectionStatus', 'quotaState'
    )),
    user_id TEXT,
    occurred_at INTEGER NOT NULL,
    received_at INTEGER NOT NULL,
    event_sha256 BLOB NOT NULL CHECK(length(event_sha256) = 32),
    disposition TEXT NOT NULL CHECK(disposition IN ('stored', 'droppedPolicy')),
    protocol TEXT CHECK(protocol IS NULL OR protocol IN ('tcp', 'udp')),
    destination_host TEXT CHECK(
        destination_host IS NULL OR length(destination_host) BETWEEN 1 AND 253
    ),
    destination_port INTEGER CHECK(
        destination_port IS NULL OR destination_port BETWEEN 1 AND 65535
    ),
    client_identifier TEXT CHECK(
        client_identifier IS NULL OR length(client_identifier) BETWEEN 1 AND 128
    ),
    status_code TEXT CHECK(status_code IS NULL OR length(status_code) BETWEEN 1 AND 64),
    PRIMARY KEY(network_id, node_id, sequence),
    FOREIGN KEY(network_id, node_id)
        REFERENCES nodes(network_id, node_id) ON DELETE CASCADE,
    FOREIGN KEY(network_id, user_id)
        REFERENCES users(network_id, user_id) ON DELETE RESTRICT
) STRICT, WITHOUT ROWID;

CREATE INDEX node_telemetry_events_retention
    ON node_telemetry_events(event_type, received_at);
CREATE INDEX node_telemetry_events_user
    ON node_telemetry_events(network_id, user_id, received_at);

CREATE TABLE traffic_hourly_aggregates (
    network_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    node_id TEXT NOT NULL,
    bucket_start INTEGER NOT NULL CHECK(bucket_start >= 0 AND bucket_start % 3600 = 0),
    bytes_up INTEGER NOT NULL CHECK(bytes_up >= 0),
    bytes_down INTEGER NOT NULL CHECK(bytes_down >= 0),
    connection_count INTEGER NOT NULL CHECK(connection_count >= 0),
    updated_at INTEGER NOT NULL,
    PRIMARY KEY(network_id, user_id, node_id, bucket_start),
    FOREIGN KEY(network_id, user_id)
        REFERENCES users(network_id, user_id) ON DELETE RESTRICT,
    FOREIGN KEY(network_id, node_id)
        REFERENCES nodes(network_id, node_id) ON DELETE RESTRICT
) STRICT, WITHOUT ROWID;

CREATE TABLE traffic_daily_aggregates (
    network_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    node_id TEXT NOT NULL,
    bucket_start INTEGER NOT NULL CHECK(bucket_start >= 0 AND bucket_start % 86400 = 0),
    bytes_up INTEGER NOT NULL CHECK(bytes_up >= 0),
    bytes_down INTEGER NOT NULL CHECK(bytes_down >= 0),
    connection_count INTEGER NOT NULL CHECK(connection_count >= 0),
    updated_at INTEGER NOT NULL,
    PRIMARY KEY(network_id, user_id, node_id, bucket_start),
    FOREIGN KEY(network_id, user_id)
        REFERENCES users(network_id, user_id) ON DELETE RESTRICT,
    FOREIGN KEY(network_id, node_id)
        REFERENCES nodes(network_id, node_id) ON DELETE RESTRICT
) STRICT, WITHOUT ROWID;

CREATE TABLE telemetry_policy (
    singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
    detailed_enabled INTEGER NOT NULL CHECK(detailed_enabled IN (0, 1)),
    detailed_retention_days INTEGER NOT NULL
        CHECK(detailed_retention_days BETWEEN 1 AND 90),
    updated_at INTEGER NOT NULL
) STRICT;
INSERT INTO telemetry_policy(singleton, detailed_enabled, detailed_retention_days, updated_at)
VALUES (1, 0, 30, 0);

CREATE TABLE endpoint_canary_credentials (
    network_id TEXT NOT NULL,
    node_id TEXT NOT NULL,
    user_id TEXT NOT NULL CHECK(length(user_id) = 36),
    credential_id TEXT NOT NULL CHECK(length(credential_id) = 36),
    vless_uuid TEXT NOT NULL CHECK(length(vless_uuid) = 36),
    generation INTEGER NOT NULL CHECK(generation > 0),
    status TEXT NOT NULL CHECK(status IN ('active', 'retired')),
    created_at INTEGER NOT NULL,
    retired_at INTEGER,
    PRIMARY KEY(network_id, node_id, credential_id),
    UNIQUE(network_id, node_id, generation),
    UNIQUE(network_id, node_id, vless_uuid),
    CHECK((status = 'active' AND retired_at IS NULL)
        OR (status = 'retired' AND retired_at IS NOT NULL)),
    FOREIGN KEY(network_id, node_id)
        REFERENCES nodes(network_id, node_id) ON DELETE CASCADE
) STRICT, WITHOUT ROWID;
CREATE UNIQUE INDEX endpoint_canary_credentials_active
    ON endpoint_canary_credentials(network_id, node_id) WHERE status = 'active';

CREATE TABLE node_revision_canary_credentials (
    network_id TEXT NOT NULL,
    node_id TEXT NOT NULL,
    revision INTEGER NOT NULL CHECK(revision > 0),
    credential_id TEXT NOT NULL,
    PRIMARY KEY(network_id, node_id, revision),
    FOREIGN KEY(network_id, node_id, revision)
        REFERENCES node_revision_targets(network_id, node_id, revision) ON DELETE RESTRICT,
    FOREIGN KEY(network_id, node_id, credential_id)
        REFERENCES endpoint_canary_credentials(network_id, node_id, credential_id)
        ON DELETE RESTRICT
) STRICT, WITHOUT ROWID;

CREATE TRIGGER node_revision_canary_credentials_no_update
BEFORE UPDATE ON node_revision_canary_credentials
BEGIN
    SELECT RAISE(ABORT, 'revision canary credentials are immutable');
END;
CREATE TRIGGER node_revision_canary_credentials_no_delete
BEFORE DELETE ON node_revision_canary_credentials
BEGIN
    SELECT RAISE(ABORT, 'revision canary credentials are immutable');
END;
";

const MIGRATION_14_SQL: &str = r"
CREATE TABLE account_reset_tokens (
    network_id TEXT NOT NULL REFERENCES networks(network_id) ON DELETE CASCADE,
    token_id TEXT NOT NULL CHECK(length(token_id) = 36),
    user_id TEXT NOT NULL,
    secret_verifier BLOB NOT NULL CHECK(length(secret_verifier) = 32),
    issue_idempotency_key_sha256 BLOB NOT NULL CHECK(length(issue_idempotency_key_sha256) = 32),
    issue_request_sha256 BLOB NOT NULL CHECK(length(issue_request_sha256) = 32),
    expires_at INTEGER NOT NULL,
    consumed_at INTEGER,
    consume_idempotency_key_sha256 BLOB
        CHECK(consume_idempotency_key_sha256 IS NULL OR length(consume_idempotency_key_sha256) = 32),
    consume_request_sha256 BLOB
        CHECK(consume_request_sha256 IS NULL OR length(consume_request_sha256) = 32),
    consume_response_json TEXT CHECK(
        consume_response_json IS NULL
        OR (json_valid(consume_response_json) AND length(consume_response_json) <= 65536)
    ),
    created_at INTEGER NOT NULL,
    PRIMARY KEY(network_id, token_id),
    UNIQUE(network_id, secret_verifier),
    UNIQUE(network_id, user_id, issue_idempotency_key_sha256),
    FOREIGN KEY(network_id, user_id) REFERENCES users(network_id, user_id) ON DELETE RESTRICT,
    CHECK(expires_at > created_at),
    CHECK(
        (consumed_at IS NULL AND consume_idempotency_key_sha256 IS NULL
            AND consume_request_sha256 IS NULL AND consume_response_json IS NULL)
        OR (consumed_at IS NOT NULL AND consume_idempotency_key_sha256 IS NOT NULL
            AND consume_request_sha256 IS NOT NULL AND consume_response_json IS NOT NULL)
    )
) STRICT, WITHOUT ROWID;

CREATE INDEX account_reset_tokens_expiry
    ON account_reset_tokens(network_id, expires_at) WHERE consumed_at IS NULL;
";

const MIGRATION_15_SQL: &str = r"
CREATE TABLE relay_routes (
    network_id TEXT NOT NULL REFERENCES networks(network_id) ON DELETE CASCADE,
    node_id TEXT NOT NULL,
    route_id TEXT NOT NULL CHECK(length(route_id) = 36),
    endpoint_id TEXT NOT NULL CHECK(length(endpoint_id) = 36),
    created_at INTEGER NOT NULL,
    PRIMARY KEY(network_id, node_id),
    UNIQUE(network_id, route_id),
    FOREIGN KEY(network_id, node_id) REFERENCES nodes(network_id, node_id) ON DELETE CASCADE
) STRICT, WITHOUT ROWID;

CREATE TABLE relay_grants (
    network_id TEXT NOT NULL REFERENCES networks(network_id) ON DELETE CASCADE,
    grant_id TEXT NOT NULL CHECK(length(grant_id) = 36),
    node_id TEXT NOT NULL,
    route_id TEXT NOT NULL CHECK(length(route_id) = 36),
    generation INTEGER NOT NULL CHECK(generation > 0),
    public_port INTEGER NOT NULL CHECK(public_port BETWEEN 1 AND 65535),
    state TEXT NOT NULL CHECK(state IN ('pending', 'published', 'revoking', 'revoked', 'expired')),
    header_json TEXT NOT NULL CHECK(json_valid(header_json) AND length(header_json) <= 16384),
    assignment_json TEXT NOT NULL CHECK(json_valid(assignment_json) AND length(assignment_json) <= 262144),
    route_json TEXT NOT NULL CHECK(json_valid(route_json) AND length(route_json) <= 65536),
    route_sha256 TEXT NOT NULL CHECK(length(route_sha256) = 71),
    issued_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    published_at INTEGER,
    revoked_at INTEGER,
    created_at INTEGER NOT NULL,
    PRIMARY KEY(network_id, grant_id),
    UNIQUE(network_id, route_id, generation),
    FOREIGN KEY(network_id, node_id) REFERENCES nodes(network_id, node_id) ON DELETE CASCADE,
    FOREIGN KEY(network_id, node_id) REFERENCES relay_routes(network_id, node_id) ON DELETE CASCADE,
    CHECK(expires_at > issued_at)
) STRICT, WITHOUT ROWID;

CREATE INDEX relay_grants_current_node ON relay_grants(network_id, node_id, state, expires_at DESC);
CREATE INDEX relay_grants_port ON relay_grants(network_id, public_port) WHERE state IN ('pending', 'published', 'revoking');

CREATE TABLE relay_outbox (
    network_id TEXT NOT NULL REFERENCES networks(network_id) ON DELETE CASCADE,
    grant_id TEXT NOT NULL CHECK(length(grant_id) = 36),
    action TEXT NOT NULL CHECK(action IN ('publish', 'revoke')),
    attempts INTEGER NOT NULL DEFAULT 0 CHECK(attempts >= 0),
    next_attempt_at INTEGER NOT NULL,
    completed_at INTEGER,
    created_at INTEGER NOT NULL,
    PRIMARY KEY(network_id, grant_id, action),
    FOREIGN KEY(network_id, grant_id) REFERENCES relay_grants(network_id, grant_id) ON DELETE CASCADE
) STRICT, WITHOUT ROWID;
CREATE INDEX relay_outbox_due ON relay_outbox(completed_at, next_attempt_at);
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
    Migration {
        version: 12,
        name: "member_devices_sessions_and_bundles",
        sql: MIGRATION_12_SQL,
    },
    Migration {
        version: 13,
        name: "protocol_canary_and_telemetry",
        sql: MIGRATION_13_SQL,
    },
    Migration {
        version: 14,
        name: "account_reset_tokens",
        sql: MIGRATION_14_SQL,
    },
    Migration {
        version: 15,
        name: "relay_provisioning_outbox",
        sql: MIGRATION_15_SQL,
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

/// Complete activation delivery material used internally to build a setup code.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeviceActivationDelivery {
    pub activation: MemberSetupActivation,
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AuthenticatedMember {
    pub network_id: NetworkId,
    pub user_id: UserId,
    pub device_id: DeviceId,
    pub session_id: SessionId,
}

#[derive(Clone, Debug)]
pub struct StoredProfileBundle {
    pub bundle: SignedProfileBundle,
    pub etag: String,
}

/// Non-secret facts needed to issue one node-encrypted relay grant.
#[derive(Clone, Debug)]
pub struct RelayGrantDraft {
    pub header: RelayAssignmentHeader,
    pub recipient_encryption_key: control_protocol::crypto::X25519PublicKey,
}

#[derive(Clone, Debug)]
pub struct RelayOutboxJob {
    pub grant_id: RelayGrantId,
    pub action: RelayOutboxAction,
    pub route: Option<SignedRelayRoute>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RelayOutboxAction {
    Publish,
    Revoke,
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
    pub last_failure: Option<NodeRevisionFailureSummary>,
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

    /// Creates or exactly replays one short-lived device activation.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid lifecycle, idempotency conflict, clock, or storage failure.
    pub async fn create_device_activation(
        &self,
        user_id: UserId,
        request: CreateDeviceActivationRequest,
        controller_origin: String,
        idempotency_key: IdempotencyKey,
    ) -> Result<DeviceActivationDelivery, DatabaseError> {
        request.validate()?;
        let identity = self.controller_identity.clone();
        let inner = Arc::clone(&self.inner);
        tokio::task::spawn_blocking(move || {
            let mut guard = inner.lock().map_err(|_| DatabaseError::LockPoisoned)?;
            create_device_activation(
                &mut guard.connection,
                &identity,
                user_id,
                &request,
                &controller_origin,
                &idempotency_key,
            )
        })
        .await
        .map_err(DatabaseError::Worker)?
    }

    /// Creates or exactly replays one short-lived account reset token.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid lifecycle, idempotency conflict, clock, or storage failure.
    pub async fn issue_account_reset_token(
        &self,
        user_id: UserId,
        request: IssueAccountResetTokenRequest,
        idempotency_key: IdempotencyKey,
    ) -> Result<IssueAccountResetTokenResponse, DatabaseError> {
        request.validate()?;
        let identity = self.controller_identity.clone();
        let inner = Arc::clone(&self.inner);
        tokio::task::spawn_blocking(move || {
            let mut guard = inner.lock().map_err(|_| DatabaseError::LockPoisoned)?;
            issue_account_reset_token(
                &mut guard.connection,
                &identity,
                user_id,
                &request,
                &idempotency_key,
            )
        })
        .await
        .map_err(DatabaseError::Worker)?
    }

    /// Consumes or exactly replays one account reset token and replaces the password.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid, expired, consumed, conflicting, or unavailable recovery state.
    pub async fn consume_account_reset_token(
        &self,
        request: ConsumeAccountResetTokenRequest,
        idempotency_key: IdempotencyKey,
    ) -> Result<ConsumeAccountResetTokenResponse, DatabaseError> {
        request.validate()?;
        let identity = self.controller_identity.clone();
        let inner = Arc::clone(&self.inner);
        tokio::task::spawn_blocking(move || {
            let mut guard = inner.lock().map_err(|_| DatabaseError::LockPoisoned)?;
            consume_account_reset_token(
                &mut guard.connection,
                &identity,
                &request,
                &idempotency_key,
            )
        })
        .await
        .map_err(DatabaseError::Worker)?
    }

    /// Sets or resets the optional Argon2id account password and revokes sessions.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid password, account lifecycle, hashing, or storage failure.
    pub async fn set_account_password(
        &self,
        user_id: UserId,
        request: SetAccountPasswordRequest,
    ) -> Result<(), DatabaseError> {
        request.validate()?;
        let identity = self.controller_identity.clone();
        let inner = Arc::clone(&self.inner);
        tokio::task::spawn_blocking(move || {
            let mut guard = inner.lock().map_err(|_| DatabaseError::LockPoisoned)?;
            set_account_password(&mut guard.connection, &identity, user_id, &request)
        })
        .await
        .map_err(DatabaseError::Worker)?
    }

    /// Revokes all devices and sessions so the account must be activated again.
    ///
    /// # Errors
    ///
    /// Returns an error when the account is unavailable or the transaction cannot commit.
    pub async fn reset_account_sessions(
        &self,
        user_id: UserId,
    ) -> Result<ResetAccountSessionsResponse, DatabaseError> {
        let identity = self.controller_identity.clone();
        let inner = Arc::clone(&self.inner);
        tokio::task::spawn_blocking(move || {
            let mut guard = inner.lock().map_err(|_| DatabaseError::LockPoisoned)?;
            reset_account_sessions(&mut guard.connection, &identity, user_id)
        })
        .await
        .map_err(DatabaseError::Worker)?
    }

    /// Consumes or exactly replays one activation-bound device session response.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid, expired, consumed, or incorrectly signed activation.
    pub async fn consume_device_activation(
        &self,
        request: ConsumeDeviceActivationRequest,
        controller_origin: String,
    ) -> Result<CreateDeviceSessionResponse, DatabaseError> {
        request.validate()?;
        let identity = self.controller_identity.clone();
        let inner = Arc::clone(&self.inner);
        tokio::task::spawn_blocking(move || {
            let mut guard = inner.lock().map_err(|_| DatabaseError::LockPoisoned)?;
            consume_device_activation(
                &mut guard.connection,
                &identity,
                &controller_origin,
                &request,
            )
        })
        .await
        .map_err(DatabaseError::Worker)?
    }

    /// Authenticates the optional password and enrolls a proof-bound device.
    ///
    /// # Errors
    ///
    /// Returns a generic authentication error or a proof, clock, or storage error.
    pub async fn create_member_session(
        &self,
        request: CreateSessionRequest,
        controller_origin: String,
        idempotency_key: IdempotencyKey,
    ) -> Result<CreateDeviceSessionResponse, DatabaseError> {
        request.validate()?;
        let identity = self.controller_identity.clone();
        let inner = Arc::clone(&self.inner);
        tokio::task::spawn_blocking(move || {
            let mut guard = inner.lock().map_err(|_| DatabaseError::LockPoisoned)?;
            create_member_session(
                &mut guard.connection,
                &identity,
                &controller_origin,
                &request,
                &idempotency_key,
            )
        })
        .await
        .map_err(DatabaseError::Worker)?
    }

    /// Rotates one refresh family and issues a replacement short access token.
    ///
    /// # Errors
    ///
    /// Returns an authentication error, or a reuse error after durably revoking the family.
    pub async fn refresh_member_session(
        &self,
        request: RefreshSessionRequest,
        idempotency_key: IdempotencyKey,
    ) -> Result<RefreshSessionResponse, DatabaseError> {
        request.validate()?;
        let identity = self.controller_identity.clone();
        let inner = Arc::clone(&self.inner);
        tokio::task::spawn_blocking(move || {
            let mut guard = inner.lock().map_err(|_| DatabaseError::LockPoisoned)?;
            refresh_member_session(&mut guard.connection, &identity, &request, &idempotency_key)
        })
        .await
        .map_err(DatabaseError::Worker)?
    }

    /// Authenticates a short-lived member bearer token against all lifecycle gates.
    ///
    /// # Errors
    ///
    /// Returns an authentication error for any failed token, account, device, or session gate.
    pub async fn authenticate_member(
        &self,
        access_token: String,
    ) -> Result<AuthenticatedMember, DatabaseError> {
        let identity = self.controller_identity.clone();
        let inner = Arc::clone(&self.inner);
        tokio::task::spawn_blocking(move || {
            let mut guard = inner.lock().map_err(|_| DatabaseError::LockPoisoned)?;
            authenticate_member(&mut guard.connection, &identity, &access_token)
        })
        .await
        .map_err(DatabaseError::Worker)?
    }

    /// Revokes the authenticated device's refresh family and current access token.
    ///
    /// # Errors
    ///
    /// Returns an authentication error for a different device or a durable storage error.
    pub async fn logout_member(
        &self,
        member: AuthenticatedMember,
        path_device_id: DeviceId,
    ) -> Result<(), DatabaseError> {
        let inner = Arc::clone(&self.inner);
        tokio::task::spawn_blocking(move || {
            let mut guard = inner.lock().map_err(|_| DatabaseError::LockPoisoned)?;
            revoke_member_session(&mut guard.connection, member, path_device_id, "logout")
        })
        .await
        .map_err(DatabaseError::Worker)?
    }

    /// Administratively revokes a device and all of its session families.
    ///
    /// # Errors
    ///
    /// Returns an error when the device is unknown or the transaction cannot commit.
    pub async fn revoke_member_device(&self, device_id: DeviceId) -> Result<(), DatabaseError> {
        let identity = self.controller_identity.clone();
        let inner = Arc::clone(&self.inner);
        tokio::task::spawn_blocking(move || {
            let mut guard = inner.lock().map_err(|_| DatabaseError::LockPoisoned)?;
            revoke_member_device(&mut guard.connection, &identity, device_id)
        })
        .await
        .map_err(DatabaseError::Worker)?
    }

    /// Loads or atomically publishes the current signed and device-encrypted bundle.
    ///
    /// # Errors
    ///
    /// Returns an error for failed authorization, evidence, cryptography, or durable storage.
    pub async fn member_profile_bundle(
        &self,
        member: AuthenticatedMember,
    ) -> Result<StoredProfileBundle, DatabaseError> {
        let identity = self.controller_identity.clone();
        let inner = Arc::clone(&self.inner);
        tokio::task::spawn_blocking(move || {
            let mut guard = inner.lock().map_err(|_| DatabaseError::LockPoisoned)?;
            member_profile_bundle(&mut guard.connection, &identity, member)
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

    /// Claims one endpoint whose latest TCP preflight succeeded but whose
    /// VLESS+REALITY identity is not currently verified.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid bounds, clock failure, corrupt state, or storage failure.
    pub async fn claim_protocol_canary(
        &self,
        runner_id: Uuid,
        options: ProtocolCanaryLoopOptions,
    ) -> Result<Option<ProtocolCanaryJob>, DatabaseError> {
        options
            .validate()
            .map_err(|_| DatabaseError::InvalidProbeSchedule)?;
        let inner = Arc::clone(&self.inner);
        tokio::task::spawn_blocking(move || {
            let mut guard = inner.lock().map_err(|_| DatabaseError::LockPoisoned)?;
            claim_protocol_canary(&mut guard.connection, runner_id, options)
        })
        .await
        .map_err(DatabaseError::Worker)?
    }

    /// Commits one claimed protocol result and changes publication readiness
    /// only after a successful data-plane canary.
    ///
    /// # Errors
    ///
    /// Returns an error for a forged, expired, stale, or uncommittable claim.
    pub async fn complete_protocol_canary(
        &self,
        job: ProtocolCanaryJob,
        result: ProtocolCanaryResult,
    ) -> Result<TcpProbeCompletion, DatabaseError> {
        let inner = Arc::clone(&self.inner);
        tokio::task::spawn_blocking(move || {
            let mut guard = inner.lock().map_err(|_| DatabaseError::LockPoisoned)?;
            complete_protocol_canary(&mut guard.connection, &job, result)
        })
        .await
        .map_err(DatabaseError::Worker)?
    }

    /// Rotates the node-scoped canary bearer and publishes a replacement
    /// revision before the old credential can be used again.
    ///
    /// # Errors
    ///
    /// Returns an error when the node is unavailable or publication cannot commit atomically.
    pub async fn rotate_protocol_canary(
        &self,
        node_id: NodeId,
    ) -> Result<SignedDesiredState, DatabaseError> {
        let identity = self.controller_identity.clone();
        let inner = Arc::clone(&self.inner);
        tokio::task::spawn_blocking(move || {
            let mut guard = inner.lock().map_err(|_| DatabaseError::LockPoisoned)?;
            rotate_protocol_canary(&mut guard.connection, &identity, node_id)
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

    /// Publishes a newly signed rollback revision for one explicit node.
    ///
    /// # Errors
    ///
    /// Returns an error when the source/failure evidence, compatibility, idempotency, or storage
    /// transaction is invalid.
    pub(crate) async fn rollback_node(
        &self,
        node_id: NodeId,
        request: OperatorNodeRollbackRequest,
        idempotency_key: IdempotencyKey,
    ) -> Result<OperatorRollbackResponse, DatabaseError> {
        request.validate()?;
        let target = OperatorRollbackTarget {
            node_id,
            source_revision: request.source_revision,
            failed_revision: request.failed_revision,
        };
        self.rollback_targets(
            vec![target],
            request.reason,
            idempotency_key,
            NODE_ROLLBACK_ROUTE_ID,
        )
        .await
    }

    /// Publishes newly signed rollback revisions for an explicit affected cohort.
    ///
    /// # Errors
    ///
    /// Returns an error before publication if any cohort member is invalid or incompatible.
    pub(crate) async fn rollback_cohort(
        &self,
        request: OperatorCohortRollbackRequest,
        idempotency_key: IdempotencyKey,
    ) -> Result<OperatorRollbackResponse, DatabaseError> {
        request.validate()?;
        self.rollback_targets(
            request.targets,
            request.reason,
            idempotency_key,
            COHORT_ROLLBACK_ROUTE_ID,
        )
        .await
    }

    async fn rollback_targets(
        &self,
        targets: Vec<OperatorRollbackTarget>,
        reason: OperatorRollbackReason,
        idempotency_key: IdempotencyKey,
        route_id: &'static str,
    ) -> Result<OperatorRollbackResponse, DatabaseError> {
        let identity = self.controller_identity.clone();
        let inner = Arc::clone(&self.inner);
        tokio::task::spawn_blocking(move || {
            let mut guard = inner.lock().map_err(|_| DatabaseError::LockPoisoned)?;
            operator_rollback(
                &mut guard.connection,
                &identity,
                targets,
                reason,
                &idempotency_key,
                route_id,
            )
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

    /// Returns the controller-owned durable telemetry cursor for one node.
    ///
    /// # Errors
    ///
    /// Returns an error when the node is unavailable or durable state is corrupt.
    pub async fn telemetry_cursor(
        &self,
        node_id: NodeId,
    ) -> Result<TelemetryCursor, DatabaseError> {
        let inner = Arc::clone(&self.inner);
        tokio::task::spawn_blocking(move || {
            let guard = inner.lock().map_err(|_| DatabaseError::LockPoisoned)?;
            load_telemetry_cursor(&guard.connection, node_id)
        })
        .await
        .map_err(DatabaseError::Worker)?
    }

    /// Atomically ingests, aggregates, and acknowledges one contiguous node batch.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid identity, sequence, policy, aggregate, or storage state.
    pub async fn ingest_telemetry(
        &self,
        node_id: NodeId,
        batch: TelemetryBatch,
    ) -> Result<TelemetryBatchAcknowledgement, DatabaseError> {
        batch.validate(&[TELEMETRY_SCHEMA_VERSION])?;
        if batch.node_id != node_id {
            return Err(DatabaseError::TelemetryNodeMismatch);
        }
        let inner = Arc::clone(&self.inner);
        tokio::task::spawn_blocking(move || {
            let mut guard = inner.lock().map_err(|_| DatabaseError::LockPoisoned)?;
            ingest_telemetry(&mut guard.connection, node_id, &batch)
        })
        .await
        .map_err(DatabaseError::Worker)?
    }

    /// Loads hourly or daily aggregates, optionally scoped by member or node.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid query bounds or corrupt durable aggregates.
    pub async fn traffic_aggregates(
        &self,
        bucket_seconds: u32,
        user_id: Option<UserId>,
        node_id: Option<NodeId>,
        since: i64,
    ) -> Result<Vec<TrafficAggregate>, DatabaseError> {
        let inner = Arc::clone(&self.inner);
        tokio::task::spawn_blocking(move || {
            let guard = inner.lock().map_err(|_| DatabaseError::LockPoisoned)?;
            load_traffic_aggregates(&guard.connection, bucket_seconds, user_id, node_id, since)
        })
        .await
        .map_err(DatabaseError::Worker)?
    }

    /// Deletes telemetry classes by their independent age policy.
    ///
    /// # Errors
    ///
    /// Returns an error when the retention transaction or audit write fails.
    pub async fn enforce_telemetry_retention(
        &self,
    ) -> Result<TelemetryRetentionResult, DatabaseError> {
        let inner = Arc::clone(&self.inner);
        tokio::task::spawn_blocking(move || {
            let mut guard = inner.lock().map_err(|_| DatabaseError::LockPoisoned)?;
            enforce_telemetry_retention(&mut guard.connection)
        })
        .await
        .map_err(DatabaseError::Worker)?
    }

    /// Builds an allowlisted, credential-free support document.
    ///
    /// # Errors
    ///
    /// Returns an error when allowlisted state cannot be read or serialized.
    pub async fn support_bundle(&self) -> Result<serde_json::Value, DatabaseError> {
        let inner = Arc::clone(&self.inner);
        tokio::task::spawn_blocking(move || {
            let guard = inner.lock().map_err(|_| DatabaseError::LockPoisoned)?;
            build_support_bundle(&guard.connection)
        })
        .await
        .map_err(DatabaseError::Worker)?
    }

    /// Reserves a stable route identity and returns a new grant generation only
    /// for an active, relay-capable node with recorded provider consent.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] when eligibility, allocation, or storage fails.
    #[allow(clippy::too_many_arguments)]
    pub async fn prepare_relay_grant(
        &self,
        node_id: NodeId,
        relay_id: control_protocol::id::RelayId,
        public_host: String,
        tunnel_host: String,
        tunnel_port: u16,
        tls_server_name: String,
        public_port_start: u16,
        public_port_end: u16,
        limits: control_protocol::relay::RelayLimits,
    ) -> Result<RelayGrantDraft, DatabaseError> {
        let inner = Arc::clone(&self.inner);
        tokio::task::spawn_blocking(move || {
            let mut guard = inner.lock().map_err(|_| DatabaseError::LockPoisoned)?;
            prepare_relay_grant(
                &mut guard.connection,
                node_id,
                relay_id,
                &public_host,
                &tunnel_host,
                tunnel_port,
                &tls_server_name,
                public_port_start,
                public_port_end,
                limits,
            )
        })
        .await
        .map_err(DatabaseError::Worker)?
    }

    /// Commits only encrypted node material and non-secret signed-route data,
    /// then queues durable filesystem publication.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] for invalid artifacts or failed persistence.
    pub async fn store_pending_relay_grant(
        &self,
        assignment: SignedRelayAssignment,
        route: SignedRelayRoute,
    ) -> Result<(), DatabaseError> {
        let inner = Arc::clone(&self.inner);
        tokio::task::spawn_blocking(move || {
            let mut guard = inner.lock().map_err(|_| DatabaseError::LockPoisoned)?;
            store_pending_relay_grant(&mut guard.connection, &assignment, &route)
        })
        .await
        .map_err(DatabaseError::Worker)?
    }

    /// Returns only a relay assignment that is already published and unexpired.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] when durable data is unreadable.
    pub async fn relay_assignment(
        &self,
        node_id: NodeId,
    ) -> Result<Option<SignedRelayAssignment>, DatabaseError> {
        let inner = Arc::clone(&self.inner);
        tokio::task::spawn_blocking(move || {
            let guard = inner.lock().map_err(|_| DatabaseError::LockPoisoned)?;
            relay_assignment(&guard.connection, node_id)
        })
        .await
        .map_err(DatabaseError::Worker)?
    }

    /// Moves expired grants into the revocation outbox before they can be read.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] when expiry reconciliation cannot commit.
    pub async fn expire_relay_grants(&self) -> Result<(), DatabaseError> {
        let inner = Arc::clone(&self.inner);
        tokio::task::spawn_blocking(move || {
            let mut guard = inner.lock().map_err(|_| DatabaseError::LockPoisoned)?;
            expire_relay_grants(&mut guard.connection)
        })
        .await
        .map_err(DatabaseError::Worker)?
    }

    /// Loads durable, incomplete file side effects for startup and retry repair.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] for an invalid or unreadable outbox row.
    pub async fn due_relay_outbox(&self) -> Result<Vec<RelayOutboxJob>, DatabaseError> {
        let inner = Arc::clone(&self.inner);
        tokio::task::spawn_blocking(move || {
            let guard = inner.lock().map_err(|_| DatabaseError::LockPoisoned)?;
            due_relay_outbox(&guard.connection)
        })
        .await
        .map_err(DatabaseError::Worker)?
    }

    /// Marks a verified route file as published. Predecessors remain available
    /// until the node acknowledges that this generation registered.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] unless the grant remains pending.
    pub async fn mark_relay_published(&self, grant_id: RelayGrantId) -> Result<(), DatabaseError> {
        let inner = Arc::clone(&self.inner);
        tokio::task::spawn_blocking(move || {
            let mut guard = inner.lock().map_err(|_| DatabaseError::LockPoisoned)?;
            mark_relay_published(&mut guard.connection, grant_id)
        })
        .await
        .map_err(DatabaseError::Worker)?
    }

    /// Records a node's registered-generation acknowledgement and queues only
    /// older generations of the same logical route for revocation.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] when the grant does not belong to this node,
    /// is not published, or the generation identity conflicts.
    pub async fn acknowledge_relay_assignment(
        &self,
        node_id: NodeId,
        acknowledgement: AcknowledgeRelayAssignmentRequest,
    ) -> Result<(), DatabaseError> {
        let inner = Arc::clone(&self.inner);
        tokio::task::spawn_blocking(move || {
            let mut guard = inner.lock().map_err(|_| DatabaseError::LockPoisoned)?;
            acknowledge_relay_assignment(&mut guard.connection, node_id, acknowledgement)
        })
        .await
        .map_err(DatabaseError::Worker)?
    }

    /// Marks a verified absent route file as revoked.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] when durable state cannot be updated.
    pub async fn mark_relay_revoked(&self, grant_id: RelayGrantId) -> Result<(), DatabaseError> {
        let inner = Arc::clone(&self.inner);
        tokio::task::spawn_blocking(move || {
            let mut guard = inner.lock().map_err(|_| DatabaseError::LockPoisoned)?;
            mark_relay_revoked(&mut guard.connection, grant_id)
        })
        .await
        .map_err(DatabaseError::Worker)?
    }

    /// Defers a failed route file operation using bounded exponential backoff.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] when retry metadata cannot be updated.
    pub async fn record_relay_outbox_failure(
        &self,
        grant_id: RelayGrantId,
        action: RelayOutboxAction,
    ) -> Result<(), DatabaseError> {
        let inner = Arc::clone(&self.inner);
        tokio::task::spawn_blocking(move || {
            let mut guard = inner.lock().map_err(|_| DatabaseError::LockPoisoned)?;
            record_relay_outbox_failure(&mut guard.connection, grant_id, action)
        })
        .await
        .map_err(DatabaseError::Worker)?
    }

    /// Admin revocation queues removal but never returns route or credential material.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] when the grant does not exist or cannot be queued.
    pub async fn revoke_relay_grant(&self, grant_id: RelayGrantId) -> Result<(), DatabaseError> {
        let inner = Arc::clone(&self.inner);
        tokio::task::spawn_blocking(move || {
            let mut guard = inner.lock().map_err(|_| DatabaseError::LockPoisoned)?;
            revoke_relay_grant(&mut guard.connection, grant_id)
        })
        .await
        .map_err(DatabaseError::Worker)?
    }

    #[must_use]
    pub fn controller_identity(&self) -> ControllerIdentity {
        self.controller_identity.clone()
    }
}

fn load_telemetry_cursor(
    connection: &Connection,
    node_id: NodeId,
) -> Result<TelemetryCursor, DatabaseError> {
    let network = load_network(connection)?;
    let node_exists = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM nodes
         WHERE network_id = ?1 AND node_id = ?2 AND status IN ('pending', 'active'))",
        params![network.network_id, node_id.to_string()],
        |row| row.get::<_, bool>(0),
    )?;
    if !node_exists {
        return Err(DatabaseError::NodeRevoked);
    }
    let acknowledged = connection
        .query_row(
            "SELECT acknowledged_sequence FROM node_telemetry_cursors
             WHERE network_id = ?1 AND node_id = ?2",
            params![network.network_id, node_id.to_string()],
            |row| row.get::<_, i64>(0),
        )
        .optional()?
        .unwrap_or(0);
    telemetry_cursor_from_acknowledged(acknowledged)
}

fn telemetry_cursor_from_acknowledged(acknowledged: i64) -> Result<TelemetryCursor, DatabaseError> {
    let acknowledged_sequence =
        SequenceNumber::new(acknowledged).map_err(|_| DatabaseError::StoredProtocolValue)?;
    let expected_sequence = acknowledged_sequence
        .checked_next()
        .ok_or(DatabaseError::TelemetrySequenceExhausted)?;
    let cursor = TelemetryCursor {
        acknowledged_sequence,
        expected_sequence,
    };
    cursor.validate()?;
    Ok(cursor)
}

fn ingest_telemetry(
    connection: &mut Connection,
    node_id: NodeId,
    batch: &TelemetryBatch,
) -> Result<TelemetryBatchAcknowledgement, DatabaseError> {
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
    if matches!(node_status.as_str(), "disabled" | "revoked") {
        return Err(DatabaseError::NodeRevoked);
    }
    transaction.execute(
        "INSERT INTO node_telemetry_cursors(
            network_id, node_id, acknowledged_sequence, updated_at
         ) VALUES (?1, ?2, 0, ?3)
         ON CONFLICT(network_id, node_id) DO NOTHING",
        params![network.network_id, node_id_text, now],
    )?;
    let acknowledged: i64 = transaction.query_row(
        "SELECT acknowledged_sequence FROM node_telemetry_cursors
         WHERE network_id = ?1 AND node_id = ?2",
        params![network.network_id, node_id_text],
        |row| row.get(0),
    )?;
    if batch.last_sequence.get() <= acknowledged {
        transaction.commit()?;
        let cursor = telemetry_cursor_from_acknowledged(acknowledged)?;
        return Ok(TelemetryBatchAcknowledgement {
            acknowledged_sequence: cursor.acknowledged_sequence,
            expected_sequence: cursor.expected_sequence,
        });
    }
    let expected = acknowledged
        .checked_add(1)
        .ok_or(DatabaseError::TelemetrySequenceExhausted)?;
    if batch.first_sequence.get() != expected {
        return Err(DatabaseError::TelemetrySequenceGap { expected });
    }
    let detailed_enabled: bool = transaction.query_row(
        "SELECT detailed_enabled FROM telemetry_policy WHERE singleton = 1",
        [],
        |row| row.get(0),
    )?;
    for event in &batch.events {
        persist_telemetry_event(
            &transaction,
            &network.network_id,
            node_id,
            event,
            detailed_enabled,
            now,
        )?;
    }
    let updated = transaction.execute(
        "UPDATE node_telemetry_cursors
         SET acknowledged_sequence = ?1, updated_at = ?2
         WHERE network_id = ?3 AND node_id = ?4 AND acknowledged_sequence = ?5",
        params![
            batch.last_sequence.get(),
            now,
            network.network_id,
            node_id_text,
            acknowledged,
        ],
    )?;
    if updated != 1 {
        return Err(DatabaseError::TelemetryCursorConflict);
    }
    transaction.commit()?;
    let cursor = telemetry_cursor_from_acknowledged(batch.last_sequence.get())?;
    Ok(TelemetryBatchAcknowledgement {
        acknowledged_sequence: cursor.acknowledged_sequence,
        expected_sequence: cursor.expected_sequence,
    })
}

#[allow(clippy::too_many_lines)]
fn persist_telemetry_event(
    connection: &Connection,
    network_id: &str,
    node_id: NodeId,
    event: &control_protocol::telemetry::TelemetryEvent,
    detailed_enabled: bool,
    received_at: i64,
) -> Result<(), DatabaseError> {
    let occurred_at = event.occurred_at.as_datetime().unix_timestamp();
    if occurred_at > received_at.saturating_add(86_400) {
        return Err(DatabaseError::TelemetryClockSkew);
    }
    let serialized = serde_json::to_vec(event)?;
    let event_digest: [u8; 32] = Sha256::digest(&serialized).into();
    let node_id_text = node_id.to_string();
    let (
        event_type,
        user_id,
        disposition,
        protocol,
        destination_host,
        destination_port,
        client_identifier,
        status_code,
    ) = match &event.kind {
        TelemetryEventKind::TrafficDelta { user_id, .. } => {
            validate_telemetry_user(connection, network_id, node_id, *user_id)?;
            (
                "trafficDelta",
                Some(user_id.to_string()),
                "stored",
                None,
                None,
                None,
                None,
                None,
            )
        }
        TelemetryEventKind::Connection {
            user_id,
            protocol,
            destination_host,
            destination_port,
            client_identifier,
        } => {
            validate_telemetry_user(connection, network_id, node_id, *user_id)?;
            if detailed_enabled {
                (
                    "connection",
                    Some(user_id.to_string()),
                    "stored",
                    Some(match protocol {
                        NetworkProtocol::Tcp => "tcp",
                        NetworkProtocol::Udp => "udp",
                    }),
                    Some(destination_host.as_str()),
                    Some(*destination_port),
                    client_identifier.as_deref(),
                    None,
                )
            } else {
                (
                    "connection",
                    Some(user_id.to_string()),
                    "droppedPolicy",
                    None,
                    None,
                    None,
                    None,
                    None,
                )
            }
        }
        TelemetryEventKind::CollectionStatus { code, .. } => (
            "collectionStatus",
            None,
            "stored",
            None,
            None,
            None,
            None,
            Some(code.as_str()),
        ),
        TelemetryEventKind::QuotaState { user_id, .. } => {
            validate_telemetry_user(connection, network_id, node_id, *user_id)?;
            (
                "quotaState",
                Some(user_id.to_string()),
                "stored",
                None,
                None,
                None,
                None,
                None,
            )
        }
    };
    connection.execute(
        "INSERT INTO node_telemetry_events(
            network_id, node_id, sequence, event_type, user_id, occurred_at,
            received_at, event_sha256, disposition, protocol, destination_host,
            destination_port, client_identifier, status_code
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)",
        params![
            network_id,
            node_id_text,
            event.sequence.get(),
            event_type,
            user_id,
            occurred_at,
            received_at,
            event_digest.as_slice(),
            disposition,
            protocol,
            destination_host,
            destination_port,
            client_identifier,
            status_code,
        ],
    )?;
    if let TelemetryEventKind::TrafficDelta {
        user_id,
        bytes_up,
        bytes_down,
        connection_count,
    } = event.kind
    {
        upsert_traffic_aggregate(
            connection,
            "traffic_hourly_aggregates",
            network_id,
            user_id,
            node_id,
            occurred_at - occurred_at.rem_euclid(3_600),
            bytes_up,
            bytes_down,
            connection_count,
            received_at,
        )?;
        upsert_traffic_aggregate(
            connection,
            "traffic_daily_aggregates",
            network_id,
            user_id,
            node_id,
            occurred_at - occurred_at.rem_euclid(86_400),
            bytes_up,
            bytes_down,
            connection_count,
            received_at,
        )?;
    }
    Ok(())
}

fn validate_telemetry_user(
    connection: &Connection,
    network_id: &str,
    node_id: NodeId,
    user_id: UserId,
) -> Result<(), DatabaseError> {
    let assigned: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM user_node_assignments
         WHERE network_id = ?1 AND node_id = ?2 AND user_id = ?3)",
        params![network_id, node_id.to_string(), user_id.to_string()],
        |row| row.get(0),
    )?;
    if !assigned {
        return Err(DatabaseError::TelemetryUserNotAssigned);
    }
    Ok(())
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
fn upsert_traffic_aggregate(
    connection: &Connection,
    table: &'static str,
    network_id: &str,
    user_id: UserId,
    node_id: NodeId,
    bucket_start: i64,
    bytes_up: control_protocol::id::Count,
    bytes_down: control_protocol::id::Count,
    connection_count: control_protocol::id::Count,
    updated_at: i64,
) -> Result<(), DatabaseError> {
    let sql = format!(
        "INSERT INTO {table}(
            network_id, user_id, node_id, bucket_start, bytes_up,
            bytes_down, connection_count, updated_at
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
         ON CONFLICT(network_id, user_id, node_id, bucket_start) DO UPDATE SET
            bytes_up = bytes_up + excluded.bytes_up,
            bytes_down = bytes_down + excluded.bytes_down,
            connection_count = connection_count + excluded.connection_count,
            updated_at = excluded.updated_at"
    );
    connection.execute(
        &sql,
        params![
            network_id,
            user_id.to_string(),
            node_id.to_string(),
            bucket_start,
            bytes_up.get(),
            bytes_down.get(),
            connection_count.get(),
            updated_at,
        ],
    )?;
    Ok(())
}

fn load_traffic_aggregates(
    connection: &Connection,
    bucket_seconds: u32,
    user_id: Option<UserId>,
    node_id: Option<NodeId>,
    since: i64,
) -> Result<Vec<TrafficAggregate>, DatabaseError> {
    if !matches!(bucket_seconds, 3_600 | 86_400) || since < 0 {
        return Err(DatabaseError::InvalidTelemetryQuery);
    }
    let table = if bucket_seconds == 3_600 {
        "traffic_hourly_aggregates"
    } else {
        "traffic_daily_aggregates"
    };
    let network = load_network(connection)?;
    let sql = format!(
        "SELECT user_id, node_id, bucket_start, bytes_up, bytes_down, connection_count
         FROM {table}
         WHERE network_id = ?1 AND bucket_start >= ?2
           AND (?3 IS NULL OR user_id = ?3)
           AND (?4 IS NULL OR node_id = ?4)
         ORDER BY bucket_start, user_id, node_id LIMIT 10000"
    );
    let user_filter = user_id.map(|value| value.to_string());
    let node_filter = node_id.map(|value| value.to_string());
    let mut statement = connection.prepare(&sql)?;
    let rows = statement.query_map(
        params![network.network_id, since, user_filter, node_filter],
        |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, i64>(4)?,
                row.get::<_, i64>(5)?,
            ))
        },
    )?;
    rows.map(|row| {
        let row = row?;
        let aggregate = TrafficAggregate {
            user_id: row
                .0
                .parse()
                .map_err(|_| DatabaseError::StoredProtocolValue)?,
            node_id: row
                .1
                .parse()
                .map_err(|_| DatabaseError::StoredProtocolValue)?,
            bucket_start: row.2,
            bucket_seconds,
            bytes_up: control_protocol::id::Count::new(row.3)
                .map_err(|_| DatabaseError::StoredProtocolValue)?,
            bytes_down: control_protocol::id::Count::new(row.4)
                .map_err(|_| DatabaseError::StoredProtocolValue)?,
            connection_count: control_protocol::id::Count::new(row.5)
                .map_err(|_| DatabaseError::StoredProtocolValue)?,
        };
        aggregate.validate()?;
        Ok(aggregate)
    })
    .collect()
}

fn enforce_telemetry_retention(
    connection: &mut Connection,
) -> Result<TelemetryRetentionResult, DatabaseError> {
    enforce_telemetry_retention_at(connection, unix_timestamp()?)
}

fn enforce_telemetry_retention_at(
    connection: &mut Connection,
    now: i64,
) -> Result<TelemetryRetentionResult, DatabaseError> {
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let detailed_days: i64 = transaction.query_row(
        "SELECT detailed_retention_days FROM telemetry_policy WHERE singleton = 1",
        [],
        |row| row.get(0),
    )?;
    let detailed_events_deleted = transaction.execute(
        "DELETE FROM node_telemetry_events
         WHERE event_type = 'connection' AND received_at < ?1",
        [now.saturating_sub(detailed_days.saturating_mul(86_400))],
    )?;
    let traffic_events_deleted = transaction.execute(
        "DELETE FROM node_telemetry_events
         WHERE event_type = 'trafficDelta' AND received_at < ?1",
        [now.saturating_sub(TELEMETRY_HOURLY_RETENTION_DAYS * 86_400)],
    )?;
    let health_events_deleted = transaction.execute(
        "DELETE FROM node_telemetry_events
         WHERE event_type IN ('collectionStatus', 'quotaState') AND received_at < ?1",
        [now.saturating_sub(TELEMETRY_HEALTH_RETENTION_DAYS * 86_400)],
    )?;
    let hourly_aggregates_deleted = transaction.execute(
        "DELETE FROM traffic_hourly_aggregates WHERE bucket_start < ?1",
        [aligned_retention_cutoff(
            now,
            TELEMETRY_HOURLY_RETENTION_DAYS,
            3_600,
        )],
    )?;
    let daily_aggregates_deleted = transaction.execute(
        "DELETE FROM traffic_daily_aggregates WHERE bucket_start < ?1",
        [aligned_retention_cutoff(
            now,
            TELEMETRY_DAILY_RETENTION_DAYS,
            86_400,
        )],
    )?;
    let result = TelemetryRetentionResult {
        traffic_events_deleted: u64::try_from(traffic_events_deleted)
            .map_err(|_| DatabaseError::TelemetryResultOverflow)?,
        detailed_events_deleted: u64::try_from(detailed_events_deleted)
            .map_err(|_| DatabaseError::TelemetryResultOverflow)?,
        health_events_deleted: u64::try_from(health_events_deleted)
            .map_err(|_| DatabaseError::TelemetryResultOverflow)?,
        hourly_aggregates_deleted: u64::try_from(hourly_aggregates_deleted)
            .map_err(|_| DatabaseError::TelemetryResultOverflow)?,
        daily_aggregates_deleted: u64::try_from(daily_aggregates_deleted)
            .map_err(|_| DatabaseError::TelemetryResultOverflow)?,
    };
    let network = load_network(&transaction)?;
    insert_audit_event(
        &transaction,
        Some(&network.network_id),
        "system",
        None,
        "telemetry.retention-enforced",
        "telemetry",
        None,
        "success",
        &serde_json::to_value(result)?,
        now,
    )?;
    transaction.commit()?;
    Ok(result)
}

fn aligned_retention_cutoff(now: i64, retention_days: i64, bucket_seconds: i64) -> i64 {
    let cutoff = now.saturating_sub(retention_days.saturating_mul(86_400));
    cutoff - cutoff.rem_euclid(bucket_seconds)
}

fn build_support_bundle(connection: &Connection) -> Result<serde_json::Value, DatabaseError> {
    let network = load_network(connection)?;
    let policy: (bool, i64) = connection.query_row(
        "SELECT detailed_enabled, detailed_retention_days
         FROM telemetry_policy WHERE singleton = 1",
        [],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    let counts: (i64, i64, i64, i64) = connection.query_row(
        "SELECT
            (SELECT COUNT(*) FROM nodes),
            (SELECT COUNT(*) FROM users WHERE status != 'deleted'),
            (SELECT COUNT(*) FROM node_telemetry_events),
            (SELECT COUNT(*) FROM audit_events)",
        [],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
    )?;
    let mut statement = connection.prepare(
        "SELECT node_id, status, agent_version, xray_version, runtime_state,
                desired_revision, applied_revision, last_seen_at
         FROM nodes ORDER BY node_id",
    )?;
    let nodes = statement
        .query_map([], |row| {
            Ok(serde_json::json!({
                "nodeId": row.get::<_, String>(0)?,
                "status": row.get::<_, String>(1)?,
                "agentVersion": row.get::<_, String>(2)?,
                "xrayVersion": row.get::<_, Option<String>>(3)?,
                "runtimeState": row.get::<_, Option<String>>(4)?,
                "desiredRevision": row.get::<_, Option<i64>>(5)?,
                "appliedRevision": row.get::<_, Option<i64>>(6)?,
                "lastSeenAt": row.get::<_, Option<i64>>(7)?,
            }))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(serde_json::json!({
        "schemaVersion": 1,
        "generatedAt": unix_timestamp()?,
        "control": {
            "databaseSchemaVersion": SCHEMA_VERSION,
            "networkStatus": network.status,
            "lastRevision": network.last_revision,
        },
        "counts": {
            "nodes": counts.0,
            "accounts": counts.1,
            "retainedTelemetryEvents": counts.2,
            "auditEvents": counts.3,
        },
        "telemetryPolicy": {
            "detailedEnabled": policy.0,
            "detailedRetentionDays": policy.1,
            "hourlyRetentionDays": TELEMETRY_HOURLY_RETENTION_DAYS,
            "dailyRetentionDays": TELEMETRY_DAILY_RETENTION_DAYS,
        },
        "nodes": nodes,
    }))
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
  AND (
      (c.mode = 'direct'
       AND revision.schema_version = 2
       AND json_type(revision.artifact_json, '$.document.xray.publicPort') = 'integer'
       AND json_extract(revision.artifact_json, '$.document.xray.publicPort') = c.port)
      OR (c.mode = 'relay' AND c.source = 'relay')
  )
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

#[allow(clippy::too_many_lines)]
fn claim_protocol_canary(
    connection: &mut Connection,
    runner_id: Uuid,
    options: ProtocolCanaryLoopOptions,
) -> Result<Option<ProtocolCanaryJob>, DatabaseError> {
    let now = unix_timestamp()?;
    let claim_expires_at = now
        .checked_add(probe_duration_seconds(options.claim_lease)?)
        .ok_or(DatabaseError::TimestampOverflow)?;
    let online_cutoff = now
        .checked_sub(probe_duration_seconds(options.node_online_window)?)
        .ok_or(DatabaseError::TimestampOverflow)?;
    let tcp_cutoff = now
        .checked_sub(probe_duration_seconds(options.success_interval)?)
        .ok_or(DatabaseError::TimestampOverflow)?;
    let success_interval = probe_duration_seconds(options.success_interval)?;
    let failure_interval = probe_duration_seconds(options.failure_interval)?;
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    expire_stale_probe_claims(&transaction, now)?;
    let stored = transaction
        .query_row(
            "SELECT c.network_id, c.node_id, c.endpoint_id, c.address, c.port,
                    c.applied_revision, c.last_report_generation,
                    tcp.resolved_address, credential.vless_uuid,
                    node.reality_public_key, node.reality_short_id,
                    json_extract(revision.artifact_json, '$.document.xray.serverNames[0]')
             FROM node_endpoint_candidates AS c
             JOIN nodes AS node ON node.network_id = c.network_id AND node.node_id = c.node_id
             JOIN config_revisions AS revision
               ON revision.network_id = c.network_id AND revision.node_id = c.node_id
              AND revision.revision = c.applied_revision
             JOIN node_revision_canary_credentials AS snapshot
               ON snapshot.network_id = c.network_id AND snapshot.node_id = c.node_id
              AND snapshot.revision = c.applied_revision
             JOIN endpoint_canary_credentials AS credential
               ON credential.network_id = snapshot.network_id
              AND credential.node_id = snapshot.node_id
              AND credential.credential_id = snapshot.credential_id
             JOIN endpoint_probe_attempts AS tcp ON tcp.attempt_id = (
                 SELECT latest.attempt_id FROM endpoint_probe_attempts AS latest
                 WHERE latest.network_id = c.network_id AND latest.node_id = c.node_id
                   AND latest.endpoint_id = c.endpoint_id AND latest.phase = 'tcp'
                   AND latest.status = 'succeeded'
                   AND latest.applied_revision = c.applied_revision
                   AND latest.address = c.address AND latest.port = c.port
                 ORDER BY latest.attempt_id DESC LIMIT 1
             )
             JOIN node_endpoint_verifications AS verification
               ON verification.network_id = c.network_id
              AND verification.node_id = c.node_id
              AND verification.endpoint_id = c.endpoint_id
             WHERE c.mode IN ('direct', 'relay') AND c.withdrawn_at IS NULL
               AND (c.expires_at IS NULL OR c.expires_at > ?1)
               AND node.status = 'active' AND node.runtime_state = 'serving'
               AND node.provider_paused = 0 AND node.last_seen_at >= ?2
               AND node.applied_revision = c.applied_revision
               AND node.last_heartbeat_generation = c.last_report_generation
               AND credential.status = 'active'
               AND tcp.completed_at >= ?3 AND tcp.resolved_address IS NOT NULL
               AND verification.status != 'withdrawn'
               AND NOT EXISTS(
                   SELECT 1 FROM endpoint_probe_attempts AS active
                   WHERE active.network_id = c.network_id
                     AND active.node_id = c.node_id AND active.status = 'claimed'
               )
               AND COALESCE((
                   SELECT previous.started_at + CASE
                       WHEN previous.status = 'succeeded' THEN ?4 ELSE ?5 END
                   FROM endpoint_probe_attempts AS previous
                   WHERE previous.network_id = c.network_id
                     AND previous.node_id = c.node_id
                     AND previous.endpoint_id = c.endpoint_id
                     AND previous.phase = 'protocol'
                   ORDER BY previous.attempt_id DESC LIMIT 1
               ), 0) <= ?1
             ORDER BY COALESCE((
                 SELECT MAX(previous.attempt_id) FROM endpoint_probe_attempts AS previous
                 WHERE previous.network_id = c.network_id
                   AND previous.node_id = c.node_id
                   AND previous.endpoint_id = c.endpoint_id
                   AND previous.phase = 'protocol'
             ), 0), c.first_reported_at, c.endpoint_id
             LIMIT 1",
            params![
                now,
                online_cutoff,
                tcp_cutoff,
                success_interval,
                failure_interval
            ],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, i64>(5)?,
                    row.get::<_, i64>(6)?,
                    row.get::<_, String>(7)?,
                    row.get::<_, String>(8)?,
                    row.get::<_, String>(9)?,
                    row.get::<_, String>(10)?,
                    row.get::<_, String>(11)?,
                ))
            },
        )
        .optional()?;
    let Some(stored) = stored else {
        transaction.commit()?;
        return Ok(None);
    };
    let network_id = stored
        .0
        .parse::<NetworkId>()
        .map_err(|_| DatabaseError::StoredProtocolValue)?;
    let node_id = stored
        .1
        .parse::<NodeId>()
        .map_err(|_| DatabaseError::StoredProtocolValue)?;
    let endpoint_id = stored
        .2
        .parse::<EndpointId>()
        .map_err(|_| DatabaseError::StoredProtocolValue)?;
    let port = u16::try_from(stored.4).map_err(|_| DatabaseError::StoredProtocolValue)?;
    let applied_revision =
        Revision::new(stored.5).map_err(|_| DatabaseError::StoredProtocolValue)?;
    let resolved_address = stored
        .7
        .parse::<IpAddr>()
        .map_err(|_| DatabaseError::StoredProtocolValue)?;
    let probe_id = Uuid::new_v4();
    let mut claim_token = [0_u8; 32];
    OsRng.fill_bytes(&mut claim_token);
    let claim_token_digest: [u8; 32] = Sha256::digest(claim_token).into();
    transaction.execute(
        "INSERT INTO endpoint_probe_attempts(
            network_id, probe_id, node_id, endpoint_id, phase, status, runner_id,
            claim_token_sha256, candidate_generation, address, port,
            applied_revision, started_at, claim_expires_at
         ) VALUES (?1, ?2, ?3, ?4, 'protocol', 'claimed', ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
        params![
            network_id.to_string(),
            probe_id.to_string(),
            node_id.to_string(),
            endpoint_id.to_string(),
            runner_id.to_string(),
            claim_token_digest.as_slice(),
            stored.6,
            stored.3,
            i64::from(port),
            applied_revision.get(),
            now,
            claim_expires_at,
        ],
    )?;
    transaction.commit()?;
    Ok(Some(ProtocolCanaryJob {
        probe_id,
        runner_id,
        network_id,
        node_id,
        endpoint_id,
        address: stored.3,
        resolved_address,
        port,
        applied_revision,
        candidate_generation: stored.6,
        claim_expires_at,
        claim_token: Secret::new(claim_token),
        vless_uuid: Secret::new(stored.8),
        reality_public_key: stored.9,
        reality_short_id: stored.10,
        server_name: stored.11,
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

    fn authenticates_protocol(&self, job: &ProtocolCanaryJob) -> bool {
        let submitted_digest: [u8; 32] = Sha256::digest(job.claim_token.expose_secret()).into();
        bool::from(
            self.claim_digest
                .as_slice()
                .ct_eq(submitted_digest.as_slice()),
        ) && self.node_id == job.node_id.to_string()
            && self.endpoint_id == job.endpoint_id.to_string()
            && self.phase == "protocol"
            && self.runner_id == job.runner_id.to_string()
            && self.candidate_generation == job.candidate_generation
            && self.address == job.address
            && self.port == i64::from(job.port)
            && self.applied_revision == job.applied_revision.get()
            && self.claim_expires_at == job.claim_expires_at
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

fn complete_protocol_canary(
    connection: &mut Connection,
    job: &ProtocolCanaryJob,
    result: ProtocolCanaryResult,
) -> Result<TcpProbeCompletion, DatabaseError> {
    let now = unix_timestamp()?;
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let stored = load_protocol_claim(&transaction, job)?;
    if !stored.authenticates_protocol(job) {
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
        finish_protocol_attempt(&transaction, job, &ProbeTerminalResult::expired(), now)?;
        transaction.commit()?;
        return Ok(TcpProbeCompletion::ClaimExpired);
    }
    let tcp_shape = TcpProbeJob {
        probe_id: job.probe_id,
        runner_id: job.runner_id,
        network_id: job.network_id,
        node_id: job.node_id,
        endpoint_id: job.endpoint_id,
        address: job.address.clone(),
        port: job.port,
        applied_revision: job.applied_revision,
        candidate_generation: job.candidate_generation,
        claim_expires_at: job.claim_expires_at,
        claim_token: job.claim_token.clone(),
    };
    if !probe_candidate_is_current(&transaction, &tcp_shape, now)?
        || !protocol_canary_credential_is_current(&transaction, job)?
    {
        finish_protocol_attempt(
            &transaction,
            job,
            &ProbeTerminalResult::candidate_changed(),
            now,
        )?;
        transaction.commit()?;
        return Ok(TcpProbeCompletion::CandidateChanged);
    }
    let terminal = match result {
        ProtocolCanaryResult::Connected { latency } => ProbeTerminalResult {
            status: "succeeded",
            resolved_address: Some(job.resolved_address.to_string()),
            latency_ms: Some(probe_duration_millis(latency)?),
            result_code: "direct_protocol_connected",
        },
        ProtocolCanaryResult::Failed { code } => ProbeTerminalResult {
            status: "failed",
            resolved_address: Some(job.resolved_address.to_string()),
            latency_ms: None,
            result_code: code.as_str(),
        },
    };
    finish_protocol_attempt(&transaction, job, &terminal, now)?;
    update_protocol_verification(&transaction, job, &terminal, now)?;
    transaction.commit()?;
    Ok(TcpProbeCompletion::Recorded)
}

fn load_protocol_claim(
    transaction: &rusqlite::Transaction<'_>,
    job: &ProtocolCanaryJob,
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

fn protocol_canary_credential_is_current(
    connection: &Connection,
    job: &ProtocolCanaryJob,
) -> Result<bool, DatabaseError> {
    connection
        .query_row(
            "SELECT EXISTS(
                SELECT 1 FROM node_revision_canary_credentials AS snapshot
                JOIN endpoint_canary_credentials AS credential
                  ON credential.network_id = snapshot.network_id
                 AND credential.node_id = snapshot.node_id
                 AND credential.credential_id = snapshot.credential_id
                WHERE snapshot.network_id = ?1 AND snapshot.node_id = ?2
                  AND snapshot.revision = ?3 AND credential.status = 'active'
                  AND credential.vless_uuid = ?4
            )",
            params![
                job.network_id.to_string(),
                job.node_id.to_string(),
                job.applied_revision.get(),
                job.vless_uuid.expose_secret(),
            ],
            |row| row.get(0),
        )
        .map_err(DatabaseError::from)
}

fn finish_protocol_attempt(
    transaction: &rusqlite::Transaction<'_>,
    job: &ProtocolCanaryJob,
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

fn update_protocol_verification(
    connection: &Connection,
    job: &ProtocolCanaryJob,
    result: &ProbeTerminalResult,
    now: i64,
) -> Result<(), DatabaseError> {
    let verification_expires_at = now
        .checked_add(15 * 60)
        .ok_or(DatabaseError::TimestampOverflow)?;
    let updated = if result.status == "succeeded" {
        connection.execute(
            "UPDATE node_endpoint_verifications
             SET status = 'verified', probe_attempts = probe_attempts + 1,
                 last_probe_at = ?1, last_success_at = ?1, latency_ms = ?2,
                 error_code = NULL, verification_expires_at = ?3, updated_at = ?1
             WHERE network_id = ?4 AND node_id = ?5 AND endpoint_id = ?6
               AND status != 'withdrawn'",
            params![
                now,
                result.latency_ms,
                verification_expires_at,
                job.network_id.to_string(),
                job.node_id.to_string(),
                job.endpoint_id.to_string(),
            ],
        )?
    } else {
        connection.execute(
            "UPDATE node_endpoint_verifications
             SET status = 'failed', probe_attempts = probe_attempts + 1,
                 last_probe_at = ?1, latency_ms = NULL, error_code = ?2,
                 verification_expires_at = NULL, updated_at = ?1
             WHERE network_id = ?3 AND node_id = ?4 AND endpoint_id = ?5
               AND status != 'withdrawn'",
            params![
                now,
                result.result_code,
                job.network_id.to_string(),
                job.node_id.to_string(),
                job.endpoint_id.to_string(),
            ],
        )?
    };
    if updated != 1 {
        return Err(DatabaseError::ProbeClaimConflict);
    }
    Ok(())
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
                   AND c.address = ?4 AND c.port = ?5 AND c.applied_revision = ?6
                   AND c.last_report_generation = ?7
                   AND (
                       (c.mode = 'direct'
                        AND revision.schema_version = 2
                        AND json_type(
                            revision.artifact_json, '$.document.xray.publicPort'
                        ) = 'integer'
                        AND json_extract(
                            revision.artifact_json, '$.document.xray.publicPort'
                        ) = c.port)
                       OR (c.mode = 'relay' AND c.source = 'relay')
                   )
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

struct PreparedRollback {
    target: OperatorRollbackTarget,
    configuration: DesiredStateConfigurationDraft,
}

#[allow(clippy::too_many_lines)]
fn operator_rollback(
    connection: &mut Connection,
    identity: &ControllerIdentity,
    mut targets: Vec<OperatorRollbackTarget>,
    reason: OperatorRollbackReason,
    idempotency_key: &IdempotencyKey,
    route_id: &'static str,
) -> Result<OperatorRollbackResponse, DatabaseError> {
    targets.sort_by_key(|target| target.node_id);
    let now = unix_timestamp()?;
    let expires_at = now
        .checked_add(IDEMPOTENCY_LIFETIME_SECONDS)
        .ok_or(DatabaseError::TimestampOverflow)?;
    let key_digest: [u8; 32] = Sha256::digest(idempotency_key.as_str().as_bytes()).into();
    let request_digest =
        canonical_request_digest(b"operator-rollback/v1\0", &(targets.clone(), reason))?;
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let mut network = load_network(&transaction)?;
    if let Some(response) = load_rollback_replay(
        &transaction,
        &network.network_id,
        route_id,
        &key_digest,
        &request_digest,
    )? {
        transaction.commit()?;
        return Ok(response);
    }

    let mut prepared = Vec::with_capacity(targets.len());
    for target in targets {
        match prepare_rollback_target(&transaction, identity, &network, &target) {
            Ok(configuration) => prepared.push(PreparedRollback {
                target,
                configuration,
            }),
            Err(error) => {
                insert_audit_event(
                    &transaction,
                    Some(&network.network_id),
                    "admin",
                    Some(BOOTSTRAP_ADMIN_PRINCIPAL),
                    "node.operator-rollback-rejected",
                    "node",
                    Some(&target.node_id.to_string()),
                    "rejected",
                    &serde_json::json!({
                        "failedRevision": target.failed_revision,
                        "reason": enum_wire(&reason)?,
                        "rejectionCode": rollback_rejection_code(&error),
                        "sourceRevision": target.source_revision,
                    }),
                    now,
                )?;
                transaction.commit()?;
                return Err(error);
            }
        }
    }

    let mut publications = Vec::with_capacity(prepared.len());
    for prepared in prepared {
        let users =
            compile_desired_users(&transaction, &network.network_id, prepared.target.node_id)?;
        let desired = publish_compiled_desired_state(
            &transaction,
            identity,
            &mut network,
            prepared.target.node_id,
            prepared.configuration,
            &users,
            "operator-rollback",
            now,
        )?;
        let publication = OperatorRollbackPublication {
            node_id: prepared.target.node_id,
            source_revision: prepared.target.source_revision,
            failed_revision: prepared.target.failed_revision,
            revision: desired.document.revision,
        };
        insert_audit_event(
            &transaction,
            Some(&network.network_id),
            "admin",
            Some(BOOTSTRAP_ADMIN_PRINCIPAL),
            "node.operator-rollback-published",
            "node",
            Some(&publication.node_id.to_string()),
            "success",
            &serde_json::json!({
                "failedRevision": publication.failed_revision,
                "idempotencyKeyHash": Sha256Digest::from_bytes(key_digest),
                "reason": enum_wire(&reason)?,
                "revision": publication.revision,
                "sourceRevision": publication.source_revision,
            }),
            now,
        )?;
        publications.push(publication);
    }
    let response = OperatorRollbackResponse { publications };
    store_rollback_idempotency(
        &transaction,
        &network.network_id,
        route_id,
        &key_digest,
        &request_digest,
        &response,
        now,
        expires_at,
    )?;
    transaction.commit()?;
    Ok(response)
}

fn prepare_rollback_target(
    connection: &rusqlite::Transaction<'_>,
    identity: &ControllerIdentity,
    network: &NetworkRecord,
    target: &OperatorRollbackTarget,
) -> Result<DesiredStateConfigurationDraft, DatabaseError> {
    let node_id = target.node_id.to_string();
    let (status, agent_version, desired_revision, capabilities_json) = connection
        .query_row(
            "SELECT status, agent_version, desired_revision, capabilities_json
             FROM nodes WHERE network_id = ?1 AND node_id = ?2",
            params![network.network_id, node_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Option<i64>>(2)?,
                    row.get::<_, String>(3)?,
                ))
            },
        )
        .optional()?
        .ok_or(DatabaseError::NodeNotFound)?;
    if status != "active" || desired_revision != Some(target.failed_revision.get()) {
        return Err(DatabaseError::RollbackTargetInvalid);
    }
    let capabilities: Vec<NodeCapability> = serde_json::from_str(&capabilities_json)?;
    if !capabilities.contains(&NodeCapability::Xray) {
        return Err(DatabaseError::RollbackTargetIncompatible);
    }

    let source = load_stored_desired_revision(
        connection,
        &network.network_id,
        &node_id,
        target.source_revision.get(),
    )?
    .ok_or(DatabaseError::RollbackTargetInvalid)?;
    let source = verify_desired_revision(identity, network, target.node_id, &source)?;
    let validated = load_revision_result_state(
        connection,
        &network.network_id,
        target.node_id,
        target.source_revision,
        RevisionResultState::Validated,
    )?
    .is_some();
    let applied = load_revision_result_state(
        connection,
        &network.network_id,
        target.node_id,
        target.source_revision,
        RevisionResultState::Applied,
    )?
    .is_some();
    if !validated || !applied {
        return Err(DatabaseError::RollbackTargetInvalid);
    }
    let failed = load_latest_revision_result(
        connection,
        &network.network_id,
        target.node_id,
        target.failed_revision,
    )?;
    if !failed.is_some_and(|result| {
        matches!(
            result.state,
            RevisionResultState::Rejected | RevisionResultState::RolledBack
        )
    }) {
        return Err(DatabaseError::RollbackTargetInvalid);
    }
    if !agent_version_satisfies(&agent_version, &source.document.min_agent_version) {
        return Err(DatabaseError::RollbackTargetIncompatible);
    }
    Ok(DesiredStateConfigurationDraft {
        min_agent_version: source.document.min_agent_version,
        xray: source.document.xray,
    })
}

fn agent_version_satisfies(agent_version: &str, minimum_version: &str) -> bool {
    match (
        numeric_version_core(agent_version),
        numeric_version_core(minimum_version),
    ) {
        (Some(agent), Some(minimum)) => agent >= minimum,
        _ => agent_version == minimum_version,
    }
}

fn numeric_version_core(value: &str) -> Option<Vec<u64>> {
    if value
        .bytes()
        .any(|byte| !byte.is_ascii_digit() && byte != b'.')
    {
        return None;
    }
    let mut parts = value
        .split('.')
        .map(str::parse::<u64>)
        .collect::<Result<Vec<_>, _>>()
        .ok()?;
    if parts.is_empty() || parts.len() > 4 {
        return None;
    }
    parts.resize(4, 0);
    Some(parts)
}

fn rollback_rejection_code(error: &DatabaseError) -> &'static str {
    match error {
        DatabaseError::NodeNotFound => "node_not_found",
        DatabaseError::RollbackTargetIncompatible => "target_incompatible",
        DatabaseError::StoredDesiredStateCorrupt | DatabaseError::DesiredState(_) => {
            "source_artifact_invalid"
        }
        _ => "target_invalid",
    }
}

fn load_rollback_replay(
    connection: &Connection,
    network_id: &str,
    route_id: &str,
    key_digest: &[u8; 32],
    request_digest: &[u8; 32],
) -> Result<Option<OperatorRollbackResponse>, DatabaseError> {
    let stored = connection
        .query_row(
            "SELECT request_sha256, state, response_status, response_json, response_sha256
             FROM idempotency_records
             WHERE network_id = ?1 AND principal_type = 'bootstrap-admin'
               AND principal_id = 'bootstrap-admin' AND route_id = ?2
               AND idempotency_key_sha256 = ?3",
            params![network_id, route_id, key_digest.as_slice()],
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
    let Some((stored_request, state, status, response_json, stored_response_digest)) = stored
    else {
        return Ok(None);
    };
    if stored_request.as_slice() != request_digest {
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

#[allow(clippy::too_many_arguments)]
fn store_rollback_idempotency(
    connection: &Connection,
    network_id: &str,
    route_id: &str,
    key_digest: &[u8; 32],
    request_digest: &[u8; 32],
    response: &OperatorRollbackResponse,
    now: i64,
    expires_at: i64,
) -> Result<(), DatabaseError> {
    let response_json = serde_json::to_string(response)?;
    let response_digest: [u8; 32] = Sha256::digest(response_json.as_bytes()).into();
    connection.execute(
        "INSERT INTO idempotency_records(
            network_id, principal_type, principal_id, route_id,
            idempotency_key_sha256, request_sha256, state, response_status,
            response_json, response_sha256, created_at, completed_at, expires_at
         ) VALUES (?1, 'bootstrap-admin', 'bootstrap-admin', ?2, ?3, ?4,
                   'completed', ?5, ?6, ?7, ?8, ?8, ?9)",
        params![
            network_id,
            route_id,
            key_digest.as_slice(),
            request_digest.as_slice(),
            HTTP_CREATED_STATUS,
            response_json,
            response_digest.as_slice(),
            now,
            expires_at,
        ],
    )?;
    Ok(())
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
    let canary =
        ensure_endpoint_canary_credential(&transaction, &network.network_id, node_id, now)?;
    let mut expected_users = users
        .iter()
        .map(|compiled| compiled.user.clone())
        .collect::<Vec<_>>();
    expected_users.push(canary.user);
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

fn rotate_protocol_canary(
    connection: &mut Connection,
    identity: &ControllerIdentity,
    node_id: NodeId,
) -> Result<SignedDesiredState, DatabaseError> {
    let now = unix_timestamp()?;
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let mut network = load_network(&transaction)?;
    let current = load_latest_node_desired(&transaction, identity, &network, node_id)?;
    let current_generation: i64 = transaction
        .query_row(
            "SELECT generation FROM endpoint_canary_credentials
             WHERE network_id = ?1 AND node_id = ?2 AND status = 'active'",
            params![network.network_id, node_id.to_string()],
            |row| row.get(0),
        )
        .optional()?
        .unwrap_or(0);
    let next_generation = current_generation
        .checked_add(1)
        .ok_or(DatabaseError::CanaryGenerationOverflow)?;
    transaction.execute(
        "UPDATE endpoint_canary_credentials
         SET status = 'retired', retired_at = ?1
         WHERE network_id = ?2 AND node_id = ?3 AND status = 'active'",
        params![now, network.network_id, node_id.to_string()],
    )?;
    transaction.execute(
        "INSERT INTO endpoint_canary_credentials(
            network_id, node_id, user_id, credential_id, vless_uuid,
            generation, status, created_at, retired_at
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'active', ?7, NULL)",
        params![
            network.network_id,
            node_id.to_string(),
            UserId::new().to_string(),
            CredentialId::new().to_string(),
            Uuid::new_v4().hyphenated().to_string(),
            next_generation,
            now,
        ],
    )?;
    transaction.execute(
        "UPDATE node_endpoint_verifications
         SET status = 'pending', probe_attempts = 0, last_probe_at = NULL,
             last_success_at = NULL, latency_ms = NULL, error_code = NULL,
             verification_expires_at = NULL, updated_at = ?1
         WHERE network_id = ?2 AND node_id = ?3 AND status != 'withdrawn'",
        params![now, network.network_id, node_id.to_string()],
    )?;
    let users = compile_desired_users(&transaction, &network.network_id, node_id)?;
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
        "protocol-canary-rotation",
        now,
    )?;
    insert_audit_event(
        &transaction,
        Some(&network.network_id),
        "admin",
        None,
        "endpoint-canary.rotated",
        "node",
        Some(&node_id.to_string()),
        "success",
        &serde_json::json!({
            "generation": next_generation,
            "revision": desired.document.revision,
        }),
        now,
    )?;
    transaction.commit()?;
    Ok(desired)
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
    let canary = ensure_endpoint_canary_credential(transaction, &network.network_id, node_id, now)?;
    let mut desired_users: Vec<DesiredUser> = users.iter().map(|user| user.user.clone()).collect();
    desired_users.push(canary.user.clone());
    let artifact = build_signed_desired_state(
        identity,
        network_id,
        node_id,
        next_revision,
        timestamp(now)?,
        controller_instance_id,
        configuration.with_users(desired_users),
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
    transaction.execute(
        "INSERT INTO node_revision_canary_credentials(
            network_id, node_id, revision, credential_id
         ) VALUES (?1, ?2, ?3, ?4)",
        params![
            network.network_id,
            node_id.to_string(),
            next_revision.get(),
            canary.user.credential_id.to_string(),
        ],
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
            "protocolCanaryGeneration": canary.generation,
        }),
        now,
    )?;
    network.last_revision = revision;
    network.updated_at = now;
    Ok(artifact.envelope)
}

#[derive(Clone)]
struct EndpointCanaryCredential {
    user: DesiredUser,
    generation: i64,
}

fn ensure_endpoint_canary_credential(
    connection: &Connection,
    network_id: &str,
    node_id: NodeId,
    now: i64,
) -> Result<EndpointCanaryCredential, DatabaseError> {
    let stored = connection
        .query_row(
            "SELECT user_id, credential_id, vless_uuid, generation
             FROM endpoint_canary_credentials
             WHERE network_id = ?1 AND node_id = ?2 AND status = 'active'",
            params![network_id, node_id.to_string()],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, i64>(3)?,
                ))
            },
        )
        .optional()?;
    let (user_id, credential_id, vless_uuid, generation) = if let Some(stored) = stored {
        stored
    } else {
        let user_id = UserId::new().to_string();
        let credential_id = CredentialId::new().to_string();
        let vless_uuid = Uuid::new_v4().hyphenated().to_string();
        connection.execute(
            "INSERT INTO endpoint_canary_credentials(
                    network_id, node_id, user_id, credential_id, vless_uuid,
                    generation, status, created_at, retired_at
                 ) VALUES (?1, ?2, ?3, ?4, ?5, 1, 'active', ?6, NULL)",
            params![
                network_id,
                node_id.to_string(),
                user_id,
                credential_id,
                vless_uuid,
                now,
            ],
        )?;
        (user_id, credential_id, vless_uuid, 1)
    };
    Ok(EndpointCanaryCredential {
        user: DesiredUser {
            user_id: user_id
                .parse()
                .map_err(|_| DatabaseError::StoredProtocolValue)?,
            credential_id: credential_id
                .parse()
                .map_err(|_| DatabaseError::StoredProtocolValue)?,
            vless_uuid: Secret::new(vless_uuid),
            enabled: true,
        },
        generation,
    })
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
    if matches!(
        result.state,
        RevisionResultState::Rejected | RevisionResultState::RolledBack
    ) {
        insert_audit_event(
            &transaction,
            Some(&network.network_id),
            "node",
            Some(&node_id.to_string()),
            "node.revision-failed",
            "revision",
            Some(&revision.get().to_string()),
            "failure",
            &serde_json::json!({
                "errorCode": result.error_code.as_ref().map(control_protocol::error::ErrorCode::as_str),
                "revision": revision,
                "rollbackRevision": result.rollback_revision,
                "state": enum_wire(&result.state)?,
            }),
            now,
        )?;
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

pub(crate) fn verify_current_migration_history(
    connection: &Connection,
) -> Result<(), DatabaseError> {
    let applied = load_applied_migrations(connection)?;
    let user_version: i64 = connection.query_row("PRAGMA user_version", [], |row| row.get(0))?;
    let highest_applied = applied.keys().next_back().copied().unwrap_or(0);
    if user_version != highest_applied {
        return Err(DatabaseError::MigrationMirrorMismatch {
            source_version: highest_applied,
            user_version,
        });
    }
    if highest_applied != SCHEMA_VERSION {
        return Err(DatabaseError::SchemaNotCurrent {
            expected: SCHEMA_VERSION,
            actual: highest_applied,
        });
    }
    if applied.len() != MIGRATIONS.len() {
        return Err(DatabaseError::UnexpectedMigrationHistory);
    }
    for migration in MIGRATIONS {
        let expected_checksum = migration_checksum(migration);
        match applied.get(&migration.version) {
            Some((name, checksum)) if name == migration.name && checksum == &expected_checksum => {}
            Some(_) => {
                return Err(DatabaseError::MigrationChecksumMismatch {
                    version: migration.version,
                });
            }
            None => {
                return Err(DatabaseError::MigrationGap {
                    version: migration.version,
                });
            }
        }
    }
    Ok(())
}

pub(crate) fn migration_set_sha256() -> String {
    let mut hasher = Sha256::new();
    for migration in MIGRATIONS {
        hasher.update(migration.version.to_be_bytes());
        hasher.update(migration.name.as_bytes());
        hasher.update(migration_checksum(migration).as_bytes());
    }
    format!("sha256:{:x}", hasher.finalize())
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
        let node_id = row
            .node_id
            .parse()
            .map_err(|_| DatabaseError::StoredProtocolValue)?;
        let last_failure = load_latest_node_failure(connection, &network.network_id, node_id)?;
        summaries.push(NodeSummaryRecord {
            node_id,
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
            last_failure,
            telemetry_cursor: row.telemetry_cursor,
            created_at: row.created_at,
            updated_at: row.updated_at,
        });
    }
    Ok(summaries)
}

fn load_latest_node_failure(
    connection: &Connection,
    network_id: &str,
    node_id: NodeId,
) -> Result<Option<NodeRevisionFailureSummary>, DatabaseError> {
    let stored = connection
        .query_row(
            "SELECT revision, result_json
             FROM node_revision_results
             WHERE network_id = ?1 AND node_id = ?2
               AND state IN ('rejected', 'rolledBack')
             ORDER BY revision DESC LIMIT 1",
            params![network_id, node_id.to_string()],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?)),
        )
        .optional()?;
    let Some((revision, result_json)) = stored else {
        return Ok(None);
    };
    let revision =
        Revision::new(revision).map_err(|_| DatabaseError::StoredRevisionResultCorrupt)?;
    let result: RevisionResult = serde_json::from_str(&result_json)
        .map_err(|_| DatabaseError::StoredRevisionResultCorrupt)?;
    result
        .validate(revision)
        .map_err(|_| DatabaseError::StoredRevisionResultCorrupt)?;
    if !matches!(
        result.state,
        RevisionResultState::Rejected | RevisionResultState::RolledBack
    ) {
        return Err(DatabaseError::StoredRevisionResultCorrupt);
    }
    Ok(Some(NodeRevisionFailureSummary {
        revision,
        state: result.state,
        error_code: result
            .error_code
            .ok_or(DatabaseError::StoredRevisionResultCorrupt)?,
        rollback_revision: result.rollback_revision,
        completed_at: result.completed_at,
    }))
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

#[allow(clippy::too_many_lines)]
fn issue_account_reset_token(
    connection: &mut Connection,
    identity: &ControllerIdentity,
    user_id: UserId,
    request: &IssueAccountResetTokenRequest,
    idempotency_key: &IdempotencyKey,
) -> Result<IssueAccountResetTokenResponse, DatabaseError> {
    let now = unix_timestamp()?;
    let expires_at = now
        .checked_add(i64::from(request.expires_in_seconds))
        .ok_or(DatabaseError::TimestampOverflow)?;
    let key_digest: [u8; 32] = Sha256::digest(idempotency_key.as_str().as_bytes()).into();
    let request_digest = canonical_request_digest(b"account-reset-issue/v1\0", request)?;
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let network = load_network(&transaction)?;
    if let Some((token_id, stored_request, stored_expiry, stored_verifier)) = transaction
        .query_row(
            "SELECT token_id, issue_request_sha256, expires_at, secret_verifier
             FROM account_reset_tokens
             WHERE network_id = ?1 AND user_id = ?2 AND issue_idempotency_key_sha256 = ?3",
            params![
                network.network_id,
                user_id.to_string(),
                key_digest.as_slice()
            ],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, Vec<u8>>(3)?,
                ))
            },
        )
        .optional()?
    {
        if stored_request.as_slice() != request_digest {
            return Err(DatabaseError::IdempotencyKeyConflict);
        }
        let secret = derive_account_reset_secret(
            identity,
            &network.network_id,
            user_id,
            &token_id,
            &key_digest,
            &request_digest,
        )?;
        if credential_verifier(identity, ACCOUNT_RESET_SECRET_DOMAIN, secret.as_bytes())?.as_slice()
            != stored_verifier
        {
            return Err(DatabaseError::StoredProtocolValue);
        }
        transaction.commit()?;
        return Ok(IssueAccountResetTokenResponse {
            reset_token: Secret::new(secret),
            expires_at: timestamp(stored_expiry)?,
        });
    }

    if load_account_status(&transaction, &network.network_id, user_id)? != "active" {
        return Err(DatabaseError::AccountAuthenticationBlocked);
    }
    let token_id = Uuid::new_v4().hyphenated().to_string();
    let secret = derive_account_reset_secret(
        identity,
        &network.network_id,
        user_id,
        &token_id,
        &key_digest,
        &request_digest,
    )?;
    let verifier = credential_verifier(identity, ACCOUNT_RESET_SECRET_DOMAIN, secret.as_bytes())?;
    transaction.execute(
        "INSERT INTO account_reset_tokens(
            network_id, token_id, user_id, secret_verifier,
            issue_idempotency_key_sha256, issue_request_sha256,
            expires_at, created_at
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        params![
            network.network_id,
            token_id,
            user_id.to_string(),
            verifier.as_slice(),
            key_digest.as_slice(),
            request_digest.as_slice(),
            expires_at,
            now,
        ],
    )?;
    insert_audit_event(
        &transaction,
        Some(&network.network_id),
        "admin",
        Some(BOOTSTRAP_ADMIN_PRINCIPAL),
        "account.reset-token-issued",
        "account",
        Some(&user_id.to_string()),
        "success",
        &serde_json::json!({
            "expiresAt": expires_at,
            "idempotencyKeyHash": Sha256Digest::from_bytes(key_digest),
        }),
        now,
    )?;
    transaction.commit()?;
    Ok(IssueAccountResetTokenResponse {
        reset_token: Secret::new(secret),
        expires_at: timestamp(expires_at)?,
    })
}

fn derive_account_reset_secret(
    identity: &ControllerIdentity,
    network_id: &str,
    user_id: UserId,
    token_id: &str,
    key_digest: &[u8; 32],
    request_digest: &[u8; 32],
) -> Result<String, DatabaseError> {
    let mut context = Vec::new();
    context.extend_from_slice(network_id.as_bytes());
    context.extend_from_slice(user_id.to_string().as_bytes());
    context.extend_from_slice(token_id.as_bytes());
    context.extend_from_slice(key_digest);
    context.extend_from_slice(request_digest);
    Ok(format!(
        "rcr1.{token_id}.{}",
        derive_secret(identity, ACCOUNT_RESET_SECRET_DOMAIN, &context)?
    ))
}

#[allow(clippy::too_many_lines)]
fn consume_account_reset_token(
    connection: &mut Connection,
    identity: &ControllerIdentity,
    request: &ConsumeAccountResetTokenRequest,
    idempotency_key: &IdempotencyKey,
) -> Result<ConsumeAccountResetTokenResponse, DatabaseError> {
    let now = unix_timestamp()?;
    let verifier = credential_verifier(
        identity,
        ACCOUNT_RESET_SECRET_DOMAIN,
        request.reset_token.expose_secret().as_bytes(),
    )?;
    let key_digest: [u8; 32] = Sha256::digest(idempotency_key.as_str().as_bytes()).into();
    let request_digest = canonical_request_digest(b"account-reset-consume/v1\0", request)?;
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let mut network = load_network(&transaction)?;
    let stored = transaction
        .query_row(
            "SELECT token_id, user_id, expires_at, consumed_at,
                    consume_idempotency_key_sha256, consume_request_sha256,
                    consume_response_json
             FROM account_reset_tokens
             WHERE network_id = ?1 AND secret_verifier = ?2",
            params![network.network_id, verifier.as_slice()],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, Option<i64>>(3)?,
                    row.get::<_, Option<Vec<u8>>>(4)?,
                    row.get::<_, Option<Vec<u8>>>(5)?,
                    row.get::<_, Option<String>>(6)?,
                ))
            },
        )
        .optional()?;
    let Some((
        token_id,
        user_id,
        expires_at,
        consumed_at,
        stored_key,
        stored_request,
        response_json,
    )) = stored
    else {
        // Unknown public bearer values are intentionally not persisted. Auditing each random
        // token would let an unauthenticated caller grow the database without a valid identity.
        return Err(DatabaseError::AccountResetTokenInvalid);
    };
    let user_id = user_id
        .parse::<UserId>()
        .map_err(|_| DatabaseError::StoredProtocolValue)?;
    if consumed_at.is_some() {
        if stored_key.as_deref() == Some(key_digest.as_slice())
            && stored_request.as_deref() == Some(request_digest.as_slice())
        {
            let response = response_json
                .ok_or(DatabaseError::StoredProtocolValue)
                .and_then(|value| serde_json::from_str(&value).map_err(DatabaseError::from))?;
            transaction.commit()?;
            return Ok(response);
        }
        insert_account_reset_rejection(
            &transaction,
            &network.network_id,
            Some(user_id),
            "consumed",
            now,
        )?;
        transaction.commit()?;
        return Err(DatabaseError::AccountResetTokenConsumed);
    }
    if now >= expires_at {
        insert_account_reset_rejection(
            &transaction,
            &network.network_id,
            Some(user_id),
            "expired",
            now,
        )?;
        transaction.commit()?;
        return Err(DatabaseError::AccountResetTokenExpired);
    }
    if load_account_status(&transaction, &network.network_id, user_id)? != "active" {
        insert_account_reset_rejection(
            &transaction,
            &network.network_id,
            Some(user_id),
            "account-unavailable",
            now,
        )?;
        transaction.commit()?;
        return Err(DatabaseError::AccountAuthenticationBlocked);
    }

    let salt = SaltString::generate(&mut OsRng);
    let password_verifier = Argon2::default()
        .hash_password(request.new_password.expose_secret().as_bytes(), &salt)
        .map_err(|_| DatabaseError::PasswordHash)?
        .to_string();
    transaction.execute(
        "UPDATE users SET password_verifier = ?1, password_updated_at = ?2,
             credential_version = credential_version + 1, updated_at = ?2
         WHERE network_id = ?3 AND user_id = ?4",
        params![
            password_verifier,
            now,
            network.network_id,
            user_id.to_string()
        ],
    )?;
    let revoked_sessions = revoke_user_sessions(
        &transaction,
        &network.network_id,
        user_id,
        now,
        "account-reset-token",
    )?;
    let affected_nodes =
        rotate_account_credentials(&transaction, &network.network_id, user_id, now)?;
    let revisions = publish_account_revisions(
        &transaction,
        identity,
        &mut network,
        &affected_nodes,
        "account-reset-token",
        now,
    )?;
    let response = ConsumeAccountResetTokenResponse {
        user_id,
        revoked_sessions: u32::try_from(revoked_sessions)
            .map_err(|_| DatabaseError::StoredProtocolValue)?,
        published_revisions: revisions.iter().map(|(_, revision)| *revision).collect(),
    };
    let response_json = serde_json::to_string(&response)?;
    let changed = transaction.execute(
        "UPDATE account_reset_tokens
         SET consumed_at = ?1, consume_idempotency_key_sha256 = ?2,
             consume_request_sha256 = ?3, consume_response_json = ?4
         WHERE network_id = ?5 AND token_id = ?6 AND consumed_at IS NULL",
        params![
            now,
            key_digest.as_slice(),
            request_digest.as_slice(),
            response_json,
            network.network_id,
            token_id,
        ],
    )?;
    if changed != 1 {
        return Err(DatabaseError::AccountResetTokenConsumed);
    }
    insert_audit_event(
        &transaction,
        Some(&network.network_id),
        "anonymous-account-recovery",
        None,
        "account.reset-token-consumed",
        "account",
        Some(&user_id.to_string()),
        "success",
        &serde_json::json!({
            "publishedRevisions": revision_audit_details(&revisions),
            "revokedSessions": revoked_sessions,
        }),
        now,
    )?;
    transaction.commit()?;
    Ok(response)
}

fn insert_account_reset_rejection(
    transaction: &rusqlite::Transaction<'_>,
    network_id: &str,
    user_id: Option<UserId>,
    reason: &'static str,
    now: i64,
) -> Result<(), DatabaseError> {
    let target_id = user_id.map(|value| value.to_string());
    insert_audit_event(
        transaction,
        Some(network_id),
        "anonymous-account-recovery",
        None,
        "account.reset-token-rejected",
        "account",
        target_id.as_deref(),
        "rejected",
        &serde_json::json!({ "reason": reason }),
        now,
    )
}

#[allow(clippy::too_many_lines)]
fn create_device_activation(
    connection: &mut Connection,
    identity: &ControllerIdentity,
    user_id: UserId,
    request: &CreateDeviceActivationRequest,
    controller_origin: &str,
    idempotency_key: &IdempotencyKey,
) -> Result<DeviceActivationDelivery, DatabaseError> {
    let now = unix_timestamp()?;
    let expires_at = now
        .checked_add(i64::from(request.expires_in_seconds))
        .ok_or(DatabaseError::TimestampOverflow)?;
    let key_digest: [u8; 32] = Sha256::digest(idempotency_key.as_str().as_bytes()).into();
    let request_digest: [u8; 32] = Sha256::digest(serde_json::to_vec(request)?).into();
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let network = load_network(&transaction)?;
    if let Some(stored) = transaction
        .query_row(
            "SELECT activation_id, request_sha256, expires_at, secret_verifier,
                    account_display_name, controller_origin, controller_instance_id,
                    bundle_signing_public_key
             FROM device_activations
             WHERE network_id = ?1 AND user_id = ?2 AND idempotency_key_sha256 = ?3",
            params![
                network.network_id,
                user_id.to_string(),
                key_digest.as_slice()
            ],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, Vec<u8>>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, String>(6)?,
                    row.get::<_, String>(7)?,
                ))
            },
        )
        .optional()?
    {
        if stored.1.as_slice() != request_digest {
            return Err(DatabaseError::IdempotencyKeyConflict);
        }
        let activation_id = stored
            .0
            .parse::<DeviceActivationId>()
            .map_err(|_| DatabaseError::StoredProtocolValue)?;
        let secret = derive_activation_secret(
            identity,
            &network.network_id,
            user_id,
            activation_id,
            &key_digest,
            &request_digest,
        )?;
        if credential_verifier(identity, ACTIVATION_SECRET_DOMAIN, secret.as_bytes())?.as_slice()
            != stored.3
        {
            return Err(DatabaseError::StoredProtocolValue);
        }
        transaction.commit()?;
        return build_device_activation_delivery(
            &network.network_id,
            user_id,
            activation_id,
            stored.2,
            secret,
            stored.4,
            stored.5,
            &stored.6,
            &stored.7,
        );
    }

    let (account_display_name, account_status) = transaction
        .query_row(
            "SELECT display_name, status FROM users WHERE network_id = ?1 AND user_id = ?2",
            params![network.network_id, user_id.to_string()],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
        )
        .optional()?
        .ok_or(DatabaseError::AccountNotFound)?;
    if account_status != "active" {
        return Err(DatabaseError::AccountAuthenticationBlocked);
    }

    let activation_id = DeviceActivationId::new();
    let secret = derive_activation_secret(
        identity,
        &network.network_id,
        user_id,
        activation_id,
        &key_digest,
        &request_digest,
    )?;
    let verifier = credential_verifier(identity, ACTIVATION_SECRET_DOMAIN, secret.as_bytes())?;
    let controller_instance_id = network.controller_epoch.clone();
    let bundle_signing_public_key = identity.public_key().as_str().to_string();
    transaction.execute(
        "INSERT INTO device_activations(
            network_id, activation_id, user_id, account_display_name, controller_origin,
            controller_instance_id, bundle_signing_public_key, secret_verifier,
            idempotency_key_sha256, request_sha256, expires_at, created_by_admin_id, created_at
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
        params![
            network.network_id,
            activation_id.to_string(),
            user_id.to_string(),
            account_display_name,
            controller_origin,
            controller_instance_id,
            bundle_signing_public_key,
            verifier.as_slice(),
            key_digest.as_slice(),
            request_digest.as_slice(),
            expires_at,
            BOOTSTRAP_ADMIN_PRINCIPAL,
            now,
        ],
    )?;
    insert_audit_event(
        &transaction,
        Some(&network.network_id),
        "admin",
        None,
        "device-activation.created",
        "device-activation",
        Some(&activation_id.to_string()),
        "success",
        &serde_json::json!({"userId": user_id, "expiresAt": timestamp(expires_at)?}),
        now,
    )?;
    transaction.commit()?;
    build_device_activation_delivery(
        &network.network_id,
        user_id,
        activation_id,
        expires_at,
        secret,
        account_display_name,
        controller_origin.to_string(),
        &controller_instance_id,
        &bundle_signing_public_key,
    )
}

#[allow(clippy::too_many_arguments)]
fn build_device_activation_delivery(
    network_id: &str,
    user_id: UserId,
    activation_id: DeviceActivationId,
    expires_at: i64,
    activation_secret: String,
    display_name: String,
    controller_origin: String,
    controller_instance_id: &str,
    bundle_signing_public_key: &str,
) -> Result<DeviceActivationDelivery, DatabaseError> {
    Ok(DeviceActivationDelivery {
        activation: MemberSetupActivation {
            display_name,
            network_id: network_id
                .parse()
                .map_err(|_| DatabaseError::StoredProtocolValue)?,
            user_id,
            activation_id,
            expires_at: timestamp(expires_at)?,
            activation_secret: Secret::new(activation_secret),
            controller_origin,
            controller_instance_id: controller_instance_id
                .parse()
                .map_err(|_| DatabaseError::StoredProtocolValue)?,
            bundle_signing_public_key: bundle_signing_public_key
                .parse()
                .map_err(|_| DatabaseError::StoredProtocolValue)?,
        },
    })
}

fn derive_activation_secret(
    identity: &ControllerIdentity,
    network_id: &str,
    user_id: UserId,
    activation_id: DeviceActivationId,
    key_digest: &[u8; 32],
    request_digest: &[u8; 32],
) -> Result<String, DatabaseError> {
    let mut context = Vec::new();
    context.extend_from_slice(network_id.as_bytes());
    context.extend_from_slice(user_id.to_string().as_bytes());
    context.extend_from_slice(activation_id.to_string().as_bytes());
    context.extend_from_slice(key_digest);
    context.extend_from_slice(request_digest);
    Ok(format!(
        "rcd1.{activation_id}.{}",
        derive_secret(identity, ACTIVATION_SECRET_DOMAIN, &context)?
    ))
}

#[allow(clippy::too_many_lines)]
fn consume_device_activation(
    connection: &mut Connection,
    identity: &ControllerIdentity,
    controller_origin: &str,
    request: &ConsumeDeviceActivationRequest,
) -> Result<CreateDeviceSessionResponse, DatabaseError> {
    let raw_secret = request.activation_secret.expose_secret();
    let activation_id = parse_prefixed_id::<DeviceActivationId>(raw_secret, "rcd1")?;
    let verifier = credential_verifier(identity, ACTIVATION_SECRET_DOMAIN, raw_secret.as_bytes())?;
    let request_digest: [u8; 32] = Sha256::digest(serde_json::to_vec(request)?).into();
    let now = unix_timestamp()?;
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let network = load_network(&transaction)?;
    let activation = transaction
        .query_row(
            "SELECT user_id, secret_verifier, expires_at, consumed_at,
                    consumed_by_device_id, consume_request_sha256, issued_session_id,
                    response_account_json
             FROM device_activations WHERE network_id = ?1 AND activation_id = ?2",
            params![network.network_id, activation_id.to_string()],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, Option<i64>>(3)?,
                    row.get::<_, Option<String>>(4)?,
                    row.get::<_, Option<Vec<u8>>>(5)?,
                    row.get::<_, Option<String>>(6)?,
                    row.get::<_, Option<String>>(7)?,
                ))
            },
        )
        .optional()?
        .ok_or(DatabaseError::ActivationInvalid)?;
    if !bool::from(activation.1.as_slice().ct_eq(verifier.as_slice())) {
        return Err(DatabaseError::ActivationInvalid);
    }
    if activation.2 < now && activation.3.is_none() {
        return Err(DatabaseError::ActivationExpired);
    }
    let user_id = activation
        .0
        .parse::<UserId>()
        .map_err(|_| DatabaseError::StoredProtocolValue)?;
    let transcript = device_activation_proof_transcript(
        activation_id,
        timestamp(activation.2)?,
        controller_origin,
        &request.device,
    )?;
    verify_device_activation_proof(&request.device, &transcript)
        .map_err(|_| DatabaseError::InvalidDeviceProof)?;

    if activation.3.is_some() {
        if activation.5.as_deref() != Some(request_digest.as_slice()) {
            return Err(DatabaseError::ActivationConsumed);
        }
        let device_id = activation
            .4
            .ok_or(DatabaseError::StoredProtocolValue)?
            .parse::<DeviceId>()
            .map_err(|_| DatabaseError::StoredProtocolValue)?;
        let session_id = activation
            .6
            .ok_or(DatabaseError::StoredProtocolValue)?
            .parse::<SessionId>()
            .map_err(|_| DatabaseError::StoredProtocolValue)?;
        let account = serde_json::from_str(
            activation
                .7
                .as_deref()
                .ok_or(DatabaseError::StoredProtocolValue)?,
        )?;
        let response = replay_initial_session(
            &transaction,
            identity,
            &network.network_id,
            user_id,
            device_id,
            session_id,
            Some(activation_id),
            &request_digest,
            account,
        )?;
        transaction.commit()?;
        return Ok(response);
    }
    if load_account_status(&transaction, &network.network_id, user_id)? != "active" {
        return Err(DatabaseError::AccountAuthenticationBlocked);
    }
    let device_id = DeviceId::new();
    let session_id = SessionId::new();
    insert_device(
        &transaction,
        &network.network_id,
        user_id,
        device_id,
        &request.device,
        now,
    )?;
    let response = issue_initial_session(
        &transaction,
        identity,
        &network.network_id,
        user_id,
        device_id,
        session_id,
        Some(activation_id),
        &request_digest,
        now,
    )?;
    let response_account_json = serde_json::to_string(&response.account)?;
    transaction.execute(
        "UPDATE device_activations
         SET consumed_at = ?1, consumed_by_device_id = ?2,
             consume_request_sha256 = ?3, issued_session_id = ?4,
             response_account_json = ?5
         WHERE network_id = ?6 AND activation_id = ?7 AND consumed_at IS NULL",
        params![
            now,
            device_id.to_string(),
            request_digest.as_slice(),
            session_id.to_string(),
            response_account_json,
            network.network_id,
            activation_id.to_string(),
        ],
    )?;
    insert_audit_event(
        &transaction,
        Some(&network.network_id),
        "device",
        Some(&device_id.to_string()),
        "device-activation.consumed",
        "account",
        Some(&user_id.to_string()),
        "success",
        &serde_json::json!({"activationId": activation_id, "sessionId": session_id}),
        now,
    )?;
    transaction.commit()?;
    Ok(response)
}

fn set_account_password(
    connection: &mut Connection,
    identity: &ControllerIdentity,
    user_id: UserId,
    request: &SetAccountPasswordRequest,
) -> Result<(), DatabaseError> {
    let salt = SaltString::generate(&mut OsRng);
    let verifier = Argon2::default()
        .hash_password(request.new_password.expose_secret().as_bytes(), &salt)
        .map_err(|_| DatabaseError::PasswordHash)?
        .to_string();
    let now = unix_timestamp()?;
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let mut network = load_network(&transaction)?;
    if load_account_status(&transaction, &network.network_id, user_id)? == "deleted" {
        return Err(DatabaseError::AccountAuthenticationBlocked);
    }
    transaction.execute(
        "UPDATE users SET password_verifier = ?1, password_updated_at = ?2,
             credential_version = credential_version + 1, updated_at = ?2
         WHERE network_id = ?3 AND user_id = ?4",
        params![verifier, now, network.network_id, user_id.to_string()],
    )?;
    revoke_user_sessions(
        &transaction,
        &network.network_id,
        user_id,
        now,
        "password-reset",
    )?;
    let affected_nodes =
        rotate_account_credentials(&transaction, &network.network_id, user_id, now)?;
    let revisions = publish_account_revisions(
        &transaction,
        identity,
        &mut network,
        &affected_nodes,
        "account-password-reset",
        now,
    )?;
    insert_audit_event(
        &transaction,
        Some(&network.network_id),
        "admin",
        None,
        "account.password-reset",
        "account",
        Some(&user_id.to_string()),
        "success",
        &serde_json::json!({
            "publishedRevisions": revision_audit_details(&revisions),
        }),
        now,
    )?;
    transaction.commit()?;
    Ok(())
}

fn reset_account_sessions(
    connection: &mut Connection,
    identity: &ControllerIdentity,
    user_id: UserId,
) -> Result<ResetAccountSessionsResponse, DatabaseError> {
    let now = unix_timestamp()?;
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let mut network = load_network(&transaction)?;
    if load_account_status(&transaction, &network.network_id, user_id)? == "deleted" {
        return Err(DatabaseError::AccountAuthenticationBlocked);
    }
    transaction.execute(
        "UPDATE users SET credential_version = credential_version + 1, updated_at = ?1
         WHERE network_id = ?2 AND user_id = ?3",
        params![now, network.network_id, user_id.to_string()],
    )?;
    let revoked_sessions = revoke_user_sessions(
        &transaction,
        &network.network_id,
        user_id,
        now,
        "account-session-reset",
    )?;
    let revoked_devices = transaction.execute(
        "UPDATE devices SET status = 'revoked', revoked_at = ?1
         WHERE network_id = ?2 AND user_id = ?3 AND status = 'active'",
        params![now, network.network_id, user_id.to_string()],
    )?;
    let affected_nodes =
        rotate_account_credentials(&transaction, &network.network_id, user_id, now)?;
    let revisions = publish_account_revisions(
        &transaction,
        identity,
        &mut network,
        &affected_nodes,
        "account-session-reset",
        now,
    )?;
    insert_audit_event(
        &transaction,
        Some(&network.network_id),
        "admin",
        None,
        "account.sessions-reset",
        "account",
        Some(&user_id.to_string()),
        "success",
        &serde_json::json!({
            "revokedDevices": revoked_devices,
            "revokedSessions": revoked_sessions,
            "publishedRevisions": revision_audit_details(&revisions),
        }),
        now,
    )?;
    transaction.commit()?;
    Ok(ResetAccountSessionsResponse {
        user_id,
        revoked_sessions: u32::try_from(revoked_sessions)
            .map_err(|_| DatabaseError::StoredProtocolValue)?,
        revoked_devices: u32::try_from(revoked_devices)
            .map_err(|_| DatabaseError::StoredProtocolValue)?,
    })
}

fn create_member_session(
    connection: &mut Connection,
    identity: &ControllerIdentity,
    controller_origin: &str,
    request: &CreateSessionRequest,
    idempotency_key: &IdempotencyKey,
) -> Result<CreateDeviceSessionResponse, DatabaseError> {
    let user_id = request
        .account
        .parse::<UserId>()
        .map_err(|_| DatabaseError::MemberAuthenticationFailed)?;
    let key_digest: [u8; 32] = Sha256::digest(idempotency_key.as_str().as_bytes()).into();
    let request_digest = canonical_request_digest(LOGIN_REQUEST_DOMAIN, request)?;
    let now = unix_timestamp()?;
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let network = load_network(&transaction)?;
    if let Some(response) = replay_member_login(
        &transaction,
        identity,
        &network.network_id,
        &key_digest,
        &request_digest,
    )? {
        transaction.commit()?;
        return Ok(response);
    }
    let stored = transaction
        .query_row(
            "SELECT password_verifier, status FROM users
             WHERE network_id = ?1 AND user_id = ?2",
            params![network.network_id, user_id.to_string()],
            |row| Ok((row.get::<_, Option<String>>(0)?, row.get::<_, String>(1)?)),
        )
        .optional()?
        .ok_or(DatabaseError::MemberAuthenticationFailed)?;
    if stored.1 != "active" {
        return Err(DatabaseError::MemberAuthenticationFailed);
    }
    let verifier = stored.0.ok_or(DatabaseError::MemberAuthenticationFailed)?;
    let parsed = PasswordHash::new(&verifier).map_err(|_| DatabaseError::StoredProtocolValue)?;
    Argon2::default()
        .verify_password(request.password.expose_secret().as_bytes(), &parsed)
        .map_err(|_| DatabaseError::MemberAuthenticationFailed)?;
    let transcript =
        device_login_proof_transcript(&request.account, controller_origin, &request.device)?;
    verify_device_activation_proof(&request.device, &transcript)
        .map_err(|_| DatabaseError::InvalidDeviceProof)?;

    let device_id = DeviceId::new();
    let session_id = SessionId::new();
    insert_device(
        &transaction,
        &network.network_id,
        user_id,
        device_id,
        &request.device,
        now,
    )?;
    let response = issue_initial_session(
        &transaction,
        identity,
        &network.network_id,
        user_id,
        device_id,
        session_id,
        None,
        &request_digest,
        now,
    )?;
    transaction.execute(
        "INSERT INTO login_idempotency_records(
            network_id, idempotency_key_sha256, request_sha256, user_id,
            device_id, session_id, response_account_json, created_at, expires_at
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        params![
            network.network_id,
            key_digest.as_slice(),
            request_digest.as_slice(),
            user_id.to_string(),
            device_id.to_string(),
            session_id.to_string(),
            serde_json::to_string(&response.account)?,
            now,
            now.checked_add(REFRESH_TOKEN_LIFETIME_SECONDS)
                .ok_or(DatabaseError::TimestampOverflow)?,
        ],
    )?;
    insert_audit_event(
        &transaction,
        Some(&network.network_id),
        "device",
        Some(&device_id.to_string()),
        "session.password-created",
        "account",
        Some(&user_id.to_string()),
        "success",
        &serde_json::json!({"sessionId": session_id}),
        now,
    )?;
    transaction.commit()?;
    Ok(response)
}

fn replay_member_login(
    transaction: &rusqlite::Transaction<'_>,
    identity: &ControllerIdentity,
    network_id: &str,
    key_digest: &[u8; 32],
    request_digest: &[u8; 32],
) -> Result<Option<CreateDeviceSessionResponse>, DatabaseError> {
    let replay = transaction
        .query_row(
            "SELECT request_sha256, user_id, device_id, session_id, response_account_json
             FROM login_idempotency_records
             WHERE network_id = ?1 AND idempotency_key_sha256 = ?2",
            params![network_id, key_digest.as_slice()],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                ))
            },
        )
        .optional()?;
    let Some(replay) = replay else {
        return Ok(None);
    };
    if replay.0.as_slice() != request_digest {
        return Err(DatabaseError::IdempotencyKeyConflict);
    }
    let user_id = replay
        .1
        .parse::<UserId>()
        .map_err(|_| DatabaseError::StoredProtocolValue)?;
    let device_id = replay
        .2
        .parse::<DeviceId>()
        .map_err(|_| DatabaseError::StoredProtocolValue)?;
    let session_id = replay
        .3
        .parse::<SessionId>()
        .map_err(|_| DatabaseError::StoredProtocolValue)?;
    let account = serde_json::from_str(&replay.4)?;
    replay_initial_session(
        transaction,
        identity,
        network_id,
        user_id,
        device_id,
        session_id,
        None,
        request_digest,
        account,
    )
    .map(Some)
}

fn insert_device(
    connection: &Connection,
    network_id: &str,
    user_id: UserId,
    device_id: DeviceId,
    enrollment: &DeviceEnrollment,
    now: i64,
) -> Result<(), DatabaseError> {
    connection.execute(
        "INSERT INTO devices(
            network_id, device_id, user_id, display_name, platform, client_version,
            identity_public_key, encryption_public_key, status, created_at, last_seen_at
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 'active', ?9, ?9)",
        params![
            network_id,
            device_id.to_string(),
            user_id.to_string(),
            enrollment.display_name,
            enrollment.platform,
            enrollment.client_version,
            enrollment.identity_public_key.as_str(),
            enrollment.encryption_public_key.as_str(),
            now,
        ],
    )?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn issue_initial_session(
    connection: &Connection,
    identity: &ControllerIdentity,
    network_id: &str,
    user_id: UserId,
    device_id: DeviceId,
    session_id: SessionId,
    activation_id: Option<DeviceActivationId>,
    request_digest: &[u8; 32],
    now: i64,
) -> Result<CreateDeviceSessionResponse, DatabaseError> {
    let access_expires_at = now
        .checked_add(ACCESS_TOKEN_LIFETIME_SECONDS)
        .ok_or(DatabaseError::TimestampOverflow)?;
    let refresh_expires_at = now
        .checked_add(REFRESH_TOKEN_LIFETIME_SECONDS)
        .ok_or(DatabaseError::TimestampOverflow)?;
    let credentials = derive_initial_credentials(
        identity,
        network_id,
        session_id,
        device_id,
        activation_id,
        request_digest,
        now,
        access_expires_at,
        refresh_expires_at,
    )?;
    let access_verifier = credential_verifier(
        identity,
        ACCESS_TOKEN_DOMAIN,
        credentials.access_token.expose_secret().as_bytes(),
    )?;
    let refresh_verifier = credential_verifier(
        identity,
        REFRESH_TOKEN_DOMAIN,
        credentials.refresh_credential.expose_secret().as_bytes(),
    )?;
    let credential_version: i64 = connection.query_row(
        "SELECT credential_version FROM users WHERE network_id = ?1 AND user_id = ?2",
        params![network_id, user_id.to_string()],
        |row| row.get(0),
    )?;
    connection.execute(
        "INSERT INTO refresh_sessions(
            network_id, session_id, user_id, device_id, generation,
            current_refresh_verifier, current_access_verifier, access_expires_at,
            credential_version, created_at, rotated_at, expires_at
         ) VALUES (?1, ?2, ?3, ?4, 0, ?5, ?6, ?7, ?8, ?9, ?9, ?10)",
        params![
            network_id,
            session_id.to_string(),
            user_id.to_string(),
            device_id.to_string(),
            refresh_verifier.as_slice(),
            access_verifier.as_slice(),
            access_expires_at,
            credential_version,
            now,
            refresh_expires_at,
        ],
    )?;
    Ok(CreateDeviceSessionResponse {
        activation_id,
        account: load_account_metadata(connection, network_id, user_id)?,
        device_id,
        credentials,
    })
}

#[allow(clippy::too_many_arguments)]
fn replay_initial_session(
    connection: &Connection,
    identity: &ControllerIdentity,
    network_id: &str,
    user_id: UserId,
    device_id: DeviceId,
    session_id: SessionId,
    activation_id: Option<DeviceActivationId>,
    request_digest: &[u8; 32],
    account: AccountMetadata,
) -> Result<CreateDeviceSessionResponse, DatabaseError> {
    let stored = connection.query_row(
        "SELECT created_at, expires_at FROM refresh_sessions
         WHERE network_id = ?1 AND session_id = ?2 AND user_id = ?3 AND device_id = ?4",
        params![
            network_id,
            session_id.to_string(),
            user_id.to_string(),
            device_id.to_string(),
        ],
        |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
    )?;
    Ok(CreateDeviceSessionResponse {
        activation_id,
        account,
        device_id,
        credentials: derive_initial_credentials(
            identity,
            network_id,
            session_id,
            device_id,
            activation_id,
            request_digest,
            stored.0,
            stored
                .0
                .checked_add(ACCESS_TOKEN_LIFETIME_SECONDS)
                .ok_or(DatabaseError::TimestampOverflow)?,
            stored.1,
        )?,
    })
}

#[allow(clippy::too_many_arguments)]
fn derive_initial_credentials(
    identity: &ControllerIdentity,
    network_id: &str,
    session_id: SessionId,
    device_id: DeviceId,
    activation_id: Option<DeviceActivationId>,
    request_digest: &[u8; 32],
    issued_at: i64,
    access_expires_at: i64,
    refresh_expires_at: i64,
) -> Result<SessionCredentials, DatabaseError> {
    let mut context = Vec::new();
    context.extend_from_slice(network_id.as_bytes());
    context.extend_from_slice(session_id.to_string().as_bytes());
    context.extend_from_slice(device_id.to_string().as_bytes());
    if let Some(activation_id) = activation_id {
        context.extend_from_slice(activation_id.to_string().as_bytes());
    }
    context.extend_from_slice(request_digest);
    context.extend_from_slice(&issued_at.to_be_bytes());
    Ok(SessionCredentials {
        session_id,
        access_token: Secret::new(format!(
            "rca1.{session_id}.{}",
            derive_secret(identity, ACCESS_TOKEN_DOMAIN, &context)?
        )),
        access_expires_at: timestamp(access_expires_at)?,
        refresh_credential: Secret::new(format!(
            "rcr1.{session_id}.{}",
            derive_secret(identity, REFRESH_TOKEN_DOMAIN, &context)?
        )),
        refresh_expires_at: timestamp(refresh_expires_at)?,
    })
}

#[allow(clippy::too_many_lines)]
fn refresh_member_session(
    connection: &mut Connection,
    identity: &ControllerIdentity,
    request: &RefreshSessionRequest,
    idempotency_key: &IdempotencyKey,
) -> Result<RefreshSessionResponse, DatabaseError> {
    let raw = request.refresh_credential.expose_secret();
    let session_id = parse_prefixed_id::<SessionId>(raw, "rcr1")?;
    let verifier = credential_verifier(identity, REFRESH_TOKEN_DOMAIN, raw.as_bytes())?;
    let key_digest: [u8; 32] = Sha256::digest(idempotency_key.as_str().as_bytes()).into();
    let request_digest = canonical_request_digest(REFRESH_REQUEST_DOMAIN, request)?;
    let now = unix_timestamp()?;
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let network = load_network(&transaction)?;
    let stored = transaction
        .query_row(
            "SELECT session.user_id, session.device_id, session.generation,
                    session.current_refresh_verifier, session.previous_refresh_verifier,
                    session.expires_at, session.revoked_at, session.credential_version,
                    user.credential_version, user.status, device.status
             FROM refresh_sessions AS session
             JOIN users AS user ON user.network_id = session.network_id
                AND user.user_id = session.user_id
             JOIN devices AS device ON device.network_id = session.network_id
                AND device.device_id = session.device_id AND device.user_id = session.user_id
             WHERE session.network_id = ?1 AND session.session_id = ?2",
            params![network.network_id, session_id.to_string()],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, Vec<u8>>(3)?,
                    row.get::<_, Option<Vec<u8>>>(4)?,
                    row.get::<_, i64>(5)?,
                    row.get::<_, Option<i64>>(6)?,
                    row.get::<_, i64>(7)?,
                    row.get::<_, i64>(8)?,
                    row.get::<_, String>(9)?,
                    row.get::<_, String>(10)?,
                ))
            },
        )
        .optional()?
        .ok_or(DatabaseError::MemberAuthenticationFailed)?;
    let current_matches = bool::from(stored.3.as_slice().ct_eq(verifier.as_slice()));
    let previous_matches = stored
        .4
        .as_deref()
        .is_some_and(|previous| bool::from(previous.ct_eq(verifier.as_slice())));
    let source_generation = if current_matches {
        stored.2
    } else if previous_matches && stored.2 > 0 {
        stored.2 - 1
    } else {
        return Err(DatabaseError::MemberAuthenticationFailed);
    };
    if let Some(replay) = transaction
        .query_row(
            "SELECT request_sha256, response_account_json, issued_at,
                    access_expires_at, refresh_expires_at
             FROM refresh_idempotency_records
             WHERE network_id = ?1 AND session_id = ?2 AND source_generation = ?3
               AND idempotency_key_sha256 = ?4",
            params![
                network.network_id,
                session_id.to_string(),
                source_generation,
                key_digest.as_slice(),
            ],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, i64>(4)?,
                ))
            },
        )
        .optional()?
    {
        if replay.0.as_slice() != request_digest {
            return Err(DatabaseError::IdempotencyKeyConflict);
        }
        let device_id = stored
            .1
            .parse::<DeviceId>()
            .map_err(|_| DatabaseError::StoredProtocolValue)?;
        let response = RefreshSessionResponse {
            account: serde_json::from_str(&replay.1)?,
            credentials: derive_refresh_credentials(
                identity,
                &network.network_id,
                session_id,
                device_id,
                source_generation,
                &key_digest,
                &request_digest,
                replay.2,
                replay.3,
                replay.4,
            )?,
        };
        transaction.commit()?;
        return Ok(response);
    }
    if previous_matches {
        transaction.execute(
            "UPDATE refresh_sessions SET revoked_at = COALESCE(revoked_at, ?1),
                 revoke_reason = COALESCE(revoke_reason, 'refresh-reuse')
             WHERE network_id = ?2 AND session_id = ?3",
            params![now, network.network_id, session_id.to_string()],
        )?;
        insert_audit_event(
            &transaction,
            Some(&network.network_id),
            "device",
            Some(&stored.1),
            "session.refresh-reuse",
            "session",
            Some(&session_id.to_string()),
            "rejected",
            &serde_json::json!({}),
            now,
        )?;
        transaction.commit()?;
        return Err(DatabaseError::RefreshCredentialReused);
    }
    if !current_matches
        || stored.6.is_some()
        || stored.5 <= now
        || stored.7 != stored.8
        || stored.9 != "active"
        || stored.10 != "active"
    {
        return Err(DatabaseError::MemberAuthenticationFailed);
    }
    let user_id = stored
        .0
        .parse::<UserId>()
        .map_err(|_| DatabaseError::StoredProtocolValue)?;
    let device_id = stored
        .1
        .parse::<DeviceId>()
        .map_err(|_| DatabaseError::StoredProtocolValue)?;
    let access_expires_at = now
        .checked_add(ACCESS_TOKEN_LIFETIME_SECONDS)
        .ok_or(DatabaseError::TimestampOverflow)?;
    let account = load_account_metadata(&transaction, &network.network_id, user_id)?;
    let credentials = derive_refresh_credentials(
        identity,
        &network.network_id,
        session_id,
        device_id,
        source_generation,
        &key_digest,
        &request_digest,
        now,
        access_expires_at,
        stored.5,
    )?;
    let next_refresh_verifier = credential_verifier(
        identity,
        REFRESH_TOKEN_DOMAIN,
        credentials.refresh_credential.expose_secret().as_bytes(),
    )?;
    let next_access_verifier = credential_verifier(
        identity,
        ACCESS_TOKEN_DOMAIN,
        credentials.access_token.expose_secret().as_bytes(),
    )?;
    transaction.execute(
        "UPDATE refresh_sessions SET generation = generation + 1,
             previous_refresh_verifier = current_refresh_verifier,
             current_refresh_verifier = ?1, current_access_verifier = ?2,
             access_expires_at = ?3, rotated_at = ?4
         WHERE network_id = ?5 AND session_id = ?6",
        params![
            next_refresh_verifier.as_slice(),
            next_access_verifier.as_slice(),
            access_expires_at,
            now,
            network.network_id,
            session_id.to_string(),
        ],
    )?;
    let response = RefreshSessionResponse {
        account,
        credentials,
    };
    transaction.execute(
        "INSERT INTO refresh_idempotency_records(
            network_id, session_id, source_generation, idempotency_key_sha256,
            request_sha256, response_account_json, issued_at, access_expires_at,
            refresh_expires_at
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        params![
            network.network_id,
            session_id.to_string(),
            source_generation,
            key_digest.as_slice(),
            request_digest.as_slice(),
            serde_json::to_string(&response.account)?,
            now,
            access_expires_at,
            stored.5,
        ],
    )?;
    transaction.execute(
        "UPDATE devices SET last_seen_at = ?1 WHERE network_id = ?2 AND device_id = ?3",
        params![now, network.network_id, stored.1],
    )?;
    insert_audit_event(
        &transaction,
        Some(&network.network_id),
        "device",
        Some(&device_id.to_string()),
        "session.refreshed",
        "session",
        Some(&session_id.to_string()),
        "success",
        &serde_json::json!({
            "sourceGeneration": source_generation,
            "generation": source_generation + 1,
        }),
        now,
    )?;
    transaction.commit()?;
    Ok(response)
}

#[allow(clippy::too_many_arguments)]
fn derive_refresh_credentials(
    identity: &ControllerIdentity,
    network_id: &str,
    session_id: SessionId,
    device_id: DeviceId,
    source_generation: i64,
    key_digest: &[u8; 32],
    request_digest: &[u8; 32],
    issued_at: i64,
    access_expires_at: i64,
    refresh_expires_at: i64,
) -> Result<SessionCredentials, DatabaseError> {
    let mut context = Vec::new();
    context.extend_from_slice(network_id.as_bytes());
    context.extend_from_slice(session_id.to_string().as_bytes());
    context.extend_from_slice(device_id.to_string().as_bytes());
    context.extend_from_slice(&source_generation.to_be_bytes());
    context.extend_from_slice(key_digest);
    context.extend_from_slice(request_digest);
    context.extend_from_slice(&issued_at.to_be_bytes());
    Ok(SessionCredentials {
        session_id,
        access_token: Secret::new(format!(
            "rca1.{session_id}.{}",
            derive_secret(identity, ACCESS_TOKEN_DOMAIN, &context)?
        )),
        access_expires_at: timestamp(access_expires_at)?,
        refresh_credential: Secret::new(format!(
            "rcr1.{session_id}.{}",
            derive_secret(identity, REFRESH_TOKEN_DOMAIN, &context)?
        )),
        refresh_expires_at: timestamp(refresh_expires_at)?,
    })
}

fn authenticate_member(
    connection: &mut Connection,
    identity: &ControllerIdentity,
    raw_access_token: &str,
) -> Result<AuthenticatedMember, DatabaseError> {
    let session_id = parse_prefixed_id::<SessionId>(raw_access_token, "rca1")?;
    let verifier = credential_verifier(identity, ACCESS_TOKEN_DOMAIN, raw_access_token.as_bytes())?;
    let now = unix_timestamp()?;
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let network = load_network(&transaction)?;
    let stored = transaction
        .query_row(
            "SELECT session.user_id, session.device_id, session.current_access_verifier,
                    session.access_expires_at, session.expires_at, session.revoked_at,
                    session.credential_version, user.credential_version, user.status, device.status
             FROM refresh_sessions AS session
             JOIN users AS user ON user.network_id = session.network_id AND user.user_id = session.user_id
             JOIN devices AS device ON device.network_id = session.network_id
                AND device.device_id = session.device_id AND device.user_id = session.user_id
             WHERE session.network_id = ?1 AND session.session_id = ?2",
            params![network.network_id, session_id.to_string()],
            |row| {
                Ok((
                    row.get::<_, String>(0)?, row.get::<_, String>(1)?, row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, i64>(3)?, row.get::<_, i64>(4)?, row.get::<_, Option<i64>>(5)?,
                    row.get::<_, i64>(6)?, row.get::<_, i64>(7)?, row.get::<_, String>(8)?,
                    row.get::<_, String>(9)?,
                ))
            },
        )
        .optional()?
        .ok_or(DatabaseError::MemberAuthenticationFailed)?;
    if !bool::from(stored.2.as_slice().ct_eq(verifier.as_slice()))
        || stored.3 <= now
        || stored.4 <= now
        || stored.5.is_some()
        || stored.6 != stored.7
        || stored.8 != "active"
        || stored.9 != "active"
    {
        return Err(DatabaseError::MemberAuthenticationFailed);
    }
    let user_id = stored
        .0
        .parse()
        .map_err(|_| DatabaseError::StoredProtocolValue)?;
    let device_id = stored
        .1
        .parse()
        .map_err(|_| DatabaseError::StoredProtocolValue)?;
    transaction.execute(
        "UPDATE devices SET last_seen_at = ?1 WHERE network_id = ?2 AND device_id = ?3",
        params![now, network.network_id, stored.1],
    )?;
    transaction.commit()?;
    Ok(AuthenticatedMember {
        network_id: network
            .network_id
            .parse()
            .map_err(|_| DatabaseError::StoredProtocolValue)?,
        user_id,
        device_id,
        session_id,
    })
}

fn revoke_member_session(
    connection: &mut Connection,
    member: AuthenticatedMember,
    path_device_id: DeviceId,
    reason: &str,
) -> Result<(), DatabaseError> {
    if member.device_id != path_device_id {
        return Err(DatabaseError::MemberAuthenticationFailed);
    }
    let now = unix_timestamp()?;
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    transaction.execute(
        "UPDATE refresh_sessions SET revoked_at = COALESCE(revoked_at, ?1),
             revoke_reason = COALESCE(revoke_reason, ?2)
         WHERE network_id = ?3 AND session_id = ?4 AND device_id = ?5",
        params![
            now,
            reason,
            member.network_id.to_string(),
            member.session_id.to_string(),
            member.device_id.to_string()
        ],
    )?;
    insert_audit_event(
        &transaction,
        Some(&member.network_id.to_string()),
        "device",
        Some(&member.device_id.to_string()),
        "session.logout",
        "session",
        Some(&member.session_id.to_string()),
        "success",
        &serde_json::json!({}),
        now,
    )?;
    transaction.commit()?;
    Ok(())
}

fn revoke_member_device(
    connection: &mut Connection,
    identity: &ControllerIdentity,
    device_id: DeviceId,
) -> Result<(), DatabaseError> {
    let now = unix_timestamp()?;
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let mut network = load_network(&transaction)?;
    let user_id = transaction
        .query_row(
            "SELECT user_id FROM devices WHERE network_id = ?1 AND device_id = ?2",
            params![network.network_id, device_id.to_string()],
            |row| row.get::<_, String>(0),
        )
        .optional()?
        .ok_or(DatabaseError::DeviceNotFound)?
        .parse::<UserId>()
        .map_err(|_| DatabaseError::StoredProtocolValue)?;
    let changed = transaction.execute(
        "UPDATE devices SET status = 'revoked', revoked_at = COALESCE(revoked_at, ?1)
         WHERE network_id = ?2 AND device_id = ?3 AND status = 'active'",
        params![now, network.network_id, device_id.to_string()],
    )?;
    transaction.execute(
        "UPDATE refresh_sessions SET revoked_at = COALESCE(revoked_at, ?1),
             revoke_reason = COALESCE(revoke_reason, 'device-revoked')
         WHERE network_id = ?2 AND device_id = ?3 AND revoked_at IS NULL",
        params![now, network.network_id, device_id.to_string()],
    )?;
    let revisions = if changed == 1 {
        let affected_nodes =
            rotate_account_credentials(&transaction, &network.network_id, user_id, now)?;
        publish_account_revisions(
            &transaction,
            identity,
            &mut network,
            &affected_nodes,
            "member-device-revocation",
            now,
        )?
    } else {
        Vec::new()
    };
    insert_audit_event(
        &transaction,
        Some(&network.network_id),
        "admin",
        None,
        "device.revoked",
        "device",
        Some(&device_id.to_string()),
        "success",
        &serde_json::json!({
            "changed": changed > 0,
            "publishedRevisions": revision_audit_details(&revisions),
        }),
        now,
    )?;
    transaction.commit()?;
    Ok(())
}

fn rotate_account_credentials(
    connection: &Connection,
    network_id: &str,
    user_id: UserId,
    now: i64,
) -> Result<BTreeSet<NodeId>, DatabaseError> {
    let assignments = load_stored_assignments(connection, network_id, user_id)?;
    let mut affected_nodes = BTreeSet::new();
    for (node_id, assignment) in assignments {
        if assignment.status != "enabled" {
            continue;
        }
        revoke_assignment_credentials(connection, network_id, assignment.assignment_id, now)?;
        issue_assignment_credential(
            connection,
            network_id,
            assignment.assignment_id,
            user_id,
            node_id,
            now,
        )?;
        affected_nodes.insert(node_id);
    }
    Ok(affected_nodes)
}

fn revoke_user_sessions(
    connection: &Connection,
    network_id: &str,
    user_id: UserId,
    now: i64,
    reason: &str,
) -> Result<usize, DatabaseError> {
    Ok(connection.execute(
        "UPDATE refresh_sessions SET revoked_at = COALESCE(revoked_at, ?1),
             revoke_reason = COALESCE(revoke_reason, ?2)
         WHERE network_id = ?3 AND user_id = ?4 AND revoked_at IS NULL",
        params![now, reason, network_id, user_id.to_string()],
    )?)
}

fn load_account_metadata(
    connection: &Connection,
    network_id: &str,
    user_id: UserId,
) -> Result<AccountMetadata, DatabaseError> {
    connection
        .query_row(
            "SELECT display_name, status FROM users WHERE network_id = ?1 AND user_id = ?2",
            params![network_id, user_id.to_string()],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
        )
        .map_err(DatabaseError::from)
        .and_then(|stored| {
            Ok(AccountMetadata {
                user_id,
                display_name: stored.0,
                status: parse_account_status(&stored.1)?,
            })
        })
}

fn derive_secret(
    identity: &ControllerIdentity,
    domain: &[u8],
    context: &[u8],
) -> Result<String, DatabaseError> {
    let mut digest = Sha256::new();
    digest.update(domain);
    digest.update(context);
    let signature = identity.sign(&digest.finalize())?;
    Ok(URL_SAFE_NO_PAD.encode(Sha256::digest(signature.as_str().as_bytes())))
}

fn credential_verifier(
    identity: &ControllerIdentity,
    domain: &[u8],
    raw: &[u8],
) -> Result<[u8; 32], DatabaseError> {
    let mut digest = Sha256::new();
    digest.update(domain);
    digest.update(raw);
    let keyed = identity.sign(&digest.finalize())?;
    Ok(Sha256::digest(keyed.as_str().as_bytes()).into())
}

fn canonical_request_digest<T: serde::Serialize>(
    domain: &[u8],
    request: &T,
) -> Result<[u8; 32], DatabaseError> {
    let mut digest = Sha256::new();
    digest.update(domain);
    digest.update(serde_json::to_vec(request)?);
    Ok(digest.finalize().into())
}

fn parse_prefixed_id<T>(raw: &str, prefix: &str) -> Result<T, DatabaseError>
where
    T: std::str::FromStr,
{
    let mut parts = raw.split('.');
    if parts.next() != Some(prefix) {
        return Err(DatabaseError::MemberAuthenticationFailed);
    }
    let id = parts
        .next()
        .ok_or(DatabaseError::MemberAuthenticationFailed)?;
    if parts.next().is_none() || parts.next().is_some() {
        return Err(DatabaseError::MemberAuthenticationFailed);
    }
    id.parse()
        .map_err(|_| DatabaseError::MemberAuthenticationFailed)
}

#[allow(clippy::too_many_lines)]
fn member_profile_bundle(
    connection: &mut Connection,
    identity: &ControllerIdentity,
    member: AuthenticatedMember,
) -> Result<StoredProfileBundle, DatabaseError> {
    let now = unix_timestamp()?;
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let network = load_network(&transaction)?;
    if network.network_id != member.network_id.to_string() {
        return Err(DatabaseError::MemberAuthenticationFailed);
    }
    let device_key = transaction
        .query_row(
            "SELECT device.encryption_public_key
             FROM devices AS device
             JOIN users AS user ON user.network_id = device.network_id AND user.user_id = device.user_id
             JOIN refresh_sessions AS session ON session.network_id = device.network_id
                AND session.device_id = device.device_id AND session.user_id = device.user_id
             WHERE device.network_id = ?1 AND device.device_id = ?2 AND device.user_id = ?3
               AND session.session_id = ?4 AND device.status = 'active' AND user.status = 'active'
               AND session.revoked_at IS NULL AND session.expires_at > ?5
               AND session.credential_version = user.credential_version",
            params![
                network.network_id,
                member.device_id.to_string(),
                member.user_id.to_string(),
                member.session_id.to_string(),
                now,
            ],
            |row| row.get::<_, String>(0),
        )
        .optional()?
        .ok_or(DatabaseError::MemberAuthenticationFailed)?
        .parse::<control_protocol::crypto::X25519PublicKey>()
        .map_err(|_| DatabaseError::StoredProtocolValue)?;
    let profiles = load_bundle_profiles(&transaction, identity, &network, member.user_id, now)?;
    let source_json = serde_json::to_vec(&profiles)?;
    let source_digest: [u8; 32] = Sha256::digest(&source_json).into();
    if let Some(stored) = transaction
        .query_row(
            "SELECT artifact_json, artifact_sha256, etag
             FROM profile_bundles WHERE network_id = ?1 AND device_id = ?2
               AND superseded_at IS NULL AND source_sha256 = ?3 AND offline_expires_at > ?4
             ORDER BY generation DESC LIMIT 1",
            params![
                network.network_id,
                member.device_id.to_string(),
                source_digest.as_slice(),
                now,
            ],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, String>(2)?,
                ))
            },
        )
        .optional()?
    {
        let digest: [u8; 32] = Sha256::digest(stored.0.as_bytes()).into();
        if stored.1.as_slice() != digest {
            return Err(DatabaseError::StoredProfileBundleCorrupt);
        }
        let bundle: SignedProfileBundle = serde_json::from_str(&stored.0)?;
        let transcript =
            profile_bundle_signature_transcript(&bundle.manifest, &bundle.encrypted_profiles)?;
        control_protocol::account_crypto::verify_profile_bundle_signature(
            &identity.public_key(),
            &bundle.signature,
            &transcript,
        )?;
        transaction.commit()?;
        return Ok(StoredProfileBundle {
            bundle,
            etag: stored.2,
        });
    }

    let generation_value: i64 = transaction.query_row(
        "SELECT COALESCE(MAX(generation), 0) + 1 FROM profile_bundles
         WHERE network_id = ?1 AND device_id = ?2",
        params![network.network_id, member.device_id.to_string()],
        |row| row.get(0),
    )?;
    let generation = BundleGeneration::new(generation_value)
        .map_err(|_| DatabaseError::BundleGenerationOverflow)?;
    let bundle_id = BundleId::new();
    let issued_at = timestamp(now)?;
    let refresh_after_value = now
        .checked_add(BUNDLE_REFRESH_SECONDS)
        .ok_or(DatabaseError::TimestampOverflow)?;
    let offline_expires_value = now
        .checked_add(BUNDLE_OFFLINE_SECONDS)
        .ok_or(DatabaseError::TimestampOverflow)?;
    let mut encrypted_profiles = Vec::with_capacity(profiles.len());
    let mut descriptors = Vec::with_capacity(profiles.len());
    for (priority, profile) in profiles.iter().enumerate() {
        let aad = profile_encryption_aad(
            member.network_id,
            member.user_id,
            member.device_id,
            bundle_id,
            generation,
            profile.node_id,
        );
        let encrypted = encrypt_profile(&device_key, &serde_json::to_vec(profile)?, &aad)?;
        let payload = EncryptedProfilePayload {
            node_id: profile.node_id,
            algorithm: encrypted.algorithm,
            ephemeral_public_key: encrypted.ephemeral_public_key,
            nonce: encrypted.nonce,
            ciphertext: encrypted.ciphertext,
        };
        descriptors.push(ProfileDescriptor {
            node_id: profile.node_id,
            display_name: profile.display_name.clone(),
            region: profile.region.clone(),
            endpoint_mode: profile.endpoint.mode,
            encrypted_payload_digest: encrypted_profile_digest(&payload)?,
            priority: u16::try_from(priority).map_err(|_| DatabaseError::StoredProtocolValue)?,
        });
        encrypted_profiles.push(payload);
    }
    let manifest = ProfileBundleManifest {
        schema_version: 1,
        format_version: 1,
        bundle_id,
        network_id: member.network_id,
        user_id: member.user_id,
        device_id: member.device_id,
        signing_key_id: controller_signing_key_id(identity)?,
        controller_instance_id: network
            .controller_epoch
            .parse()
            .map_err(|_| DatabaseError::StoredProtocolValue)?,
        generation,
        issued_at,
        not_before: issued_at,
        refresh_after: timestamp(refresh_after_value)?,
        offline_expires_at: timestamp(offline_expires_value)?,
        min_client_version: "0.1.0".to_string(),
        account_status: AccountStatus::Active,
        profiles: descriptors,
        selection_hints: SelectionHints {
            minimum_hold_seconds: 300,
            latency_tolerance_milliseconds: 40,
            failure_threshold: 3,
        },
        replacement: None,
    };
    let transcript = profile_bundle_signature_transcript(&manifest, &encrypted_profiles)?;
    let signature = identity.sign(&transcript)?;
    let bundle = SignedProfileBundle {
        manifest,
        encrypted_profiles,
        signature,
    };
    bundle.validate_shape(&[1], &[1])?;
    let artifact_json = serde_json::to_string(&bundle)?;
    let artifact_digest: [u8; 32] = Sha256::digest(artifact_json.as_bytes()).into();
    let etag = format!("\"sha256-{}\"", URL_SAFE_NO_PAD.encode(artifact_digest));
    transaction.execute(
        "UPDATE profile_bundles SET superseded_at = ?1
         WHERE network_id = ?2 AND device_id = ?3 AND superseded_at IS NULL",
        params![now, network.network_id, member.device_id.to_string()],
    )?;
    transaction.execute(
        "INSERT INTO profile_bundles(
            network_id, bundle_id, user_id, device_id, generation, source_sha256,
            artifact_json, artifact_sha256, signature, etag, issued_at,
            refresh_after, offline_expires_at
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
        params![
            network.network_id,
            bundle_id.to_string(),
            member.user_id.to_string(),
            member.device_id.to_string(),
            generation.get(),
            source_digest.as_slice(),
            artifact_json,
            artifact_digest.as_slice(),
            bundle.signature.as_str(),
            etag,
            now,
            refresh_after_value,
            offline_expires_value,
        ],
    )?;
    insert_audit_event(
        &transaction,
        Some(&network.network_id),
        "device",
        Some(&member.device_id.to_string()),
        "profile-bundle.issued",
        "profile-bundle",
        Some(&bundle_id.to_string()),
        "success",
        &serde_json::json!({"generation": generation, "profileCount": profiles.len()}),
        now,
    )?;
    transaction.commit()?;
    Ok(StoredProfileBundle { bundle, etag })
}

#[allow(clippy::too_many_lines)]
fn load_bundle_profiles(
    connection: &Connection,
    identity: &ControllerIdentity,
    network: &NetworkRecord,
    user_id: UserId,
    now: i64,
) -> Result<Vec<NodeProfile>, DatabaseError> {
    let mut statement = connection.prepare(
        "SELECT node.node_id, node.display_name, node.reality_public_key,
                node.reality_short_id, node.applied_revision,
                credential.credential_id, credential.vless_uuid,
                candidate.mode, candidate.address, candidate.port,
                verification.latency_ms
         FROM user_node_assignments AS assignment
         JOIN users AS user ON user.network_id = assignment.network_id AND user.user_id = assignment.user_id
         JOIN nodes AS node ON node.network_id = assignment.network_id AND node.node_id = assignment.node_id
         JOIN user_node_credentials AS credential ON credential.network_id = assignment.network_id
            AND credential.assignment_id = assignment.assignment_id AND credential.user_id = assignment.user_id
            AND credential.node_id = assignment.node_id
         JOIN node_revision_member_credentials AS applied ON applied.network_id = node.network_id
            AND applied.node_id = node.node_id AND applied.revision = node.applied_revision
            AND applied.assignment_id = assignment.assignment_id AND applied.credential_id = credential.credential_id
         JOIN node_revision_results AS result ON result.network_id = node.network_id
            AND result.node_id = node.node_id AND result.revision = node.applied_revision
            AND result.state = 'applied'
         JOIN node_endpoint_candidates AS candidate ON candidate.network_id = node.network_id
            AND candidate.node_id = node.node_id AND candidate.applied_revision = node.applied_revision
            AND candidate.withdrawn_at IS NULL
         JOIN node_endpoint_verifications AS verification ON verification.network_id = candidate.network_id
            AND verification.node_id = candidate.node_id AND verification.endpoint_id = candidate.endpoint_id
            AND verification.status = 'verified' AND verification.verification_expires_at > ?3
         WHERE assignment.network_id = ?1 AND assignment.user_id = ?2
           AND user.status = 'active' AND assignment.status = 'enabled'
           AND node.status = 'active' AND node.provider_paused = 0
           AND credential.status = 'active'
           AND node.reality_public_key IS NOT NULL AND node.reality_short_id IS NOT NULL
           AND EXISTS(
               SELECT 1 FROM endpoint_probe_attempts AS probe
               WHERE probe.network_id = candidate.network_id AND probe.node_id = candidate.node_id
                 AND probe.endpoint_id = candidate.endpoint_id AND probe.phase = 'protocol'
                 AND probe.status = 'succeeded' AND probe.applied_revision = candidate.applied_revision
                 AND probe.address = candidate.address AND probe.port = candidate.port
           )
         ORDER BY node.node_id ASC,
             CASE candidate.mode WHEN 'direct' THEN 0 ELSE 1 END ASC,
             verification.latency_ms ASC, candidate.endpoint_id ASC",
    )?;
    let rows = statement
        .query_map(
            params![network.network_id, user_id.to_string(), now],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, String>(6)?,
                    row.get::<_, String>(7)?,
                    row.get::<_, String>(8)?,
                    row.get::<_, u16>(9)?,
                ))
            },
        )?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    drop(statement);
    let mut profiles = Vec::new();
    let mut seen = BTreeSet::new();
    for row in rows {
        let node_id = row
            .0
            .parse::<NodeId>()
            .map_err(|_| DatabaseError::StoredProtocolValue)?;
        if !seen.insert(node_id) {
            continue;
        }
        let stored = load_stored_desired_revision(connection, &network.network_id, &row.0, row.4)?
            .ok_or(DatabaseError::StoredDesiredStateCorrupt)?;
        let desired = verify_desired_revision(identity, network, node_id, &stored)?;
        let server_name = desired
            .document
            .xray
            .server_names
            .first()
            .cloned()
            .ok_or(DatabaseError::StoredDesiredStateCorrupt)?;
        profiles.push(NodeProfile {
            node_id,
            credential_id: row
                .5
                .parse()
                .map_err(|_| DatabaseError::StoredProtocolValue)?,
            display_name: row.1,
            region: None,
            endpoint: ProfileEndpoint {
                mode: match row.7.as_str() {
                    "direct" => control_protocol::node::EndpointMode::Direct,
                    "relay" => control_protocol::node::EndpointMode::Relay,
                    _ => return Err(DatabaseError::StoredProtocolValue),
                },
                address: row.8,
                port: row.9,
            },
            connection: RealityConnectionParameters {
                vless_uuid: Secret::new(row.6),
                flow: "xtls-rprx-vision".to_string(),
                server_name,
                fingerprint: "chrome".to_string(),
                reality_public_key: Secret::new(row.2),
                short_id: Secret::new(row.3),
                spider_x: Secret::new("/".to_string()),
            },
        });
    }
    Ok(profiles)
}

fn profile_encryption_aad(
    network_id: NetworkId,
    user_id: UserId,
    device_id: DeviceId,
    bundle_id: BundleId,
    generation: BundleGeneration,
    node_id: NodeId,
) -> Vec<u8> {
    format!(
        "control/profile-aad/v1\0{network_id}\0{user_id}\0{device_id}\0{bundle_id}\0{}\0{node_id}",
        generation.get()
    )
    .into_bytes()
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
            revoke_user_sessions(connection, network_id, user_id, now, "account-disabled")?;
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
            revoke_user_sessions(connection, network_id, user_id, now, "account-deleted")?;
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
    revoke_node_relay_grants(&transaction, &network.network_id, &node_id, now)?;
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

fn revoke_node_relay_grants(
    transaction: &rusqlite::Transaction<'_>,
    network_id: &str,
    node_id: &str,
    now: i64,
) -> Result<(), DatabaseError> {
    transaction.execute(
        "UPDATE relay_grants SET state = 'revoking' WHERE network_id = ?1 AND node_id = ?2
         AND state IN ('pending', 'published')",
        params![network_id, node_id],
    )?;
    transaction.execute(
        "INSERT OR IGNORE INTO relay_outbox(network_id, grant_id, action, next_attempt_at, created_at)
         SELECT network_id, grant_id, 'revoke', ?1, ?1 FROM relay_grants
         WHERE network_id = ?2 AND node_id = ?3 AND state = 'revoking'",
        params![now, network_id, node_id],
    )?;
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

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
fn prepare_relay_grant(
    connection: &mut Connection,
    node_id: NodeId,
    relay_id: control_protocol::id::RelayId,
    public_host: &str,
    tunnel_host: &str,
    tunnel_port: u16,
    tls_server_name: &str,
    public_port_start: u16,
    public_port_end: u16,
    limits: control_protocol::relay::RelayLimits,
) -> Result<RelayGrantDraft, DatabaseError> {
    let now = unix_timestamp()?;
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let network = load_network(&transaction)?;
    let node = transaction
        .query_row(
            "SELECT status, capabilities_json, consent_exit_ip, encryption_public_key
         FROM nodes WHERE network_id = ?1 AND node_id = ?2",
            params![network.network_id, node_id.to_string()],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, bool>(2)?,
                    row.get::<_, String>(3)?,
                ))
            },
        )
        .optional()?
        .ok_or(DatabaseError::NodeNotFound)?;
    let capabilities: Vec<NodeCapability> = serde_json::from_str(&node.1)?;
    if node.0 != "active" || !node.2 || !capabilities.contains(&NodeCapability::RelayTcp) {
        return Err(DatabaseError::RelayNotEligible);
    }
    let recipient_encryption_key = node
        .3
        .parse()
        .map_err(|_| DatabaseError::StoredProtocolValue)?;
    let route = transaction
        .query_row(
            "SELECT route_id, endpoint_id FROM relay_routes WHERE network_id = ?1 AND node_id = ?2",
            params![network.network_id, node_id.to_string()],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
        )
        .optional()?;
    let (route_id, endpoint_id) = if let Some((route_id, endpoint_id)) = route {
        (
            route_id
                .parse()
                .map_err(|_| DatabaseError::StoredProtocolValue)?,
            endpoint_id
                .parse()
                .map_err(|_| DatabaseError::StoredProtocolValue)?,
        )
    } else {
        let route_id = RelayRouteId::new();
        let endpoint_id = EndpointId::new();
        transaction.execute(
            "INSERT INTO relay_routes(network_id, node_id, route_id, endpoint_id, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                network.network_id,
                node_id.to_string(),
                route_id.to_string(),
                endpoint_id.to_string(),
                now
            ],
        )?;
        (route_id, endpoint_id)
    };
    let next_generation: i64 = transaction.query_row(
        "SELECT COALESCE(MAX(generation), 0) + 1 FROM relay_grants WHERE network_id = ?1 AND route_id = ?2",
        params![network.network_id, route_id.to_string()], |row| row.get(0),
    )?;
    let generation = RelayGeneration::new(next_generation)
        .map_err(|_| DatabaseError::RelayGenerationOverflow)?;
    let mut public_port = None;
    for port in public_port_start..=public_port_end {
        let used: bool = transaction.query_row(
            "SELECT EXISTS(SELECT 1 FROM relay_grants WHERE network_id = ?1 AND public_port = ?2
              AND state IN ('pending', 'published', 'revoking'))",
            params![network.network_id, i64::from(port)],
            |row| row.get(0),
        )?;
        if !used {
            public_port = Some(port);
            break;
        }
    }
    let public_port = public_port.ok_or(DatabaseError::RelayPortExhausted)?;
    let issued_at = timestamp(now)?;
    let expires_at = timestamp(
        now.checked_add(control_protocol::relay::MAX_RELAY_GRANT_LIFETIME_SECONDS)
            .ok_or(DatabaseError::TimestampOverflow)?,
    )?;
    let header = RelayAssignmentHeader {
        schema_version: control_protocol::relay::RELAY_SCHEMA_VERSION,
        network_id: network
            .network_id
            .parse()
            .map_err(|_| DatabaseError::StoredProtocolValue)?,
        node_id,
        relay_id,
        route_id,
        grant_id: RelayGrantId::new(),
        generation,
        endpoint_id,
        public_host: public_host.to_owned(),
        public_port,
        tunnel_host: tunnel_host.to_owned(),
        tunnel_port,
        tls_server_name: tls_server_name.to_owned(),
        issued_at,
        not_before: issued_at,
        expires_at,
        limits,
    };
    header.validate()?;
    transaction.commit()?;
    Ok(RelayGrantDraft {
        header,
        recipient_encryption_key,
    })
}

fn store_pending_relay_grant(
    connection: &mut Connection,
    assignment: &SignedRelayAssignment,
    route: &SignedRelayRoute,
) -> Result<(), DatabaseError> {
    assignment.validate()?;
    route.validate()?;
    if assignment.header != route.header || assignment.signing_key_id != route.signing_key_id {
        return Err(DatabaseError::RelayGrantMismatch);
    }
    let now = unix_timestamp()?;
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let network = load_network(&transaction)?;
    let header = &assignment.header;
    let route_exists: bool = transaction.query_row(
        "SELECT EXISTS(SELECT 1 FROM relay_routes WHERE network_id = ?1 AND node_id = ?2 AND route_id = ?3)",
        params![network.network_id, header.node_id.to_string(), header.route_id.to_string()], |row| row.get(0),
    )?;
    if !route_exists {
        return Err(DatabaseError::RelayGrantMismatch);
    }
    let route_bytes = serde_json::to_vec(route)?;
    let route_sha256 = format!("sha256:{:x}", Sha256::digest(&route_bytes));
    transaction.execute(
        "INSERT INTO relay_grants(network_id, grant_id, node_id, route_id, generation, public_port, state,
             header_json, assignment_json, route_json, route_sha256, issued_at, expires_at, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'pending', ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
        params![network.network_id, header.grant_id.to_string(), header.node_id.to_string(), header.route_id.to_string(),
            header.generation.get(), i64::from(header.public_port), serde_json::to_string(header)?,
            serde_json::to_string(assignment)?, serde_json::to_string(route)?, route_sha256,
            header.issued_at.as_datetime().unix_timestamp(), header.expires_at.as_datetime().unix_timestamp(), now],
    )?;
    transaction.execute(
        "INSERT INTO relay_outbox(network_id, grant_id, action, next_attempt_at, created_at)
         VALUES (?1, ?2, 'publish', ?3, ?3)",
        params![network.network_id, header.grant_id.to_string(), now],
    )?;
    transaction.commit()?;
    Ok(())
}

fn relay_assignment(
    connection: &Connection,
    node_id: NodeId,
) -> Result<Option<SignedRelayAssignment>, DatabaseError> {
    let network = load_network(connection)?;
    let now = unix_timestamp()?;
    connection
        .query_row(
            "SELECT assignment_json FROM relay_grants WHERE network_id = ?1 AND node_id = ?2
         AND state = 'published' AND expires_at > ?3 ORDER BY generation DESC LIMIT 1",
            params![network.network_id, node_id.to_string(), now],
            |row| row.get::<_, String>(0),
        )
        .optional()?
        .map(|json| {
            let assignment: SignedRelayAssignment = serde_json::from_str(&json)?;
            assignment.validate()?;
            Ok(assignment)
        })
        .transpose()
}

fn expire_relay_grants(connection: &mut Connection) -> Result<(), DatabaseError> {
    let now = unix_timestamp()?;
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    transaction.execute(
        "UPDATE relay_grants SET state = 'revoking' WHERE state IN ('pending', 'published') AND expires_at <= ?1",
        [now],
    )?;
    transaction.execute(
        "INSERT OR IGNORE INTO relay_outbox(network_id, grant_id, action, next_attempt_at, created_at)
         SELECT network_id, grant_id, 'revoke', ?1, ?1 FROM relay_grants WHERE state = 'revoking'",
        [now],
    )?;
    transaction.commit()?;
    Ok(())
}

fn due_relay_outbox(connection: &Connection) -> Result<Vec<RelayOutboxJob>, DatabaseError> {
    let now = unix_timestamp()?;
    let mut statement = connection.prepare(
        "SELECT outbox.grant_id, outbox.action, grants.route_json FROM relay_outbox AS outbox
         JOIN relay_grants AS grants ON grants.network_id = outbox.network_id AND grants.grant_id = outbox.grant_id
         WHERE outbox.completed_at IS NULL AND outbox.next_attempt_at <= ?1
           AND ((outbox.action = 'publish' AND grants.state = 'pending')
             OR (outbox.action = 'revoke' AND grants.state = 'revoking'))
         ORDER BY outbox.created_at ASC",
    )?;
    let jobs = statement
        .query_map([now], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
            ))
        })?
        .map(|row| {
            let (grant_id, action, route_json) = row?;
            let grant_id = grant_id
                .parse()
                .map_err(|_| DatabaseError::StoredProtocolValue)?;
            match action.as_str() {
                "publish" => {
                    let route: SignedRelayRoute = serde_json::from_str(&route_json)?;
                    route.validate()?;
                    Ok(RelayOutboxJob {
                        grant_id,
                        action: RelayOutboxAction::Publish,
                        route: Some(route),
                    })
                }
                "revoke" => Ok(RelayOutboxJob {
                    grant_id,
                    action: RelayOutboxAction::Revoke,
                    route: None,
                }),
                _ => Err(DatabaseError::StoredProtocolValue),
            }
        })
        .collect();
    jobs
}

fn mark_relay_published(
    connection: &mut Connection,
    grant_id: RelayGrantId,
) -> Result<(), DatabaseError> {
    let now = unix_timestamp()?;
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let network = load_network(&transaction)?;
    let exists: bool = transaction.query_row(
        "SELECT EXISTS(SELECT 1 FROM relay_grants
         WHERE network_id = ?1 AND grant_id = ?2 AND state = 'pending')",
        params![network.network_id, grant_id.to_string()],
        |row| row.get(0),
    )?;
    if !exists {
        return Err(DatabaseError::RelayGrantNotPending);
    }
    transaction.execute("UPDATE relay_grants SET state = 'published', published_at = ?1 WHERE network_id = ?2 AND grant_id = ?3",
        params![now, network.network_id, grant_id.to_string()])?;
    transaction.execute("UPDATE relay_outbox SET completed_at = ?1 WHERE network_id = ?2 AND grant_id = ?3 AND action = 'publish'",
        params![now, network.network_id, grant_id.to_string()])?;
    transaction.commit()?;
    Ok(())
}

fn acknowledge_relay_assignment(
    connection: &mut Connection,
    node_id: NodeId,
    acknowledgement: AcknowledgeRelayAssignmentRequest,
) -> Result<(), DatabaseError> {
    acknowledgement.validate()?;
    let now = unix_timestamp()?;
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let network = load_network(&transaction)?;
    let route_id: String = transaction
        .query_row(
            "SELECT route_id FROM relay_grants
             WHERE network_id = ?1 AND node_id = ?2 AND grant_id = ?3
               AND generation = ?4 AND state = 'published' AND expires_at > ?5
               AND NOT EXISTS(
                   SELECT 1 FROM relay_grants AS newer
                   WHERE newer.network_id = relay_grants.network_id
                     AND newer.node_id = relay_grants.node_id
                     AND newer.route_id = relay_grants.route_id
                     AND newer.generation > relay_grants.generation
                     AND newer.state = 'published'
               )",
            params![
                network.network_id,
                node_id.to_string(),
                acknowledgement.grant_id.to_string(),
                acknowledgement.generation.get(),
                now
            ],
            |row| row.get(0),
        )
        .optional()?
        .ok_or(DatabaseError::RelayAcknowledgementConflict)?;
    transaction.execute(
        "UPDATE relay_grants SET state = 'revoking'
         WHERE network_id = ?1 AND node_id = ?2 AND route_id = ?3
           AND generation < ?4 AND state = 'published'",
        params![
            network.network_id,
            node_id.to_string(),
            route_id,
            acknowledgement.generation.get()
        ],
    )?;
    transaction.execute(
        "INSERT OR IGNORE INTO relay_outbox(
            network_id, grant_id, action, next_attempt_at, created_at
         )
         SELECT network_id, grant_id, 'revoke', ?1, ?1 FROM relay_grants
         WHERE network_id = ?2 AND node_id = ?3 AND route_id = ?4 AND state = 'revoking'",
        params![now, network.network_id, node_id.to_string(), route_id],
    )?;
    transaction.commit()?;
    Ok(())
}

fn mark_relay_revoked(
    connection: &mut Connection,
    grant_id: RelayGrantId,
) -> Result<(), DatabaseError> {
    let now = unix_timestamp()?;
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let network = load_network(&transaction)?;
    transaction.execute(
        "UPDATE relay_grants SET state = 'revoked', revoked_at = ?1 WHERE network_id = ?2 AND grant_id = ?3 AND state = 'revoking'",
        params![now, network.network_id, grant_id.to_string()],
    )?;
    transaction.execute("UPDATE relay_outbox SET completed_at = ?1 WHERE network_id = ?2 AND grant_id = ?3 AND action = 'revoke'",
        params![now, network.network_id, grant_id.to_string()])?;
    transaction.commit()?;
    Ok(())
}

fn record_relay_outbox_failure(
    connection: &mut Connection,
    grant_id: RelayGrantId,
    action: RelayOutboxAction,
) -> Result<(), DatabaseError> {
    let now = unix_timestamp()?;
    let action = match action {
        RelayOutboxAction::Publish => "publish",
        RelayOutboxAction::Revoke => "revoke",
    };
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let network = load_network(&transaction)?;
    let attempts: i64 = transaction.query_row(
        "SELECT attempts FROM relay_outbox WHERE network_id = ?1 AND grant_id = ?2 AND action = ?3",
        params![network.network_id, grant_id.to_string(), action],
        |row| row.get(0),
    )?;
    let delay = 1_i64
        .checked_shl(u32::try_from(attempts.min(8)).unwrap_or(8))
        .unwrap_or(300)
        .min(300);
    transaction.execute("UPDATE relay_outbox SET attempts = attempts + 1, next_attempt_at = ?1 WHERE network_id = ?2 AND grant_id = ?3 AND action = ?4",
        params![now + delay, network.network_id, grant_id.to_string(), action])?;
    transaction.commit()?;
    Ok(())
}

fn revoke_relay_grant(
    connection: &mut Connection,
    grant_id: RelayGrantId,
) -> Result<(), DatabaseError> {
    let now = unix_timestamp()?;
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let network = load_network(&transaction)?;
    let changed = transaction.execute(
        "UPDATE relay_grants SET state = 'revoking' WHERE network_id = ?1 AND grant_id = ?2 AND state IN ('pending', 'published')",
        params![network.network_id, grant_id.to_string()],
    )?;
    if changed == 0 {
        let exists: bool = transaction.query_row(
            "SELECT EXISTS(SELECT 1 FROM relay_grants WHERE network_id = ?1 AND grant_id = ?2)",
            params![network.network_id, grant_id.to_string()],
            |row| row.get(0),
        )?;
        if !exists {
            return Err(DatabaseError::RelayGrantNotFound);
        }
    }
    transaction.execute("INSERT OR IGNORE INTO relay_outbox(network_id, grant_id, action, next_attempt_at, created_at) VALUES (?1, ?2, 'revoke', ?3, ?3)",
        params![network.network_id, grant_id.to_string(), now])?;
    transaction.commit()?;
    Ok(())
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
    AccountCrypto(#[from] AccountCryptoError),
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
    #[error("database schema {actual} is not the required schema {expected}")]
    SchemaNotCurrent { expected: i64, actual: i64 },
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
    #[error("migration history contains an unexpected migration record")]
    UnexpectedMigrationHistory,
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
    #[error("telemetry batch belongs to another node")]
    TelemetryNodeMismatch,
    #[error("telemetry sequence is not contiguous; expected {expected}")]
    TelemetrySequenceGap { expected: i64 },
    #[error("telemetry sequence space is exhausted")]
    TelemetrySequenceExhausted,
    #[error("telemetry cursor changed during ingestion")]
    TelemetryCursorConflict,
    #[error("telemetry references a member that was never assigned to this node")]
    TelemetryUserNotAssigned,
    #[error("detailed connection telemetry is disabled")]
    DetailedTelemetryDisabled,
    #[error("telemetry event time is unreasonably far in the future")]
    TelemetryClockSkew,
    #[error("telemetry aggregate query is invalid")]
    InvalidTelemetryQuery,
    #[error("telemetry result exceeds protocol limits")]
    TelemetryResultOverflow,
    #[error("the node request signature is invalid")]
    InvalidNodeRequestSignature,
    #[error("the node was not found")]
    NodeNotFound,
    #[error("the member account was not found")]
    AccountNotFound,
    #[error("the device activation is invalid")]
    ActivationInvalid,
    #[error("the device activation has expired")]
    ActivationExpired,
    #[error("the device activation was already consumed")]
    ActivationConsumed,
    #[error("the account reset token is invalid")]
    AccountResetTokenInvalid,
    #[error("the account reset token has expired")]
    AccountResetTokenExpired,
    #[error("the account reset token was already consumed")]
    AccountResetTokenConsumed,
    #[error("the device enrollment proof is invalid")]
    InvalidDeviceProof,
    #[error("member authentication failed")]
    MemberAuthenticationFailed,
    #[error("the account cannot authenticate in its current lifecycle state")]
    AccountAuthenticationBlocked,
    #[error("a rotated refresh credential was reused and the family was revoked")]
    RefreshCredentialReused,
    #[error("the member device was not found")]
    DeviceNotFound,
    #[error("password hashing failed")]
    PasswordHash,
    #[error("profile bundle generation sequence is exhausted")]
    BundleGenerationOverflow,
    #[error("protocol canary credential generation is exhausted")]
    CanaryGenerationOverflow,
    #[error("the stored profile bundle is corrupt")]
    StoredProfileBundleCorrupt,
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
    #[error("the rollback source or failed revision is not an eligible target")]
    RollbackTargetInvalid,
    #[error("the rollback source is incompatible with the current node")]
    RollbackTargetIncompatible,
    #[error("the stored desired-state artifact is corrupt")]
    StoredDesiredStateCorrupt,
    #[error("relay provisioning requires an active relay-capable node with provider consent")]
    RelayNotEligible,
    #[error("the configured relay public-port range is exhausted")]
    RelayPortExhausted,
    #[error("relay generation sequence is exhausted")]
    RelayGenerationOverflow,
    #[error("relay assignment and route metadata do not match")]
    RelayGrantMismatch,
    #[error("the relay grant was not found")]
    RelayGrantNotFound,
    #[error("the relay grant is no longer pending publication")]
    RelayGrantNotPending,
    #[error("the relay generation acknowledgement conflicts with published state")]
    RelayAcknowledgementConflict,
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
        acknowledge_relay_assignment, enforce_telemetry_retention_at, ingest_telemetry, lock_path,
        migration_checksum, unix_timestamp, Database, DatabaseError, MIGRATIONS, SCHEMA_VERSION,
    };
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine as _;
    use control_protocol::id::{
        Count, EndpointId, NodeId, RelayGeneration, RelayGrantId, RelayId, RelayRouteId,
        SequenceNumber, Timestamp, UserId,
    };
    use control_protocol::node::NodeCapability;
    use control_protocol::relay::{AcknowledgeRelayAssignmentRequest, RelayLimits};
    use control_protocol::telemetry::{
        NetworkProtocol, TelemetryBatch, TelemetryEvent, TelemetryEventKind,
        TELEMETRY_SCHEMA_VERSION,
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

    fn insert_relay_node(
        database: &Database,
        capabilities: &[NodeCapability],
        consent: bool,
    ) -> NodeId {
        let node_id = NodeId::new();
        let mut key_bytes = [0_u8; 32];
        key_bytes[..16].copy_from_slice(node_id.as_uuid().as_bytes());
        let key = URL_SAFE_NO_PAD.encode(key_bytes);
        let guard = database.inner.lock().unwrap();
        let network_id: String = guard
            .connection
            .query_row("SELECT network_id FROM networks", [], |row| row.get(0))
            .unwrap();
        guard.connection.execute(
            "INSERT INTO nodes(node_id, network_id, display_name, status, agent_version, platform,
                capabilities_json, identity_public_key, encryption_public_key, consent_policy_version,
                consent_host_owner, consent_exit_ip, consent_accepted_at, created_at, updated_at)
             VALUES (?1, ?2, 'Relay test', 'active', '0.1.0', 'macos-arm64', ?3, ?4, ?5,
                'relay-test', 1, ?6, 1, 1, 1)",
            params![
                node_id.to_string(), network_id, serde_json::to_string(capabilities).unwrap(),
                format!("identity-{node_id}"), key, i64::from(consent),
            ],
        ).unwrap();
        node_id
    }

    #[tokio::test]
    async fn relay_grants_require_capability_and_provider_consent() {
        let temp = TempDir::new().unwrap();
        let database = Database::open(&database_path(&temp), "Relay test").unwrap();
        let limits = RelayLimits {
            max_concurrent_streams: 1,
            max_bytes_per_second: 1_024,
            max_bytes_per_connection: 1_048_576,
            monthly_byte_limit: 1_048_576,
        };
        let no_capability = insert_relay_node(&database, &[NodeCapability::Xray], true);
        let no_consent = insert_relay_node(&database, &[NodeCapability::RelayTcp], false);
        for node_id in [no_capability, no_consent] {
            assert!(matches!(
                database
                    .prepare_relay_grant(
                        node_id,
                        RelayId::new(),
                        "relay.test".to_string(),
                        "relay.test".to_string(),
                        9443,
                        "relay.test".to_string(),
                        20_000,
                        20_010,
                        limits,
                    )
                    .await,
                Err(DatabaseError::RelayNotEligible)
            ));
        }
    }

    #[test]
    fn relay_predecessor_is_retained_until_successor_acknowledgement() {
        let temp = TempDir::new().unwrap();
        let database = Database::open(&database_path(&temp), "Relay rotation").unwrap();
        let node_id = insert_relay_node(&database, &[NodeCapability::RelayTcp], true);
        let route_id = RelayRouteId::new();
        let endpoint_id = EndpointId::new();
        let first = RelayGrantId::new();
        let second = RelayGrantId::new();
        let mut guard = database.inner.lock().unwrap();
        let network_id: String = guard
            .connection
            .query_row("SELECT network_id FROM networks", [], |row| row.get(0))
            .unwrap();
        guard
            .connection
            .execute(
                "INSERT INTO relay_routes(network_id, node_id, route_id, endpoint_id, created_at)
                 VALUES (?1, ?2, ?3, ?4, 1)",
                params![
                    network_id,
                    node_id.to_string(),
                    route_id.to_string(),
                    endpoint_id.to_string()
                ],
            )
            .unwrap();
        let now = unix_timestamp().unwrap();
        for (grant_id, generation, port) in [(first, 1_i64, 20_001_i64), (second, 2, 20_002)] {
            guard
                .connection
                .execute(
                    "INSERT INTO relay_grants(
                    network_id, grant_id, node_id, route_id, generation, public_port, state,
                    header_json, assignment_json, route_json, route_sha256, issued_at,
                    expires_at, published_at, created_at
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'published', '{}', '{}', '{}', ?7,
                    ?8, ?9, ?8, ?8)",
                    params![
                        network_id,
                        grant_id.to_string(),
                        node_id.to_string(),
                        route_id.to_string(),
                        generation,
                        port,
                        format!("sha256:{}", "0".repeat(64)),
                        now,
                        now + 3600
                    ],
                )
                .unwrap();
        }

        acknowledge_relay_assignment(
            &mut guard.connection,
            node_id,
            AcknowledgeRelayAssignmentRequest {
                grant_id: second,
                generation: RelayGeneration::new(2).unwrap(),
            },
        )
        .unwrap();

        let states = guard
            .connection
            .prepare("SELECT generation, state FROM relay_grants ORDER BY generation")
            .unwrap()
            .query_map([], |row| {
                Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
            })
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap();
        assert_eq!(
            states,
            [(1, "revoking".to_string()), (2, "published".to_string())]
        );
        let revoke_jobs: i64 = guard
            .connection
            .query_row(
                "SELECT COUNT(*) FROM relay_outbox WHERE grant_id = ?1 AND action = 'revoke'",
                [first.to_string()],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(revoke_jobs, 1);
        assert!(matches!(
            acknowledge_relay_assignment(
                &mut guard.connection,
                node_id,
                AcknowledgeRelayAssignmentRequest {
                    grant_id: first,
                    generation: RelayGeneration::new(1).unwrap(),
                },
            ),
            Err(DatabaseError::RelayAcknowledgementConflict)
        ));
        acknowledge_relay_assignment(
            &mut guard.connection,
            node_id,
            AcknowledgeRelayAssignmentRequest {
                grant_id: second,
                generation: RelayGeneration::new(2).unwrap(),
            },
        )
        .expect("exact acknowledgement retry is idempotent");
    }

    fn insert_telemetry_subjects(connection: &Connection) -> (String, NodeId, UserId) {
        let network_id: String = connection
            .query_row("SELECT network_id FROM networks", [], |row| row.get(0))
            .unwrap();
        let node_id = NodeId::new();
        let user_id = UserId::new();
        connection
            .execute(
                "INSERT INTO nodes(
                    node_id, network_id, display_name, status, agent_version, platform,
                    capabilities_json, identity_public_key, encryption_public_key,
                    consent_policy_version, consent_host_owner, consent_exit_ip,
                    consent_accepted_at, created_at, updated_at
                 ) VALUES (?1, ?2, 'node', 'active', '0.1.0', 'macos-arm64',
                    '[]', ?3, ?4, 'v1', 1, 1, 1, 1, 1)",
                params![
                    node_id.to_string(),
                    network_id,
                    format!("identity-{node_id}"),
                    format!("encryption-{node_id}"),
                ],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO users(
                    network_id, user_id, display_name, status, credential_version,
                    created_at, updated_at, disabled_at, deleted_at
                 ) VALUES (?1, ?2, 'member', 'active', 1, 1, 1, NULL, NULL)",
                params![network_id, user_id.to_string()],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO user_node_assignments(
                    network_id, assignment_id, user_id, node_id, status,
                    created_at, updated_at, disabled_at, deleted_at
                 ) VALUES (?1, ?2, ?3, ?4, 'enabled', 1, 1, NULL, NULL)",
                params![
                    network_id,
                    uuid::Uuid::new_v4().to_string(),
                    user_id.to_string(),
                    node_id.to_string(),
                ],
            )
            .unwrap();
        (network_id, node_id, user_id)
    }

    fn traffic_batch(
        node_id: NodeId,
        user_id: UserId,
        first: i64,
        values: &[(i64, i64, i64)],
    ) -> TelemetryBatch {
        let events = values
            .iter()
            .enumerate()
            .map(
                |(offset, (bytes_up, bytes_down, connections))| TelemetryEvent {
                    sequence: SequenceNumber::new(first + i64::try_from(offset).unwrap()).unwrap(),
                    occurred_at: Timestamp::from_datetime(time::OffsetDateTime::now_utc()),
                    kind: TelemetryEventKind::TrafficDelta {
                        user_id,
                        bytes_up: Count::new(*bytes_up).unwrap(),
                        bytes_down: Count::new(*bytes_down).unwrap(),
                        connection_count: Count::new(*connections).unwrap(),
                    },
                },
            )
            .collect::<Vec<_>>();
        TelemetryBatch {
            schema_version: TELEMETRY_SCHEMA_VERSION,
            node_id,
            first_sequence: events.first().unwrap().sequence,
            last_sequence: events.last().unwrap().sequence,
            events,
        }
    }

    #[tokio::test]
    async fn telemetry_exact_retries_converge_and_overlap_or_gap_never_double_count() {
        let temp = TempDir::new().unwrap();
        let database = Database::open(&database_path(&temp), "Telemetry retry").unwrap();
        let (node_id, user_id) = {
            let guard = database.inner.lock().unwrap();
            let (_, node_id, user_id) = insert_telemetry_subjects(&guard.connection);
            (node_id, user_id)
        };
        let first = traffic_batch(node_id, user_id, 1, &[(10, 20, 1)]);
        let (left, right) = tokio::join!(
            database.ingest_telemetry(node_id, first.clone()),
            database.ingest_telemetry(node_id, first.clone())
        );
        assert_eq!(left.unwrap().acknowledged_sequence.get(), 1);
        assert_eq!(right.unwrap().acknowledged_sequence.get(), 1);

        let gap = traffic_batch(node_id, user_id, 3, &[(30, 40, 1)]);
        assert!(matches!(
            database.ingest_telemetry(node_id, gap).await,
            Err(DatabaseError::TelemetrySequenceGap { expected: 2 })
        ));
        let overlap = traffic_batch(node_id, user_id, 1, &[(10, 20, 1), (30, 40, 1)]);
        assert!(matches!(
            database.ingest_telemetry(node_id, overlap).await,
            Err(DatabaseError::TelemetrySequenceGap { expected: 2 })
        ));
        let second = traffic_batch(node_id, user_id, 2, &[(30, 40, 1)]);
        assert_eq!(
            database
                .ingest_telemetry(node_id, second)
                .await
                .unwrap()
                .acknowledged_sequence
                .get(),
            2
        );
        assert_eq!(
            database
                .ingest_telemetry(node_id, first)
                .await
                .unwrap()
                .acknowledged_sequence
                .get(),
            2
        );

        let guard = database.inner.lock().unwrap();
        let totals: (i64, i64, i64) = guard
            .connection
            .query_row(
                "SELECT SUM(bytes_up), SUM(bytes_down), SUM(connection_count)
             FROM traffic_hourly_aggregates WHERE node_id = ?1 AND user_id = ?2",
                params![node_id.to_string(), user_id.to_string()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert_eq!(totals, (40, 60, 2));
        let stored_events: i64 = guard
            .connection
            .query_row(
                "SELECT COUNT(*) FROM node_telemetry_events WHERE node_id = ?1",
                [node_id.to_string()],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(stored_events, 2);
    }

    #[tokio::test]
    async fn two_node_telemetry_aggregates_reconcile_to_each_acknowledged_sequence() {
        let temp = TempDir::new().unwrap();
        let database = Database::open(&database_path(&temp), "Telemetry multi-node").unwrap();
        let (network_id, first_node, user_id, second_node) = {
            let guard = database.inner.lock().unwrap();
            let (network_id, first_node, user_id) = insert_telemetry_subjects(&guard.connection);
            let second_node = NodeId::new();
            guard
                .connection
                .execute(
                    "INSERT INTO nodes(
                    node_id, network_id, display_name, status, agent_version, platform,
                    capabilities_json, identity_public_key, encryption_public_key,
                    consent_policy_version, consent_host_owner, consent_exit_ip,
                    consent_accepted_at, created_at, updated_at
                 ) VALUES (?1, ?2, 'node two', 'active', '0.1.0', 'macos-arm64',
                    '[]', ?3, ?4, 'v1', 1, 1, 1, 1, 1)",
                    params![
                        second_node.to_string(),
                        network_id,
                        format!("identity-{second_node}"),
                        format!("encryption-{second_node}")
                    ],
                )
                .unwrap();
            guard
                .connection
                .execute(
                    "INSERT INTO user_node_assignments(
                    network_id, assignment_id, user_id, node_id, status,
                    created_at, updated_at, disabled_at, deleted_at
                 ) VALUES (?1, ?2, ?3, ?4, 'enabled', 1, 1, NULL, NULL)",
                    params![
                        network_id,
                        uuid::Uuid::new_v4().to_string(),
                        user_id.to_string(),
                        second_node.to_string()
                    ],
                )
                .unwrap();
            (network_id, first_node, user_id, second_node)
        };
        let first_batch = traffic_batch(first_node, user_id, 1, &[(10, 20, 1), (5, 7, 0)]);
        let second_batch = traffic_batch(second_node, user_id, 1, &[(100, 200, 3)]);
        let (first_ack, second_ack) = tokio::join!(
            database.ingest_telemetry(first_node, first_batch),
            database.ingest_telemetry(second_node, second_batch)
        );
        assert_eq!(first_ack.unwrap().acknowledged_sequence.get(), 2);
        assert_eq!(second_ack.unwrap().acknowledged_sequence.get(), 1);

        let guard = database.inner.lock().unwrap();
        let mut statement = guard
            .connection
            .prepare(
                "SELECT node_id, SUM(bytes_up), SUM(bytes_down), SUM(connection_count)
             FROM traffic_hourly_aggregates
             WHERE network_id = ?1 AND user_id = ?2 GROUP BY node_id ORDER BY node_id",
            )
            .unwrap();
        let rows = statement
            .query_map(params![network_id, user_id.to_string()], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?,
                ))
            })
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap();
        let expected = std::collections::BTreeMap::from([
            (first_node.to_string(), (15, 27, 1)),
            (second_node.to_string(), (100, 200, 3)),
        ]);
        let actual = rows
            .into_iter()
            .map(|(node, up, down, count)| (node, (up, down, count)))
            .collect::<std::collections::BTreeMap<_, _>>();
        assert_eq!(actual, expected);
        let cursor_sum: i64 = guard
            .connection
            .query_row(
                "SELECT SUM(acknowledged_sequence) FROM node_telemetry_cursors
             WHERE network_id = ?1 AND node_id IN (?2, ?3)",
                params![network_id, first_node.to_string(), second_node.to_string()],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(cursor_sum, 3);
    }

    #[test]
    fn disabled_detailed_policy_drops_fields_without_blocking_the_cursor() {
        let temp = TempDir::new().unwrap();
        let path = database_path(&temp);
        let database = Database::open(&path, "Friends").unwrap();
        let mut guard = database.inner.lock().unwrap();
        let (network_id, node_id, user_id) = insert_telemetry_subjects(&guard.connection);
        guard
            .connection
            .execute(
                "UPDATE telemetry_policy SET detailed_enabled = 1 WHERE singleton = 1",
                [],
            )
            .unwrap();
        let event = TelemetryEvent {
            sequence: SequenceNumber::new(1).unwrap(),
            occurred_at: Timestamp::from_datetime(time::OffsetDateTime::now_utc()),
            kind: TelemetryEventKind::Connection {
                user_id,
                protocol: NetworkProtocol::Tcp,
                destination_host: "sensitive.example".to_string(),
                destination_port: 443,
                client_identifier: Some("client-sensitive".to_string()),
            },
        };
        guard
            .connection
            .execute(
                "UPDATE telemetry_policy SET detailed_enabled = 0 WHERE singleton = 1",
                [],
            )
            .unwrap();
        let acknowledgement = ingest_telemetry(
            &mut guard.connection,
            node_id,
            &TelemetryBatch {
                schema_version: TELEMETRY_SCHEMA_VERSION,
                node_id,
                first_sequence: event.sequence,
                last_sequence: event.sequence,
                events: vec![event],
            },
        )
        .unwrap();
        assert_eq!(acknowledgement.acknowledged_sequence.get(), 1);
        let stored: (String, Option<String>, Option<i64>, Option<String>) = guard
            .connection
            .query_row(
                "SELECT disposition, destination_host, destination_port, client_identifier
                 FROM node_telemetry_events
                 WHERE network_id = ?1 AND node_id = ?2 AND sequence = 1",
                params![network_id, node_id.to_string()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .unwrap();
        assert_eq!(stored, ("droppedPolicy".to_string(), None, None, None));
    }

    #[test]
    fn retention_uses_strict_per_class_time_boundaries() {
        let temp = TempDir::new().unwrap();
        let path = database_path(&temp);
        let database = Database::open(&path, "Friends").unwrap();
        let mut guard = database.inner.lock().unwrap();
        let (network_id, node_id, user_id) = insert_telemetry_subjects(&guard.connection);
        let now = 2_000_000_000_i64;
        let hourly_cutoff = now - 90 * 86_400;
        for (sequence, received_at) in [(1, hourly_cutoff - 1), (2, hourly_cutoff)] {
            guard
                .connection
                .execute(
                    "INSERT INTO node_telemetry_events(
                    network_id, node_id, sequence, event_type, user_id,
                    occurred_at, received_at, event_sha256, disposition
                 ) VALUES (?1, ?2, ?3, 'trafficDelta', ?4, ?5, ?5, ?6, 'stored')",
                    params![
                        network_id,
                        node_id.to_string(),
                        sequence,
                        user_id.to_string(),
                        received_at,
                        [0_u8; 32].as_slice(),
                    ],
                )
                .unwrap();
        }
        for (table, seconds, cutoff) in [
            ("traffic_hourly_aggregates", 3_600_i64, hourly_cutoff),
            ("traffic_daily_aggregates", 86_400_i64, now - 365 * 86_400),
        ] {
            let aligned = cutoff - cutoff.rem_euclid(seconds);
            for bucket in [aligned - seconds, aligned] {
                guard
                    .connection
                    .execute(
                        &format!(
                            "INSERT INTO {table}(
                        network_id, user_id, node_id, bucket_start,
                        bytes_up, bytes_down, connection_count, updated_at
                     ) VALUES (?1, ?2, ?3, ?4, 1, 1, 1, ?5)"
                        ),
                        params![
                            network_id,
                            user_id.to_string(),
                            node_id.to_string(),
                            bucket,
                            now
                        ],
                    )
                    .unwrap();
            }
        }
        let result = enforce_telemetry_retention_at(&mut guard.connection, now).unwrap();
        assert_eq!(result.traffic_events_deleted, 1);
        assert_eq!(result.hourly_aggregates_deleted, 1);
        assert_eq!(result.daily_aggregates_deleted, 1);
        let retained_raw: i64 = guard
            .connection
            .query_row(
                "SELECT COUNT(*) FROM node_telemetry_events WHERE event_type = 'trafficDelta'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(retained_raw, 1);
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
