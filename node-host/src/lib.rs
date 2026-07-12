//! Persistent local foundation for the Reality Console node host.

mod activation;
mod admission;
mod background;
#[cfg(target_os = "macos")]
mod background_macos;
mod bootstrap;
mod controller_status;
mod enrollment;
mod local_api;
#[cfg(target_os = "macos")]
mod local_api_macos;
mod mapping;
mod operations;
mod policy;
mod relay;
mod router_protocol;
mod service;
mod setup_session;
mod sync;
mod system_setup;
#[cfg(target_os = "macos")]
mod system_setup_macos;
mod telemetry;
#[cfg(test)]
mod test_support;
mod xray;

pub use relay::{
    configure_relay, revoke_relay, RelayAssignmentFile, RelayAssignmentState,
    RelayAssignmentStatus, RelayRuntimeState,
};

use anyhow::{bail, Context, Result};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use control_protocol::crypto::{Ed25519PublicKey, Ed25519Signature, X25519PublicKey};
use control_protocol::id::{ControllerInstanceId, NodeId, NodeInvitationId, NodeKeyId, Timestamp};
use control_protocol::node::{EnrollNodeResponse, NodeAuthenticationMode, NodeHeartbeatStatus};
use ed25519_dalek::{Signer as _, SigningKey};
use fs2::FileExt;
use rand_core::{OsRng, RngCore as _};
use rusqlite::{params, Connection, OpenFlags, OptionalExtension as _, TransactionBehavior};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::fmt;
use std::fmt::Write as _;
use std::fs::{self, File, OpenOptions};
use std::io::Write as _;
use std::net::IpAddr;
use std::path::{Component, Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use url::Url;
use x25519_dalek::{PublicKey as X25519DalekPublicKey, StaticSecret};
use zeroize::Zeroize as _;

const DATABASE_FILE: &str = "node-host.sqlite3";
const LOCK_FILE: &str = "node-host.lock";
const ED25519_SEED_FILE: &str = "identity.ed25519.seed";
const X25519_SEED_FILE: &str = "identity.x25519.seed";
const REALITY_X25519_SEED_FILE: &str = "reality.x25519.seed";
const SEED_LENGTH: usize = 32;
const CURRENT_SCHEMA_VERSION: i64 = 17;
const APPLICATION_ID: i64 = 0x4E48_4F53;
const MIGRATION_1_NAME: &str = "node_host_foundation";
const MIGRATION_2_NAME: &str = "node_enrollment_metadata";
const MIGRATION_3_NAME: &str = "node_control_sync_state";
const MIGRATION_4_NAME: &str = "node_desired_state_receipt";
const MIGRATION_5_NAME: &str = "node_xray_runtime_configuration";
const MIGRATION_6_NAME: &str = "node_rendered_xray_configs";
const MIGRATION_7_NAME: &str = "node_xray_activation_state";
const MIGRATION_8_NAME: &str = "node_heartbeat_generation";
const MIGRATION_9_NAME: &str = "node_router_mapping_state";
const MIGRATION_10_NAME: &str = "node_router_mapping_supervision";
const MIGRATION_11_NAME: &str = "verified_controller_status";
const MIGRATION_12_NAME: &str = "provider_consent_receipt";
const MIGRATION_13_NAME: &str = "bounded_telemetry_spool";
const MIGRATION_14_NAME: &str = "owner_managed_relay_assignment";
const MIGRATION_15_NAME: &str = "xray_traffic_collection";
const MIGRATION_16_NAME: &str = "provider_local_policy";
const MIGRATION_17_NAME: &str = "installation_identity_binding";

const MIGRATION_1: &str = "
    CREATE TABLE host_config (
        singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
        controller_url TEXT NOT NULL
    ) STRICT;
";

const MIGRATION_2: &str = "
    CREATE TABLE enrollment_registration (
        singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
        invitation_id TEXT NOT NULL UNIQUE,
        network_id TEXT NOT NULL,
        node_id TEXT NOT NULL UNIQUE,
        controller_instance_id TEXT NOT NULL,
        controller_fingerprint TEXT NOT NULL,
        controller_signing_public_key TEXT NOT NULL,
        credential_key_id TEXT NOT NULL,
        credential_mode TEXT NOT NULL,
        credential_expires_at TEXT NOT NULL,
        enrolled_at INTEGER NOT NULL
    ) STRICT;
";

const MIGRATION_3: &str = "
    CREATE TABLE control_sync_state (
        singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
        last_heartbeat_at INTEGER,
        last_sync_at INTEGER,
        desired_revision_cursor INTEGER NOT NULL DEFAULT 0
            CHECK (desired_revision_cursor >= 0)
    ) STRICT;

    INSERT INTO control_sync_state(singleton, desired_revision_cursor)
    VALUES (1, 0);
";

const MIGRATION_4: &str = "
    CREATE TABLE desired_state_artifacts (
        revision INTEGER PRIMARY KEY CHECK (revision > 0),
        network_id TEXT NOT NULL,
        node_id TEXT NOT NULL,
        controller_instance_id TEXT NOT NULL,
        signing_key_id TEXT NOT NULL,
        envelope_json TEXT NOT NULL CHECK (json_valid(envelope_json)),
        envelope_digest TEXT NOT NULL CHECK (length(envelope_digest) = 71),
        transcript_digest TEXT NOT NULL CHECK (length(transcript_digest) = 71),
        received_at INTEGER NOT NULL
    ) STRICT;

    CREATE TABLE local_revision_results (
        revision INTEGER NOT NULL REFERENCES desired_state_artifacts(revision) ON DELETE RESTRICT,
        state TEXT NOT NULL CHECK (
            state IN ('received', 'validated', 'applied', 'rejected', 'rolledBack')
        ),
        report_json TEXT NOT NULL CHECK (json_valid(report_json)),
        report_digest TEXT NOT NULL CHECK (length(report_digest) = 71),
        reported_at INTEGER,
        created_at INTEGER NOT NULL,
        PRIMARY KEY(revision, state)
    ) STRICT;

    CREATE INDEX local_revision_results_unreported
        ON local_revision_results(revision, state) WHERE reported_at IS NULL;

    CREATE TRIGGER desired_state_artifacts_no_update
    BEFORE UPDATE ON desired_state_artifacts
    BEGIN
        SELECT RAISE(ABORT, 'desired-state artifacts are immutable');
    END;

    CREATE TRIGGER desired_state_artifacts_no_delete
    BEFORE DELETE ON desired_state_artifacts
    BEGIN
        SELECT RAISE(ABORT, 'desired-state artifacts are immutable');
    END;

    CREATE TRIGGER local_revision_result_payload_no_update
    BEFORE UPDATE OF report_json, report_digest, revision, state, created_at
    ON local_revision_results
    BEGIN
        SELECT RAISE(ABORT, 'revision result payloads are immutable');
    END;

    CREATE TRIGGER local_revision_results_no_delete
    BEFORE DELETE ON local_revision_results
    BEGIN
        SELECT RAISE(ABORT, 'revision results are append-only');
    END;
";

const MIGRATION_5: &str = "
    CREATE TABLE xray_runtime_config (
        singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
        binary_path TEXT NOT NULL CHECK (length(binary_path) BETWEEN 1 AND 4096),
        expected_sha256 TEXT NOT NULL CHECK (
            length(expected_sha256) = 64
            AND expected_sha256 NOT GLOB '*[^0-9a-f]*'
        ),
        version TEXT NOT NULL CHECK (length(version) BETWEEN 1 AND 256),
        configured_at INTEGER NOT NULL,
        updated_at INTEGER NOT NULL
    ) STRICT;
";

const MIGRATION_6: &str = "
    CREATE TABLE rendered_xray_configs (
        revision INTEGER PRIMARY KEY
            REFERENCES desired_state_artifacts(revision) ON DELETE RESTRICT,
        relative_path TEXT NOT NULL CHECK (length(relative_path) BETWEEN 1 AND 4096),
        config_digest TEXT NOT NULL CHECK (
            length(config_digest) = 71
            AND substr(config_digest, 1, 7) = 'sha256:'
            AND substr(config_digest, 8) NOT GLOB '*[^0-9a-f]*'
        ),
        binary_digest TEXT NOT NULL CHECK (
            length(binary_digest) = 64
            AND binary_digest NOT GLOB '*[^0-9a-f]*'
        ),
        validated_at INTEGER NOT NULL
    ) STRICT;

    CREATE TRIGGER rendered_xray_configs_no_update
    BEFORE UPDATE ON rendered_xray_configs
    BEGIN
        SELECT RAISE(ABORT, 'rendered Xray configs are immutable');
    END;

    CREATE TRIGGER rendered_xray_configs_no_delete
    BEFORE DELETE ON rendered_xray_configs
    BEGIN
        SELECT RAISE(ABORT, 'rendered Xray configs are immutable');
    END;
";

const MIGRATION_7: &str = "
    CREATE TABLE xray_active_state (
        singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
        applied_revision INTEGER
            REFERENCES rendered_xray_configs(revision) ON DELETE RESTRICT,
        config_digest TEXT,
        binary_digest TEXT,
        generation INTEGER NOT NULL DEFAULT 0 CHECK (generation >= 0),
        restart_count INTEGER NOT NULL DEFAULT 0 CHECK (restart_count >= 0),
        applied_at INTEGER,
        updated_at INTEGER NOT NULL,
        CHECK (
            (applied_revision IS NULL
                AND config_digest IS NULL
                AND binary_digest IS NULL
                AND applied_at IS NULL)
            OR
            (applied_revision IS NOT NULL
                AND length(config_digest) = 71
                AND substr(config_digest, 1, 7) = 'sha256:'
                AND substr(config_digest, 8) NOT GLOB '*[^0-9a-f]*'
                AND length(binary_digest) = 64
                AND binary_digest NOT GLOB '*[^0-9a-f]*'
                AND applied_at IS NOT NULL)
        )
    ) STRICT;

    INSERT INTO xray_active_state(
        singleton, generation, restart_count, updated_at
    ) VALUES (1, 0, 0, 0);

    CREATE TABLE xray_activation_journal (
        revision INTEGER PRIMARY KEY
            REFERENCES rendered_xray_configs(revision) ON DELETE RESTRICT,
        previous_revision INTEGER
            REFERENCES rendered_xray_configs(revision) ON DELETE RESTRICT,
        phase TEXT NOT NULL CHECK (
            phase IN (
                'activating', 'stabilizing', 'retryPending', 'applied',
                'rollingBack', 'rolledBack', 'rejected', 'recoveryRequired'
            )
        ),
        attempt_count INTEGER NOT NULL CHECK (attempt_count > 0),
        started_at INTEGER NOT NULL,
        updated_at INTEGER NOT NULL,
        completed_at INTEGER,
        error_code TEXT CHECK (error_code IS NULL OR length(error_code) BETWEEN 1 AND 128),
        CHECK (previous_revision IS NULL OR previous_revision < revision),
        CHECK (
            (phase IN ('applied', 'rolledBack', 'rejected', 'recoveryRequired')
                AND completed_at IS NOT NULL)
            OR
            (phase NOT IN ('applied', 'rolledBack', 'rejected', 'recoveryRequired')
                AND completed_at IS NULL)
        )
    ) STRICT;

    CREATE TRIGGER xray_activation_journal_identity_no_update
    BEFORE UPDATE OF revision, previous_revision, started_at
    ON xray_activation_journal
    BEGIN
        SELECT RAISE(ABORT, 'Xray activation journal identity is immutable');
    END;

    CREATE TRIGGER xray_activation_journal_no_delete
    BEFORE DELETE ON xray_activation_journal
    BEGIN
        SELECT RAISE(ABORT, 'Xray activation journal is retained for recovery');
    END;
";

const MIGRATION_8: &str = "
    ALTER TABLE control_sync_state
    ADD COLUMN heartbeat_generation INTEGER NOT NULL DEFAULT 0
        CHECK (heartbeat_generation >= 0);
";

const MIGRATION_9: &str = "
    CREATE TABLE provider_network_policy (
        singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
        automatic_router_mapping_enabled INTEGER NOT NULL DEFAULT 0
            CHECK (automatic_router_mapping_enabled IN (0, 1)),
        router_mapping_consented_at INTEGER,
        allow_permanent_upnp INTEGER NOT NULL DEFAULT 0
            CHECK (allow_permanent_upnp IN (0, 1)),
        updated_at INTEGER NOT NULL,
        CHECK (
            automatic_router_mapping_enabled = 0
            OR router_mapping_consented_at IS NOT NULL
        ),
        CHECK (
            allow_permanent_upnp = 0
            OR router_mapping_consented_at IS NOT NULL
        )
    ) STRICT;

    INSERT INTO provider_network_policy(
        singleton, automatic_router_mapping_enabled, allow_permanent_upnp, updated_at
    ) VALUES (1, 0, 0, 0);

    CREATE TABLE router_mapping_leases (
        mapping_id TEXT PRIMARY KEY CHECK (length(mapping_id) = 36),
        endpoint_id TEXT NOT NULL UNIQUE CHECK (length(endpoint_id) = 36),
        applied_revision INTEGER NOT NULL
            REFERENCES rendered_xray_configs(revision) ON DELETE RESTRICT,
        source TEXT NOT NULL CHECK (source IN ('pcp', 'natPmp', 'upnp')),
        gateway_address TEXT NOT NULL CHECK (length(gateway_address) BETWEEN 1 AND 64),
        internal_address TEXT NOT NULL CHECK (length(internal_address) BETWEEN 1 AND 64),
        internal_port INTEGER NOT NULL CHECK (internal_port BETWEEN 1 AND 65535),
        external_address TEXT NOT NULL CHECK (length(external_address) BETWEEN 1 AND 253),
        external_port INTEGER NOT NULL CHECK (external_port BETWEEN 1 AND 65535),
        pcp_nonce BLOB CHECK (pcp_nonce IS NULL OR length(pcp_nonce) = 12),
        upnp_description TEXT
            CHECK (upnp_description IS NULL OR length(upnp_description) BETWEEN 1 AND 64),
        gateway_epoch INTEGER CHECK (gateway_epoch IS NULL OR gateway_epoch >= 0),
        lease_started_at INTEGER NOT NULL,
        lease_expires_at INTEGER NOT NULL,
        state TEXT NOT NULL CHECK (
            state IN ('active', 'releasing', 'released', 'failed', 'abandoned')
        ),
        failure_code TEXT CHECK (failure_code IS NULL OR length(failure_code) BETWEEN 1 AND 64),
        ended_at INTEGER,
        created_at INTEGER NOT NULL,
        updated_at INTEGER NOT NULL,
        CHECK (lease_expires_at > lease_started_at),
        CHECK (
            (source = 'pcp' AND pcp_nonce IS NOT NULL AND upnp_description IS NULL)
            OR (source = 'natPmp' AND pcp_nonce IS NULL AND upnp_description IS NULL)
            OR (source = 'upnp' AND pcp_nonce IS NULL AND upnp_description IS NOT NULL)
        ),
        CHECK (
            (state IN ('active', 'releasing') AND ended_at IS NULL)
            OR (state IN ('released', 'failed', 'abandoned') AND ended_at IS NOT NULL)
        ),
        CHECK (state != 'active' OR failure_code IS NULL),
        CHECK (ended_at IS NULL OR ended_at >= lease_started_at),
        CHECK (updated_at >= created_at)
    ) STRICT;

    CREATE UNIQUE INDEX router_mapping_leases_owned_current
        ON router_mapping_leases ((1))
        WHERE state IN ('active', 'releasing');

    CREATE INDEX router_mapping_leases_revision_state
        ON router_mapping_leases(applied_revision, state, lease_expires_at DESC);
";

const MIGRATION_10: &str = "
    ALTER TABLE router_mapping_leases
    ADD COLUMN topology_fingerprint BLOB
        CHECK (topology_fingerprint IS NULL OR length(topology_fingerprint) = 32);

    ALTER TABLE provider_network_policy
    ADD COLUMN last_mapping_error_code TEXT
        CHECK (
            last_mapping_error_code IS NULL
            OR length(last_mapping_error_code) BETWEEN 1 AND 64
        );

    ALTER TABLE provider_network_policy
    ADD COLUMN last_mapping_attempt_at INTEGER;
";

const MIGRATION_11: &str = "
    CREATE TABLE controller_status_state (
        singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
        schema_version INTEGER NOT NULL CHECK (schema_version = 1),
        heartbeat_generation INTEGER NOT NULL CHECK (heartbeat_generation > 0),
        node_id TEXT NOT NULL CHECK (length(node_id) = 36),
        controller_instance_id TEXT NOT NULL CHECK (length(controller_instance_id) = 36),
        signing_key_id TEXT NOT NULL CHECK (length(signing_key_id) = 36),
        observed_at TEXT NOT NULL CHECK (length(observed_at) BETWEEN 20 AND 64),
        envelope_json TEXT NOT NULL CHECK (
            json_valid(envelope_json) AND length(envelope_json) BETWEEN 2 AND 65536
        ),
        envelope_digest TEXT NOT NULL CHECK (
            length(envelope_digest) = 71
            AND substr(envelope_digest, 1, 7) = 'sha256:'
            AND substr(envelope_digest, 8) NOT GLOB '*[^0-9a-f]*'
        ),
        transcript_digest TEXT NOT NULL CHECK (
            length(transcript_digest) = 71
            AND substr(transcript_digest, 1, 7) = 'sha256:'
            AND substr(transcript_digest, 8) NOT GLOB '*[^0-9a-f]*'
        ),
        received_at INTEGER NOT NULL
    ) STRICT;

    CREATE TRIGGER controller_status_generation_no_regression
    BEFORE UPDATE ON controller_status_state
    WHEN NEW.singleton != OLD.singleton
        OR NEW.heartbeat_generation < OLD.heartbeat_generation
    BEGIN
        SELECT RAISE(ABORT, 'controller status generation cannot regress');
    END;

    CREATE TRIGGER controller_status_state_no_delete
    BEFORE DELETE ON controller_status_state
    BEGIN
        SELECT RAISE(ABORT, 'verified controller status is retained');
    END;
";

const MIGRATION_12: &str = "
    CREATE TABLE provider_consent_receipt (
        singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
        invitation_id TEXT NOT NULL CHECK (length(invitation_id) = 36),
        policy_version TEXT NOT NULL CHECK (length(policy_version) BETWEEN 1 AND 64),
        host_owner_consented INTEGER NOT NULL CHECK (host_owner_consented = 1),
        exit_ip_disclosure_accepted INTEGER NOT NULL CHECK (exit_ip_disclosure_accepted = 1),
        router_mapping_accepted INTEGER NOT NULL CHECK (router_mapping_accepted IN (0, 1)),
        accepted_at INTEGER NOT NULL
    ) STRICT;
";

const MIGRATION_13: &str = "
    CREATE TABLE telemetry_spool_state (
        singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
        next_sequence INTEGER NOT NULL CHECK(next_sequence > 0),
        acknowledged_sequence INTEGER NOT NULL CHECK(acknowledged_sequence >= 0),
        updated_at INTEGER NOT NULL
    ) STRICT;
    INSERT INTO telemetry_spool_state(
        singleton, next_sequence, acknowledged_sequence, updated_at
    ) VALUES (1, 1, 0, 0);

    CREATE TABLE telemetry_spool (
        sequence INTEGER PRIMARY KEY CHECK(sequence > 0),
        event_type TEXT NOT NULL CHECK(event_type IN (
            'trafficDelta', 'connection', 'collectionStatus', 'quotaState'
        )),
        event_json TEXT NOT NULL CHECK(
            json_valid(event_json) AND length(event_json) BETWEEN 2 AND 16384
        ),
        event_sha256 TEXT NOT NULL CHECK(
            length(event_sha256) = 71
            AND substr(event_sha256, 1, 7) = 'sha256:'
            AND substr(event_sha256, 8) NOT GLOB '*[^0-9a-f]*'
        ),
        occurred_at INTEGER NOT NULL,
        created_at INTEGER NOT NULL,
        acknowledged_at INTEGER,
        CHECK(acknowledged_at IS NULL OR acknowledged_at >= created_at)
    ) STRICT;
    CREATE INDEX telemetry_spool_unacknowledged
        ON telemetry_spool(sequence) WHERE acknowledged_at IS NULL;
    CREATE INDEX telemetry_spool_retention
        ON telemetry_spool(acknowledged_at) WHERE acknowledged_at IS NOT NULL;

    CREATE TRIGGER telemetry_spool_payload_no_update
    BEFORE UPDATE OF sequence, event_type, event_json, event_sha256, occurred_at, created_at
    ON telemetry_spool
    BEGIN
        SELECT RAISE(ABORT, 'telemetry spool payloads are immutable');
    END;
    CREATE TRIGGER telemetry_spool_no_unacknowledged_delete
    BEFORE DELETE ON telemetry_spool WHEN OLD.acknowledged_at IS NULL
    BEGIN
        SELECT RAISE(ABORT, 'unacknowledged telemetry cannot be deleted');
    END;
";

const MIGRATION_14: &str = "
    CREATE TABLE relay_provider_consent (
        singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
        policy_version TEXT NOT NULL CHECK(length(policy_version) BETWEEN 1 AND 64),
        accepted_at INTEGER NOT NULL
    ) STRICT;

    CREATE TABLE relay_assignment (
        singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
        state TEXT NOT NULL CHECK(state IN ('active', 'revoked')),
        endpoint_id TEXT NOT NULL CHECK(length(endpoint_id) = 36),
        route_id TEXT NOT NULL CHECK(length(route_id) BETWEEN 16 AND 128),
        relay_address TEXT NOT NULL CHECK(length(relay_address) BETWEEN 3 AND 64),
        relay_server_name TEXT NOT NULL CHECK(length(relay_server_name) BETWEEN 1 AND 253),
        public_address TEXT NOT NULL CHECK(length(public_address) BETWEEN 1 AND 253),
        public_port INTEGER NOT NULL CHECK(public_port BETWEEN 1 AND 65535),
        expires_at INTEGER NOT NULL,
        material_generation TEXT CHECK(
            material_generation IS NULL OR length(material_generation) = 36
        ),
        material_digest TEXT CHECK(
            material_digest IS NULL OR (
                length(material_digest) = 71
                AND substr(material_digest, 1, 7) = 'sha256:'
                AND substr(material_digest, 8) NOT GLOB '*[^0-9a-f]*'
            )
        ),
        installed_at INTEGER NOT NULL,
        updated_at INTEGER NOT NULL,
        revoked_at INTEGER,
        CHECK(
            (state = 'active' AND material_generation IS NOT NULL
                AND material_digest IS NOT NULL AND revoked_at IS NULL)
            OR
            (state = 'revoked' AND material_generation IS NULL
                AND material_digest IS NULL AND revoked_at IS NOT NULL)
        ),
        CHECK(updated_at >= installed_at),
        CHECK(revoked_at IS NULL OR revoked_at >= installed_at)
    ) STRICT;
";

const MIGRATION_15: &str = "
    ALTER TABLE xray_runtime_config
    ADD COLUMN stats_api_port INTEGER CHECK(stats_api_port BETWEEN 1 AND 65535);

    CREATE TABLE xray_traffic_collection_state (
        singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
        runtime_generation INTEGER CHECK(runtime_generation IS NULL OR runtime_generation > 0),
        last_status_code TEXT CHECK(
            last_status_code IS NULL OR length(last_status_code) BETWEEN 1 AND 64
        ),
        updated_at INTEGER NOT NULL
    ) STRICT;
    INSERT INTO xray_traffic_collection_state(
        singleton, runtime_generation, last_status_code, updated_at
    ) VALUES (1, NULL, NULL, 0);

    CREATE TABLE xray_user_traffic_counters (
        user_id TEXT PRIMARY KEY CHECK(length(user_id) = 36),
        runtime_generation INTEGER NOT NULL CHECK(runtime_generation > 0),
        uplink_counter INTEGER NOT NULL CHECK(uplink_counter >= 0),
        downlink_counter INTEGER NOT NULL CHECK(downlink_counter >= 0),
        updated_at INTEGER NOT NULL
    ) STRICT;
";

const MIGRATION_16: &str = r#"
    CREATE TABLE provider_policy (
        singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
        schema_version INTEGER NOT NULL CHECK (schema_version = 1),
        policy_json TEXT NOT NULL CHECK (json_valid(policy_json)),
        generation INTEGER NOT NULL CHECK (generation > 0),
        updated_at INTEGER NOT NULL
    ) STRICT;

    INSERT INTO provider_policy(singleton, schema_version, policy_json, generation, updated_at)
    VALUES (
        1,
        1,
        '{"schemaVersion":1,"paused":false,"weeklySchedule":[],"monthlyTransferCapBytes":107374182400,"maxConcurrentSessions":16,"bandwidthLimitBps":20000000}',
        1,
        unixepoch()
    );

    CREATE TABLE provider_month_usage (
        singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
        utc_month TEXT NOT NULL CHECK (utc_month = '' OR length(utc_month) = 7),
        observed_bytes INTEGER NOT NULL CHECK (observed_bytes >= 0),
        clock_high_watermark INTEGER NOT NULL CHECK (clock_high_watermark >= 0),
        last_observed_at INTEGER,
        coverage TEXT NOT NULL CHECK (coverage = 'xrayObservedLowerBound')
    ) STRICT;

    INSERT INTO provider_month_usage(
        singleton, utc_month, observed_bytes, clock_high_watermark, last_observed_at, coverage
    ) VALUES (1, '', 0, 0, NULL, 'xrayObservedLowerBound');

    CREATE TABLE provider_manual_endpoint (
        singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
        endpoint_id TEXT NOT NULL CHECK (length(endpoint_id) = 36),
        address TEXT NOT NULL CHECK (length(address) BETWEEN 1 AND 253),
        public_port INTEGER NOT NULL CHECK (public_port BETWEEN 1 AND 65535),
        forwarded_local_port INTEGER NOT NULL CHECK (forwarded_local_port BETWEEN 1 AND 65535),
        applied_revision INTEGER NOT NULL REFERENCES desired_state_artifacts(revision) ON DELETE RESTRICT,
        observed_at INTEGER NOT NULL,
        expires_at INTEGER NOT NULL CHECK (expires_at > observed_at),
        configured_at INTEGER NOT NULL
    ) STRICT;

    CREATE TABLE provider_pending_traffic_delta (
        user_id TEXT PRIMARY KEY CHECK (length(user_id) = 36),
        bytes_up INTEGER NOT NULL CHECK (bytes_up >= 0),
        bytes_down INTEGER NOT NULL CHECK (bytes_down >= 0),
        observed_at INTEGER NOT NULL
    ) STRICT;
"#;

const MIGRATION_17: &str = "
    CREATE TABLE installation_identity_binding (
        singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
        identity_path TEXT NOT NULL UNIQUE CHECK (length(identity_path) BETWEEN 1 AND 4096),
        public_fingerprint TEXT NOT NULL UNIQUE CHECK (
            length(public_fingerprint) = 71
            AND substr(public_fingerprint, 1, 7) = 'sha256:'
            AND substr(public_fingerprint, 8) NOT GLOB '*[^0-9a-f]*'
        ),
        bound_at INTEGER NOT NULL
    ) STRICT;

    CREATE TRIGGER installation_identity_binding_no_update
    BEFORE UPDATE ON installation_identity_binding
    BEGIN
        SELECT RAISE(ABORT, 'installation identity binding is immutable');
    END;
";

pub use admission::AdmissionCounters;
pub use background::{
    install_user_service, remove_user_service, user_service_status, BackgroundServiceStatus,
    UserServiceInstallRequest, USER_SERVICE_LABEL,
};
pub use bootstrap::{
    bootstrap, bootstrap_and_install_user_service, bootstrap_with_identity_dir, inspect_setup_code,
    BootstrapRequest, BootstrapServiceOutcome, NodeSetupPreview,
};
pub use enrollment::join;
pub use local_api::{
    query_local_service_status, query_node_setup_status, LocalServiceError, LocalServiceErrorCode,
    LocalServicePhase, LocalServiceStatus, NodeSetupPhase, NodeSetupStatus,
};
pub use mapping::{RouterMappingState, RouterMappingStatus};
pub use operations::{support_bundle, uninstall_local};
pub use policy::{
    clear_manual_endpoint, configure_manual_endpoint, configure_provider_policy, pause_provider,
    provider_policy_status, resume_provider, ManualEndpointInput, ManualEndpointStatus,
    ProviderAvailability, ProviderMonthUsage, ProviderPolicy, ProviderPolicyStatus,
    WeeklyScheduleWindow, PROVIDER_POLICY_SCHEMA_VERSION,
};
pub use service::{run, run_until, SyncLoopOptions};
pub use setup_session::{
    NodeSetupInstallRequest, NodeSetupSession, NodeSetupSessionStore, PendingNodeSetup,
};
pub use sync::sync_once;
pub use system_setup::{
    provider_relay_consent, ProtocolVerification, RelayConnectionState, SetupInvitation,
    SystemServicePhase, SystemServiceStatus, SystemSetupError, SystemSetupErrorCode,
    SystemSetupOperation, SystemSetupOutcome, SystemSetupRequest, SystemSetupResponse,
    SystemSetupResult,
};
#[cfg(target_os = "macos")]
pub use system_setup_macos::{
    migrate_system_layout_binding, run_system_service, SystemServiceClient, SystemServicePaths,
    SYSTEM_CURRENT_PATH, SYSTEM_IDENTITY_PATH, SYSTEM_RELEASES_PATH, SYSTEM_SERVICE_ACCOUNT,
    SYSTEM_SERVICE_STATE_ROOT_PATH, SYSTEM_SIDECAR_MANIFEST, SYSTEM_SOCKET_PATH, SYSTEM_STATE_PATH,
};
pub use telemetry::record_telemetry_event;
pub use xray::configure_xray;

/// Safe enrollment state rendered by the CLI.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum EnrollmentState {
    /// The local identity has not completed controller enrollment.
    NotEnrolled,
    /// A controller response was cryptographically verified and persisted.
    Enrolled,
}

impl fmt::Display for EnrollmentState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotEnrolled => formatter.write_str("not-enrolled"),
            Self::Enrolled => formatter.write_str("enrolled"),
        }
    }
}

/// Public, non-secret state suitable for CLI output and logs.
#[derive(Debug, Serialize)]
pub struct HostStatus {
    /// Configured controller origin.
    pub controller: Url,
    /// Public request-signing identity.
    pub identity_public_key: Ed25519PublicKey,
    /// Public recipient-encryption identity.
    pub encryption_public_key: X25519PublicKey,
    /// Applied database schema version.
    pub schema_version: i64,
    /// Whether a verified controller enrollment is persisted.
    pub enrollment_state: EnrollmentState,
    /// Controller-assigned node identity, when enrolled.
    pub node_id: Option<NodeId>,
    /// Expiry of the active node authentication credential, when enrolled.
    pub credential_expires_at: Option<Timestamp>,
    /// Last heartbeat durably acknowledged by the controller.
    pub last_heartbeat_at: Option<Timestamp>,
    /// Latest controller-signed lifecycle and endpoint-readiness snapshot.
    pub controller_status: Option<NodeHeartbeatStatus>,
    /// Last complete heartbeat and desired-state synchronization cycle.
    pub last_sync_at: Option<Timestamp>,
    /// Highest desired-state revision durably accepted by this host.
    pub desired_revision_cursor: i64,
    /// Last revision that passed local startup and health checks.
    pub applied_revision: Option<control_protocol::id::Revision>,
    /// Most recent activation-journal phase, when any attempt exists.
    pub xray_activation_phase: Option<String>,
    /// Whether an installer-provided, checksum-pinned Xray runtime is configured.
    pub xray_configured: bool,
    /// Explicit validated Xray binary path, when configured.
    pub xray_binary_path: Option<PathBuf>,
    /// Trusted lowercase SHA-256 of the configured Xray binary.
    pub xray_expected_sha256: Option<String>,
    /// Safe first line returned by the bounded Xray version probe.
    pub xray_version: Option<String>,
    /// Public REALITY key derived from the node-local private identity.
    pub reality_public_key: Option<X25519PublicKey>,
    /// Stable node-local REALITY short ID.
    pub reality_short_id: Option<String>,
    /// Provider-owned automatic router-mapping preference and safe current state.
    pub router_mapping: RouterMappingStatus,
    /// Controller-assigned relay metadata without credential material.
    pub relay: RelayAssignmentStatus,
    /// Provider-local hard limits and redacted reachability/usage state.
    pub provider_policy: ProviderPolicyStatus,
}

/// A seed whose formatting can never reveal its bytes.
struct SecretSeed([u8; SEED_LENGTH]);

impl fmt::Debug for SecretSeed {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("[redacted]")
    }
}

impl Drop for SecretSeed {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// Initializes a data directory, or verifies and reuses an existing one.
///
/// # Errors
///
/// Returns an error if the directory cannot be locked, persisted state is
/// invalid, migrations fail, or an existing controller differs.
pub fn initialize(data_dir: &Path, controller: &str) -> Result<HostStatus> {
    let identity_dir = default_installation_identity_dir(data_dir)?;
    initialize_with_identity_dir(data_dir, &identity_dir, controller)
}

/// Initializes a data directory with an explicit installation-owned identity
/// directory outside the copyable state tree.
///
/// Production callers must pass their fixed package path. This explicit form
/// also lets isolated development and tests inject a unique identity root.
///
/// # Errors
///
/// Returns an error if either path is unsafe, an immutable identity binding
/// already points elsewhere, identity material is missing or inconsistent, or
/// normal initialization fails.
pub fn initialize_with_identity_dir(
    data_dir: &Path,
    identity_dir: &Path,
    controller: &str,
) -> Result<HostStatus> {
    let controller = parse_controller(controller)?;
    let _lock = DataDirLock::acquire(data_dir, true)?;
    let mut connection = open_database(data_dir, true)?;
    migrate(&mut connection)?;
    configure_controller(&connection, &controller)?;
    let identity = Identity::load_or_create(&connection, data_dir, identity_dir)?;
    build_status(&connection, data_dir, controller, &identity)
}

/// Returns the default development identity directory next to, never inside,
/// the copyable state directory.
///
/// # Errors
///
/// Returns an error when the data directory has no safe absolute parent/name.
pub fn default_installation_identity_dir(data_dir: &Path) -> Result<PathBuf> {
    validate_absolute_path(data_dir, "node data directory")?;
    let parent = data_dir
        .parent()
        .context("node data directory has no parent")?;
    let name = data_dir
        .file_name()
        .and_then(|value| value.to_str())
        .context("node data directory name is invalid")?;
    if name.is_empty() || name == "." || name == ".." {
        bail!("node data directory name is invalid");
    }
    Ok(parent.join(format!(".{name}.installation-identity")))
}

/// Reads initialized state while holding the data-directory lock.
///
/// # Errors
///
/// Returns an error if the host is not initialized, cannot be exclusively
/// locked, or contains invalid state.
pub fn status(data_dir: &Path) -> Result<HostStatus> {
    let _lock = DataDirLock::acquire(data_dir, false)?;
    status_locked(data_dir)
}

fn status_locked(data_dir: &Path) -> Result<HostStatus> {
    let connection = open_database(data_dir, false)?;
    apply_pragmas(&connection)?;
    validate_migration_state(&connection)?;
    let controller_value: String = connection
        .query_row(
            "SELECT controller_url FROM host_config WHERE singleton = 1",
            [],
            |row| row.get(0),
        )
        .context("node host is not initialized")?;
    let controller = parse_controller(&controller_value)?;
    let identity = Identity::load(&connection, data_dir)?;
    build_status(&connection, data_dir, controller, &identity)
}

fn parse_controller(value: &str) -> Result<Url> {
    let url = Url::parse(value).context("controller must be an absolute URL")?;
    let host = url
        .host_str()
        .context("controller URL must include a host")?;
    let is_loopback = host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<IpAddr>()
            .is_ok_and(|address| address.is_loopback());
    if url.scheme() != "https" && !(url.scheme() == "http" && is_loopback) {
        bail!("controller must use https; http is allowed only for loopback development");
    }
    if !url.username().is_empty()
        || url.password().is_some()
        || !matches!(url.path(), "" | "/")
        || url.query().is_some()
        || url.fragment().is_some()
    {
        bail!("controller URL must be an origin without credentials, path, query, or fragment");
    }
    Url::parse(&url.origin().ascii_serialization()).context("controller origin is invalid")
}

fn open_database(data_dir: &Path, create: bool) -> Result<Connection> {
    let path = data_dir.join(DATABASE_FILE);
    let mut flags = OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX;
    if create {
        flags |= OpenFlags::SQLITE_OPEN_CREATE;
    }
    let connection = Connection::open_with_flags(&path, flags)
        .with_context(|| format!("failed to open {}", path.display()))?;
    set_owner_only(&path)?;
    apply_pragmas(&connection)?;
    validate_application_id(&connection)?;
    Ok(connection)
}

fn apply_pragmas(connection: &Connection) -> Result<()> {
    connection.busy_timeout(std::time::Duration::from_secs(5))?;
    connection.execute_batch(
        "PRAGMA foreign_keys = ON;
         PRAGMA journal_mode = WAL;
         PRAGMA synchronous = FULL;
         PRAGMA trusted_schema = OFF;
         PRAGMA secure_delete = FAST;",
    )?;
    Ok(())
}

fn migrate(connection: &mut Connection) -> Result<()> {
    connection.execute_batch(
        "CREATE TABLE IF NOT EXISTS schema_migrations (
            version INTEGER PRIMARY KEY,
            name TEXT NOT NULL UNIQUE,
            checksum TEXT NOT NULL,
            applied_at INTEGER NOT NULL
        ) STRICT;",
    )?;

    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    validate_migration_state(&transaction)?;
    apply_migration(&transaction, 1, MIGRATION_1_NAME, MIGRATION_1)?;
    apply_migration(&transaction, 2, MIGRATION_2_NAME, MIGRATION_2)?;
    apply_migration(&transaction, 3, MIGRATION_3_NAME, MIGRATION_3)?;
    apply_migration(&transaction, 4, MIGRATION_4_NAME, MIGRATION_4)?;
    apply_migration(&transaction, 5, MIGRATION_5_NAME, MIGRATION_5)?;
    apply_migration(&transaction, 6, MIGRATION_6_NAME, MIGRATION_6)?;
    apply_migration(&transaction, 7, MIGRATION_7_NAME, MIGRATION_7)?;
    apply_migration(&transaction, 8, MIGRATION_8_NAME, MIGRATION_8)?;
    apply_migration(&transaction, 9, MIGRATION_9_NAME, MIGRATION_9)?;
    apply_migration(&transaction, 10, MIGRATION_10_NAME, MIGRATION_10)?;
    apply_migration(&transaction, 11, MIGRATION_11_NAME, MIGRATION_11)?;
    apply_migration(&transaction, 12, MIGRATION_12_NAME, MIGRATION_12)?;
    apply_migration(&transaction, 13, MIGRATION_13_NAME, MIGRATION_13)?;
    apply_migration(&transaction, 14, MIGRATION_14_NAME, MIGRATION_14)?;
    apply_migration(&transaction, 15, MIGRATION_15_NAME, MIGRATION_15)?;
    apply_migration(&transaction, 16, MIGRATION_16_NAME, MIGRATION_16)?;
    apply_migration(&transaction, 17, MIGRATION_17_NAME, MIGRATION_17)?;
    transaction.commit()?;
    ensure_stats_api_port(connection)?;
    Ok(())
}

fn ensure_stats_api_port(connection: &Connection) -> Result<()> {
    let missing: bool = connection.query_row(
        "SELECT EXISTS(
            SELECT 1 FROM xray_runtime_config
            WHERE singleton = 1 AND stats_api_port IS NULL
         )",
        [],
        |row| row.get(0),
    )?;
    if !missing {
        return Ok(());
    }
    let listener = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
        .context("failed to reserve a loopback Xray Stats API port")?;
    let port = listener
        .local_addr()
        .context("failed to inspect the reserved Xray Stats API port")?
        .port();
    drop(listener);
    let changed = connection.execute(
        "UPDATE xray_runtime_config SET stats_api_port = ?1, updated_at = ?2
         WHERE singleton = 1 AND stats_api_port IS NULL",
        params![port, unix_timestamp()?],
    )?;
    if changed != 1 {
        bail!("Xray Stats API port allocation raced with another writer");
    }
    Ok(())
}

fn apply_migration(connection: &Connection, version: i64, name: &str, sql: &str) -> Result<()> {
    let applied: i64 = connection.query_row(
        "SELECT COUNT(*) FROM schema_migrations WHERE version = ?1",
        params![version],
        |row| row.get(0),
    )?;
    if applied == 0 {
        connection.execute_batch(sql)?;
        connection.execute(
            "INSERT INTO schema_migrations(version, name, checksum, applied_at)
             VALUES (?1, ?2, ?3, ?4)",
            params![
                version,
                name,
                migration_checksum(version, name, sql),
                unix_timestamp()?
            ],
        )?;
        connection.pragma_update(None, "user_version", version)?;
    }
    Ok(())
}

fn validate_application_id(connection: &Connection) -> Result<()> {
    let current: i64 = connection.query_row("PRAGMA application_id", [], |row| row.get(0))?;
    match current {
        0 => connection.pragma_update(None, "application_id", APPLICATION_ID)?,
        APPLICATION_ID => {}
        _ => bail!("database belongs to another application"),
    }
    Ok(())
}

fn validate_migration_state(connection: &Connection) -> Result<()> {
    let user_version: i64 = connection.query_row("PRAGMA user_version", [], |row| row.get(0))?;
    if user_version > CURRENT_SCHEMA_VERSION {
        bail!("database schema is newer than this node host supports");
    }
    let rows: Vec<(i64, String, String)> = {
        let mut statement = connection
            .prepare("SELECT version, name, checksum FROM schema_migrations ORDER BY version")?;
        let rows = statement
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))?
            .collect::<rusqlite::Result<_>>()?;
        rows
    };
    if rows.is_empty() {
        if user_version == 0 {
            return Ok(());
        }
        bail!("schema migration history does not match PRAGMA user_version");
    }

    let known = [
        (1, MIGRATION_1_NAME, MIGRATION_1),
        (2, MIGRATION_2_NAME, MIGRATION_2),
        (3, MIGRATION_3_NAME, MIGRATION_3),
        (4, MIGRATION_4_NAME, MIGRATION_4),
        (5, MIGRATION_5_NAME, MIGRATION_5),
        (6, MIGRATION_6_NAME, MIGRATION_6),
        (7, MIGRATION_7_NAME, MIGRATION_7),
        (8, MIGRATION_8_NAME, MIGRATION_8),
        (9, MIGRATION_9_NAME, MIGRATION_9),
        (10, MIGRATION_10_NAME, MIGRATION_10),
        (11, MIGRATION_11_NAME, MIGRATION_11),
        (12, MIGRATION_12_NAME, MIGRATION_12),
        (13, MIGRATION_13_NAME, MIGRATION_13),
        (14, MIGRATION_14_NAME, MIGRATION_14),
        (15, MIGRATION_15_NAME, MIGRATION_15),
        (16, MIGRATION_16_NAME, MIGRATION_16),
        (17, MIGRATION_17_NAME, MIGRATION_17),
    ];
    if rows.len() > known.len() {
        bail!("database schema is newer than this node host supports");
    }
    for ((version, name, checksum), (expected_version, expected_name, expected_sql)) in
        rows.iter().zip(known)
    {
        if *version != expected_version
            || name != expected_name
            || checksum != &migration_checksum(expected_version, expected_name, expected_sql)
        {
            bail!("schema migration history is invalid or has been modified");
        }
    }
    let last_version = rows.last().map_or(0, |row| row.0);
    if user_version != last_version {
        bail!("schema migration history does not match PRAGMA user_version");
    }
    Ok(())
}

fn migration_checksum(version: i64, name: &str, sql: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(version.to_be_bytes());
    hasher.update(name.as_bytes());
    hasher.update(sql.as_bytes());
    hasher
        .finalize()
        .iter()
        .fold(String::with_capacity(64), |mut output, byte| {
            write!(output, "{byte:02x}").expect("writing to a string cannot fail");
            output
        })
}

fn unix_timestamp() -> Result<i64> {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before the Unix epoch")?
        .as_secs();
    i64::try_from(seconds).context("current timestamp does not fit SQLite INTEGER")
}

fn configure_controller(connection: &Connection, controller: &Url) -> Result<()> {
    let existing = connection.query_row(
        "SELECT controller_url FROM host_config WHERE singleton = 1",
        [],
        |row| row.get::<_, String>(0),
    );
    match existing {
        Ok(existing) if existing == controller.as_str() => Ok(()),
        Ok(_) => bail!("node host is already initialized for a different controller"),
        Err(rusqlite::Error::QueryReturnedNoRows) => {
            connection.execute(
                "INSERT INTO host_config(singleton, controller_url) VALUES (1, ?1)",
                params![controller.as_str()],
            )?;
            Ok(())
        }
        Err(error) => Err(error.into()),
    }
}

fn build_status(
    connection: &Connection,
    data_dir: &Path,
    controller: Url,
    identity: &Identity,
) -> Result<HostStatus> {
    let schema_version = connection.query_row(
        "SELECT COALESCE(MAX(version), 0) FROM schema_migrations",
        [],
        |row| row.get(0),
    )?;
    let registration = load_registration_status(connection)?;
    let sync_status = load_sync_status(connection)?;
    let controller_status = controller_status::load_verified(connection)?;
    let activation_status = activation::load_activation_status(connection)?;
    let router_mapping = mapping::load_status(connection)?;
    let relay = relay::load_status(connection)?;
    let provider_policy = policy::load_status_readonly(connection)?;
    let xray_status = xray::load_xray_runtime_status(connection, data_dir)?;
    let (
        xray_binary_path,
        xray_expected_sha256,
        xray_version,
        reality_public_key,
        reality_short_id,
    ) = xray_status.map_or((None, None, None, None, None), |status| {
        (
            Some(status.binary_path),
            Some(status.expected_sha256),
            Some(status.version),
            Some(status.reality_public_key),
            Some(status.reality_short_id),
        )
    });
    Ok(HostStatus {
        controller,
        identity_public_key: identity.ed25519_public()?,
        encryption_public_key: identity.x25519_public()?,
        schema_version,
        enrollment_state: if registration.is_some() {
            EnrollmentState::Enrolled
        } else {
            EnrollmentState::NotEnrolled
        },
        node_id: registration.as_ref().map(|value| value.0),
        credential_expires_at: registration.map(|value| value.1),
        last_heartbeat_at: sync_status.last_heartbeat_at,
        controller_status,
        last_sync_at: sync_status.last_sync_at,
        desired_revision_cursor: sync_status.desired_revision_cursor,
        applied_revision: activation_status.applied_revision,
        xray_activation_phase: activation_status.latest_phase,
        xray_configured: xray_binary_path.is_some(),
        xray_binary_path,
        xray_expected_sha256,
        xray_version,
        reality_public_key,
        reality_short_id,
        router_mapping,
        relay,
        provider_policy,
    })
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct SyncStatus {
    last_heartbeat_at: Option<Timestamp>,
    last_sync_at: Option<Timestamp>,
    desired_revision_cursor: i64,
}

fn load_sync_status(connection: &Connection) -> Result<SyncStatus> {
    let has_table: i64 = connection.query_row(
        "SELECT COUNT(*) FROM sqlite_schema WHERE type = 'table' AND name = 'control_sync_state'",
        [],
        |row| row.get(0),
    )?;
    if has_table == 0 {
        return Ok(SyncStatus::default());
    }

    let stored = connection
        .query_row(
            "SELECT last_heartbeat_at, last_sync_at, desired_revision_cursor
             FROM control_sync_state WHERE singleton = 1",
            [],
            |row| {
                Ok((
                    row.get::<_, Option<i64>>(0)?,
                    row.get::<_, Option<i64>>(1)?,
                    row.get::<_, i64>(2)?,
                ))
            },
        )
        .context("control sync state is missing")?;
    Ok(SyncStatus {
        last_heartbeat_at: stored
            .0
            .map(timestamp_from_unix)
            .transpose()
            .context("stored heartbeat timestamp is invalid")?,
        last_sync_at: stored
            .1
            .map(timestamp_from_unix)
            .transpose()
            .context("stored sync timestamp is invalid")?,
        desired_revision_cursor: stored.2,
    })
}

fn timestamp_from_unix(value: i64) -> Result<Timestamp> {
    Ok(Timestamp::from_datetime(
        time::OffsetDateTime::from_unix_timestamp(value)?,
    ))
}

fn load_registration_status(connection: &Connection) -> Result<Option<(NodeId, Timestamp)>> {
    connection
        .query_row(
            "SELECT node_id, credential_expires_at
             FROM enrollment_registration WHERE singleton = 1",
            [],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
        )
        .optional()?
        .map(|(node_id, expires_at)| {
            Ok((
                node_id.parse().context("stored node ID is invalid")?,
                expires_at
                    .parse()
                    .context("stored credential expiry is invalid")?,
            ))
        })
        .transpose()
}

pub(crate) fn persist_verified_registration(
    connection: &mut Connection,
    invitation_id: NodeInvitationId,
    controller_fingerprint: &str,
    response: &EnrollNodeResponse,
) -> Result<()> {
    let expected =
        RegistrationRecord::from_verified_response(invitation_id, controller_fingerprint, response);
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let existing = load_registration(&transaction)?;
    match existing {
        Some(existing) if existing == expected => {}
        Some(_) => bail!("node host is already enrolled with different registration metadata"),
        None => {
            transaction.execute(
                "INSERT INTO enrollment_registration(
                    singleton, invitation_id, network_id, node_id, controller_instance_id,
                    controller_fingerprint, controller_signing_public_key, credential_key_id,
                    credential_mode, credential_expires_at, enrolled_at
                 ) VALUES (1, ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
                params![
                    expected.invitation_id,
                    expected.network_id,
                    expected.node_id,
                    expected.controller_instance_id,
                    expected.controller_fingerprint,
                    expected.controller_signing_public_key,
                    expected.credential_key_id,
                    expected.credential_mode,
                    expected.credential_expires_at,
                    unix_timestamp()?,
                ],
            )?;
        }
    }
    transaction.commit()?;
    Ok(())
}

#[derive(Debug, PartialEq, Eq)]
struct RegistrationRecord {
    invitation_id: String,
    network_id: String,
    node_id: String,
    controller_instance_id: String,
    controller_fingerprint: String,
    controller_signing_public_key: String,
    credential_key_id: String,
    credential_mode: String,
    credential_expires_at: String,
}

#[derive(Debug, Clone)]
struct SyncRegistration {
    network: control_protocol::id::NetworkId,
    node: NodeId,
    controller_instance: ControllerInstanceId,
    controller_signing_public_key: Ed25519PublicKey,
    key: NodeKeyId,
}

fn load_sync_registration(connection: &Connection) -> Result<SyncRegistration> {
    let registration = load_registration(connection)?.context("node host is not enrolled")?;
    if registration.credential_mode != "signedRequest" {
        bail!("node host credential mode is not supported for outbound sync");
    }
    let credential_expires_at: Timestamp = registration
        .credential_expires_at
        .parse()
        .context("stored credential expiry is invalid")?;
    if credential_expires_at.as_datetime() <= time::OffsetDateTime::now_utc() {
        bail!("node host credential has expired");
    }
    Ok(SyncRegistration {
        network: registration
            .network_id
            .parse()
            .context("stored network ID is invalid")?,
        node: registration
            .node_id
            .parse()
            .context("stored node ID is invalid")?,
        controller_instance: registration
            .controller_instance_id
            .parse()
            .context("stored controller instance ID is invalid")?,
        controller_signing_public_key: registration
            .controller_signing_public_key
            .parse()
            .context("stored controller signing public key is invalid")?,
        key: registration
            .credential_key_id
            .parse()
            .context("stored credential key ID is invalid")?,
    })
}

impl RegistrationRecord {
    fn from_verified_response(
        invitation_id: NodeInvitationId,
        controller_fingerprint: &str,
        response: &EnrollNodeResponse,
    ) -> Self {
        Self {
            invitation_id: invitation_id.to_string(),
            network_id: response.network_id.to_string(),
            node_id: response.node_id.to_string(),
            controller_instance_id: response.controller_instance_id.to_string(),
            controller_fingerprint: controller_fingerprint.to_string(),
            controller_signing_public_key: response
                .desired_state_signing_public_key
                .as_str()
                .to_string(),
            credential_key_id: response.credential.key_id.to_string(),
            credential_mode: authentication_mode_name(response.credential.mode).to_string(),
            credential_expires_at: response.credential.expires_at.to_string(),
        }
    }
}

fn load_registration(connection: &Connection) -> Result<Option<RegistrationRecord>> {
    connection
        .query_row(
            "SELECT invitation_id, network_id, node_id, controller_instance_id,
                    controller_fingerprint, controller_signing_public_key, credential_key_id,
                    credential_mode, credential_expires_at
             FROM enrollment_registration WHERE singleton = 1",
            [],
            |row| {
                Ok(RegistrationRecord {
                    invitation_id: row.get(0)?,
                    network_id: row.get(1)?,
                    node_id: row.get(2)?,
                    controller_instance_id: row.get(3)?,
                    controller_fingerprint: row.get(4)?,
                    controller_signing_public_key: row.get(5)?,
                    credential_key_id: row.get(6)?,
                    credential_mode: row.get(7)?,
                    credential_expires_at: row.get(8)?,
                })
            },
        )
        .optional()
        .map_err(Into::into)
}

fn authentication_mode_name(mode: NodeAuthenticationMode) -> &'static str {
    match mode {
        NodeAuthenticationMode::MutualTls => "mutualTls",
        NodeAuthenticationMode::SignedRequest => "signedRequest",
    }
}

struct Identity {
    signing: SecretSeed,
    encryption: SecretSeed,
}

impl Identity {
    fn load_or_create_default(connection: &Connection, data_dir: &Path) -> Result<Self> {
        if load_identity_binding(connection)?.is_some() {
            return Self::load(connection, data_dir);
        }
        let identity_dir = default_installation_identity_dir(data_dir)?;
        Self::load_or_create(connection, data_dir, &identity_dir)
    }

    fn load_or_create(
        connection: &Connection,
        data_dir: &Path,
        requested_identity_dir: &Path,
    ) -> Result<Self> {
        validate_identity_dir_path(data_dir, requested_identity_dir)?;
        if let Some((stored_path, fingerprint)) = load_identity_binding(connection)? {
            if stored_path != requested_identity_dir {
                bail!("installation identity is already bound to a different path");
            }
            return Self::load_bound(requested_identity_dir, &fingerprint);
        }
        prepare_identity_directory(requested_identity_dir)?;
        migrate_legacy_identity(data_dir, requested_identity_dir)?;
        let identity = Self {
            signing: load_or_create_seed(&requested_identity_dir.join(ED25519_SEED_FILE))?,
            encryption: load_or_create_seed(&requested_identity_dir.join(X25519_SEED_FILE))?,
        };
        bind_identity(connection, requested_identity_dir, &identity)?;
        Ok(identity)
    }

    fn load(connection: &Connection, data_dir: &Path) -> Result<Self> {
        if let Some((identity_dir, fingerprint)) = load_identity_binding(connection)? {
            validate_identity_dir_path(data_dir, &identity_dir)?;
            return Self::load_bound(&identity_dir, &fingerprint);
        }

        // Upgrade an initialized pre-binding installation without allowing a
        // missing identity to be silently recreated during ordinary reads.
        let identity_dir = default_installation_identity_dir(data_dir)?;
        validate_identity_dir_path(data_dir, &identity_dir)?;
        prepare_identity_directory(&identity_dir)?;
        migrate_legacy_identity(data_dir, &identity_dir)?;
        let identity = Self {
            signing: load_seed(&identity_dir.join(ED25519_SEED_FILE))?,
            encryption: load_seed(&identity_dir.join(X25519_SEED_FILE))?,
        };
        bind_identity(connection, &identity_dir, &identity)?;
        Ok(identity)
    }

    fn load_bound(identity_dir: &Path, expected_fingerprint: &str) -> Result<Self> {
        inspect_identity_directory(identity_dir)?;
        let identity = Self {
            signing: load_seed(&identity_dir.join(ED25519_SEED_FILE))?,
            encryption: load_seed(&identity_dir.join(X25519_SEED_FILE))?,
        };
        if identity.public_fingerprint()? != expected_fingerprint {
            bail!("installation identity fingerprint does not match its immutable binding");
        }
        Ok(identity)
    }

    fn ed25519_public(&self) -> Result<Ed25519PublicKey> {
        URL_SAFE_NO_PAD
            .encode(
                SigningKey::from_bytes(&self.signing.0)
                    .verifying_key()
                    .to_bytes(),
            )
            .parse()
            .context("generated invalid Ed25519 public key")
    }

    fn x25519_public(&self) -> Result<X25519PublicKey> {
        let secret = StaticSecret::from(self.encryption.0);
        URL_SAFE_NO_PAD
            .encode(X25519DalekPublicKey::from(&secret).to_bytes())
            .parse()
            .context("generated invalid X25519 public key")
    }

    fn sign(&self, message: &[u8]) -> Result<Ed25519Signature> {
        URL_SAFE_NO_PAD
            .encode(
                SigningKey::from_bytes(&self.signing.0)
                    .sign(message)
                    .to_bytes(),
            )
            .parse()
            .context("generated invalid Ed25519 signature")
    }

    fn public_fingerprint(&self) -> Result<String> {
        let signing = self.ed25519_public()?;
        let encryption = self.x25519_public()?;
        let mut digest = Sha256::new();
        digest.update(b"private-network-node-installation-identity-v1\0");
        digest.update(signing.as_str().as_bytes());
        digest.update([0]);
        digest.update(encryption.as_str().as_bytes());
        let mut fingerprint = String::from("sha256:");
        for byte in digest.finalize() {
            write!(&mut fingerprint, "{byte:02x}")?;
        }
        Ok(fingerprint)
    }
}

fn load_identity_binding(connection: &Connection) -> Result<Option<(PathBuf, String)>> {
    connection
        .query_row(
            "SELECT identity_path, public_fingerprint
             FROM installation_identity_binding WHERE singleton = 1",
            [],
            |row| Ok((PathBuf::from(row.get::<_, String>(0)?), row.get(1)?)),
        )
        .optional()
        .context("failed to load installation identity binding")
}

fn bind_identity(connection: &Connection, identity_dir: &Path, identity: &Identity) -> Result<()> {
    let identity_path = identity_dir
        .to_str()
        .context("installation identity path is not UTF-8")?;
    let fingerprint = identity.public_fingerprint()?;
    connection
        .execute(
            "INSERT INTO installation_identity_binding(
                singleton, identity_path, public_fingerprint, bound_at
             ) VALUES (1, ?1, ?2, ?3)",
            params![identity_path, fingerprint, unix_timestamp()?],
        )
        .context("failed to bind installation identity")?;
    Ok(())
}

fn validate_identity_dir_path(data_dir: &Path, identity_dir: &Path) -> Result<()> {
    validate_absolute_path(identity_dir, "installation identity directory")?;
    if identity_dir == data_dir || identity_dir.starts_with(data_dir) {
        bail!("installation identity directory must be outside node state");
    }
    Ok(())
}

fn validate_absolute_path(path: &Path, label: &str) -> Result<()> {
    if !path.is_absolute()
        || path
            .components()
            .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
    {
        bail!("{label} must be an absolute normalized path");
    }
    Ok(())
}

fn prepare_identity_directory(path: &Path) -> Result<()> {
    if path.exists() {
        return inspect_identity_directory(path);
    }
    fs::create_dir(path).with_context(|| {
        format!(
            "failed to create installation identity directory {}",
            path.display()
        )
    })?;
    set_directory_owner_only(path)?;
    File::open(path)?.sync_all()?;
    inspect_identity_directory(path)
}

fn inspect_identity_directory(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path).with_context(|| {
        format!(
            "failed to inspect installation identity directory {}",
            path.display()
        )
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        bail!("installation identity path must be a non-symlink directory");
    }
    ensure_directory_owner_only(path)
}

fn migrate_legacy_identity(data_dir: &Path, identity_dir: &Path) -> Result<()> {
    for name in [ED25519_SEED_FILE, X25519_SEED_FILE] {
        let legacy = data_dir.join(name);
        let target = identity_dir.join(name);
        let legacy_exists = legacy.try_exists()?;
        let target_exists = target.try_exists()?;
        if legacy_exists && target_exists {
            bail!("legacy and installation identity both contain {name}");
        }
        if legacy_exists {
            let metadata = fs::symlink_metadata(&legacy)?;
            if metadata.file_type().is_symlink() || !metadata.is_file() {
                bail!("legacy installation identity is unsafe");
            }
            ensure_owner_only(&legacy)?;
        }
    }
    for name in [ED25519_SEED_FILE, X25519_SEED_FILE] {
        let legacy = data_dir.join(name);
        if legacy.try_exists()? {
            fs::rename(&legacy, identity_dir.join(name))
                .with_context(|| format!("failed to move legacy installation identity {name}"))?;
        }
    }
    File::open(identity_dir)?.sync_all()?;
    File::open(data_dir)?.sync_all()?;
    Ok(())
}

fn load_or_create_seed(path: &Path) -> Result<SecretSeed> {
    if path.exists() {
        return load_seed(path);
    }
    let mut bytes = [0_u8; SEED_LENGTH];
    OsRng.fill_bytes(&mut bytes);
    atomic_write_owner_only(path, &bytes)?;
    load_seed(path)
}

fn load_seed(path: &Path) -> Result<SecretSeed> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("failed to inspect {}", path.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        bail!("{} must be a regular non-symlink file", path.display());
    }
    ensure_owner_only(path)?;
    let bytes = fs::read(path).with_context(|| format!("failed to read {}", path.display()))?;
    let seed: [u8; SEED_LENGTH] = bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("{} has an invalid seed length", path.display()))?;
    Ok(SecretSeed(seed))
}

fn atomic_write_owner_only(path: &Path, contents: &[u8]) -> Result<()> {
    let parent = path.parent().context("seed path has no parent")?;
    let mut random = [0_u8; 8];
    OsRng.fill_bytes(&mut random);
    let temporary = parent.join(format!(".seed-{}.tmp", u64::from_ne_bytes(random)));
    let result = (|| -> Result<()> {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        set_create_owner_only(&mut options);
        let mut file = options.open(&temporary)?;
        file.write_all(contents)?;
        file.sync_all()?;
        fs::rename(&temporary, path)?;
        File::open(parent)?.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result.with_context(|| format!("failed to atomically create {}", path.display()))
}

struct DataDirLock {
    file: File,
}

impl DataDirLock {
    fn acquire(data_dir: &Path, create: bool) -> Result<Self> {
        if create {
            fs::create_dir_all(data_dir)?;
            set_directory_owner_only(data_dir)?;
        } else if !data_dir.is_dir() {
            bail!("node host is not initialized");
        }
        let path = data_dir.join(LOCK_FILE);
        let mut options = OpenOptions::new();
        options.read(true).write(true).create(create);
        set_create_owner_only(&mut options);
        let file = options
            .open(&path)
            .context("node host is not initialized")?;
        set_owner_only(&path)?;
        file.try_lock_exclusive()
            .context("node host data directory is already in use")?;
        Ok(Self { file })
    }
}

impl Drop for DataDirLock {
    fn drop(&mut self) {
        let _ = FileExt::unlock(&self.file);
    }
}

#[cfg(unix)]
fn set_create_owner_only(options: &mut OpenOptions) {
    use std::os::unix::fs::OpenOptionsExt as _;
    options.mode(0o600);
}

#[cfg(not(unix))]
fn set_create_owner_only(_options: &mut OpenOptions) {}

#[cfg(unix)]
fn set_owner_only(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt as _;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(())
}

#[cfg(not(unix))]
fn set_owner_only(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(unix)]
fn ensure_owner_only(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt as _;
    let mode = fs::metadata(path)?.permissions().mode() & 0o777;
    if mode != 0o600 {
        bail!("{} must have permissions 0600", path.display());
    }
    Ok(())
}

#[cfg(not(unix))]
fn ensure_owner_only(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(unix)]
fn set_directory_owner_only(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt as _;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    Ok(())
}

#[cfg(not(unix))]
fn set_directory_owner_only(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(unix)]
fn ensure_directory_owner_only(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt as _;
    let mode = fs::metadata(path)?.permissions().mode() & 0o777;
    if mode != 0o700 {
        bail!("{} must have permissions 0700", path.display());
    }
    Ok(())
}

#[cfg(not(unix))]
fn ensure_directory_owner_only(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{open_database, SecretSeed};

    #[test]
    fn private_seed_debug_is_redacted() {
        let seed = SecretSeed([42; 32]);
        assert_eq!(format!("{seed:?}"), "[redacted]");
        assert!(!format!("{seed:?}").contains("42"));
    }

    #[test]
    fn configured_connection_uses_required_pragmas() {
        let temp = tempfile::tempdir().unwrap();
        let connection = open_database(temp.path(), true).unwrap();

        for (pragma, expected) in [
            ("foreign_keys", 1),
            ("synchronous", 2),
            ("trusted_schema", 0),
            ("secure_delete", 2),
        ] {
            let actual: i64 = connection
                .query_row(&format!("PRAGMA {pragma}"), [], |row| row.get(0))
                .unwrap();
            assert_eq!(actual, expected, "unexpected PRAGMA {pragma}");
        }
    }
}
