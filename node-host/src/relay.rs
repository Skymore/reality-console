use crate::{
    atomic_write_owner_only, ensure_owner_only, migrate, open_database, set_directory_owner_only,
    unix_timestamp, DataDirLock,
};
use anyhow::{bail, Context as _, Result};
use control_protocol::id::{EndpointId, Revision, Timestamp};
use control_protocol::node::{EndpointCandidate, EndpointMode, EndpointSource};
use relay_server::{ConnectorStatus, NodeConnectorConfig, RelayNodeConnector};
use rusqlite::{params, Connection, OptionalExtension as _, TransactionBehavior};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::fs;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use time::OffsetDateTime;
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

const ASSIGNMENT_SCHEMA_VERSION: u16 = 1;
const RELAY_CONSENT_POLICY_VERSION: &str = "2026-07-11-relay-v1";
const MATERIAL_DIRECTORY: &str = "relay-material";
const MAX_ASSIGNMENT_BYTES: u64 = 128 * 1024;
const MAX_MATERIAL_BYTES: u64 = 128 * 1024;

/// One controller-issued relay route installed by the local host owner.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RelayAssignmentFile {
    pub schema_version: u16,
    pub endpoint_id: EndpointId,
    pub route_id: String,
    pub relay_address: SocketAddr,
    pub relay_server_name: String,
    pub public_address: String,
    pub public_port: u16,
    pub expires_at: Timestamp,
    pub route_token_path: PathBuf,
    pub tls_certificate_path: PathBuf,
    pub tls_private_key_path: PathBuf,
    pub relay_ca_path: PathBuf,
}

/// Safe durable relay assignment state. Credential paths and contents are omitted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RelayAssignmentStatus {
    pub state: RelayAssignmentState,
    pub endpoint_id: Option<EndpointId>,
    pub public_address: Option<String>,
    pub public_port: Option<u16>,
    pub expires_at: Option<Timestamp>,
    pub consented_at: Option<Timestamp>,
}

/// Durable assignment lifecycle, independent from the live connector state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum RelayAssignmentState {
    NotConfigured,
    Configured,
    Expired,
    Revoked,
}

/// Redacted live connector state exposed through the same-user local API.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum RelayRuntimeState {
    NotConfigured,
    WaitingForRuntime,
    Connecting,
    Registered,
    Backoff,
    Stopped,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct StoredAssignment {
    endpoint_id: EndpointId,
    route_id: String,
    relay_address: SocketAddr,
    relay_server_name: String,
    public_address: String,
    public_port: u16,
    expires_at: Timestamp,
    material_generation: String,
    material_digest: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct RelayTarget {
    pub revision: Revision,
    pub admission_port: u16,
}

struct RunningRelay {
    assignment: StoredAssignment,
    target: RelayTarget,
    status: watch::Receiver<ConnectorStatus>,
    registered_at: Option<Timestamp>,
    cancellation: CancellationToken,
    task: JoinHandle<()>,
}

/// Owns at most one controller-assigned relay connector for this Node Host.
pub(crate) struct RelaySupervisor {
    running: Option<RunningRelay>,
    state: RelayRuntimeState,
}

impl RelaySupervisor {
    pub(crate) fn new() -> Self {
        Self {
            running: None,
            state: RelayRuntimeState::NotConfigured,
        }
    }

    pub(crate) fn runtime_state(&mut self) -> RelayRuntimeState {
        self.refresh_status();
        self.state
    }

    pub(crate) fn poll_status_change(&mut self) -> bool {
        let changed = self
            .running
            .as_ref()
            .is_some_and(|running| running.status.has_changed().unwrap_or(true));
        if changed {
            self.refresh_status();
        }
        changed
    }

    pub(crate) async fn reconcile(
        &mut self,
        data_dir: &Path,
        target: Option<RelayTarget>,
    ) -> Result<()> {
        let connection = open_database(data_dir, false)?;
        let assignment = load_active_assignment(&connection)?;
        let Some(assignment) = assignment else {
            self.stop_running().await;
            self.state = if load_status(&connection)?.state == RelayAssignmentState::NotConfigured {
                RelayRuntimeState::NotConfigured
            } else {
                RelayRuntimeState::Stopped
            };
            return Ok(());
        };
        let Some(target) = target else {
            self.stop_running().await;
            self.state = RelayRuntimeState::WaitingForRuntime;
            return Ok(());
        };
        if self
            .running
            .as_ref()
            .is_some_and(|running| running.assignment == assignment && running.target == target)
        {
            self.refresh_status();
            return Ok(());
        }

        self.stop_running().await;
        let config = connector_config(data_dir, &assignment, target)?;
        let connector = Arc::new(
            RelayNodeConnector::new(config)
                .await
                .context("installed relay material is invalid")?,
        );
        let status = connector.subscribe();
        let cancellation = CancellationToken::new();
        let task_cancellation = cancellation.clone();
        let task = tokio::spawn(async move {
            connector.run(task_cancellation).await;
        });
        self.running = Some(RunningRelay {
            assignment,
            target,
            status,
            registered_at: None,
            cancellation,
            task,
        });
        self.state = RelayRuntimeState::Connecting;
        Ok(())
    }

    pub(crate) fn candidate(&mut self) -> Result<Option<EndpointCandidate>> {
        self.refresh_status();
        if self.state != RelayRuntimeState::Registered {
            return Ok(None);
        }
        let running = self
            .running
            .as_ref()
            .context("registered relay has no owned connector")?;
        let observed_at = running
            .registered_at
            .context("registered relay has no observation time")?;
        Ok(Some(EndpointCandidate {
            endpoint_id: running.assignment.endpoint_id,
            mode: EndpointMode::Relay,
            source: EndpointSource::Relay,
            address: running.assignment.public_address.clone(),
            port: running.assignment.public_port,
            applied_revision: running.target.revision,
            observed_at,
            expires_at: Some(running.assignment.expires_at),
        }))
    }

    pub(crate) async fn shutdown(&mut self) {
        self.stop_running().await;
        self.state = RelayRuntimeState::Stopped;
    }

    fn refresh_status(&mut self) {
        let Some(running) = self.running.as_mut() else {
            return;
        };
        let state = match &*running.status.borrow_and_update() {
            ConnectorStatus::Disconnected | ConnectorStatus::Connecting => {
                RelayRuntimeState::Connecting
            }
            ConnectorStatus::Registered => RelayRuntimeState::Registered,
            ConnectorStatus::Backoff { .. } => RelayRuntimeState::Backoff,
            ConnectorStatus::Stopped => RelayRuntimeState::Stopped,
        };
        if state == RelayRuntimeState::Registered {
            if running.registered_at.is_none() {
                running.registered_at = Some(now());
            }
        } else {
            running.registered_at = None;
        }
        self.state = state;
    }

    async fn stop_running(&mut self) {
        if let Some(running) = self.running.take() {
            running.cancellation.cancel();
            let _ = running.task.await;
        }
    }
}

/// Installs or atomically replaces one relay assignment after explicit local consent.
///
/// The assignment document and all referenced secret material must be owner-only files. Material
/// is copied into a generation directory; `SQLite` contains only route metadata and digests.
///
/// # Errors
///
/// Returns an error for missing consent, an unenrolled host, unsafe files, invalid TLS material,
/// an expired assignment, or replacement without `replace`.
pub async fn configure_relay(
    data_dir: &Path,
    assignment_path: &Path,
    accept_relay: bool,
    replace: bool,
) -> Result<RelayAssignmentStatus> {
    if !accept_relay {
        bail!("relay configuration requires explicit --accept-relay provider consent");
    }
    ensure_regular_owner_only(assignment_path)?;
    let assignment = load_assignment_file(assignment_path)?;
    validate_assignment(&assignment)?;

    let _lock = DataDirLock::acquire(data_dir, false)?;
    let mut connection = open_database(data_dir, false)?;
    migrate(&mut connection)?;
    require_enrolled_provider_consent(&connection)?;

    let material = read_material(assignment_path, &assignment)?;
    let material_digest = material_digest(&material);
    let generation = Uuid::new_v4().to_string();
    let candidate = stored_assignment(&assignment, generation.clone(), material_digest);
    let existing = load_active_assignment(&connection)?;
    if existing
        .as_ref()
        .is_some_and(|value| same_assignment(value, &candidate))
    {
        return load_status(&connection);
    }
    if existing.is_some() && !replace {
        bail!("a different relay assignment is active; pass --replace to rotate it");
    }

    let generation_dir = data_dir.join(MATERIAL_DIRECTORY).join(&generation);
    persist_material(&generation_dir, &material)?;
    let validation_revision =
        Revision::new(1).context("relay validation revision could not be constructed")?;
    let config = connector_config(
        data_dir,
        &candidate,
        RelayTarget {
            revision: validation_revision,
            admission_port: 1,
        },
    )?;
    if let Err(error) = RelayNodeConnector::new(config).await {
        let _ = fs::remove_dir_all(&generation_dir);
        return Err(error).context("relay assignment credential validation failed");
    }

    let previous_generation = existing.map(|value| value.material_generation);
    if let Err(error) = persist_assignment(&mut connection, &candidate) {
        let _ = fs::remove_dir_all(&generation_dir);
        return Err(error).context("relay assignment could not be committed");
    }
    if let Some(previous) = previous_generation {
        if previous != generation {
            let _ = fs::remove_dir_all(data_dir.join(MATERIAL_DIRECTORY).join(previous));
        }
    }
    load_status(&connection)
}

fn persist_assignment(connection: &mut Connection, candidate: &StoredAssignment) -> Result<()> {
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let now = unix_timestamp()?;
    transaction.execute(
        "INSERT INTO relay_provider_consent(singleton, policy_version, accepted_at)
         VALUES (1, ?1, ?2)
         ON CONFLICT(singleton) DO UPDATE SET
            policy_version = excluded.policy_version,
            accepted_at = excluded.accepted_at",
        params![RELAY_CONSENT_POLICY_VERSION, now],
    )?;
    transaction.execute(
        "INSERT INTO relay_assignment(
            singleton, state, endpoint_id, route_id, relay_address, relay_server_name,
            public_address, public_port, expires_at, material_generation, material_digest,
            installed_at, updated_at, revoked_at
         ) VALUES (1, 'active', ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?10, NULL)
         ON CONFLICT(singleton) DO UPDATE SET
            state = 'active', endpoint_id = excluded.endpoint_id, route_id = excluded.route_id,
            relay_address = excluded.relay_address,
            relay_server_name = excluded.relay_server_name,
            public_address = excluded.public_address, public_port = excluded.public_port,
            expires_at = excluded.expires_at,
            material_generation = excluded.material_generation,
            material_digest = excluded.material_digest,
            updated_at = excluded.updated_at, revoked_at = NULL",
        params![
            candidate.endpoint_id.to_string(),
            candidate.route_id.as_str(),
            candidate.relay_address.to_string(),
            candidate.relay_server_name.as_str(),
            candidate.public_address.as_str(),
            i64::from(candidate.public_port),
            candidate.expires_at.as_datetime().unix_timestamp(),
            candidate.material_generation.as_str(),
            candidate.material_digest.as_str(),
            now,
        ],
    )?;
    transaction.commit()?;
    Ok(())
}

/// Revokes the active relay assignment and removes its local credential generation.
///
/// # Errors
///
/// Returns an error if the confirmation endpoint does not match or durable state cannot be
/// updated. Retained provider consent is not silently rewritten or removed.
pub fn revoke_relay(
    data_dir: &Path,
    confirm_endpoint_id: EndpointId,
) -> Result<RelayAssignmentStatus> {
    let _lock = DataDirLock::acquire(data_dir, false)?;
    let mut connection = open_database(data_dir, false)?;
    migrate(&mut connection)?;
    let status = load_status(&connection)?;
    let stored_endpoint = status
        .endpoint_id
        .context("no relay assignment exists to revoke")?;
    if stored_endpoint != confirm_endpoint_id {
        bail!("relay endpoint confirmation does not match the stored assignment");
    }
    if status.state == RelayAssignmentState::Revoked {
        return Ok(status);
    }
    let active = load_assignment_material(&connection)?;
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    transaction.execute(
        "UPDATE relay_assignment
         SET state = 'revoked', material_generation = NULL, material_digest = NULL,
             revoked_at = ?1, updated_at = ?1
         WHERE singleton = 1 AND state = 'active'",
        [unix_timestamp()?],
    )?;
    transaction.commit()?;
    if let Some(active) = active {
        fs::remove_dir_all(
            data_dir
                .join(MATERIAL_DIRECTORY)
                .join(active.material_generation),
        )
        .context("relay assignment was revoked but credential cleanup failed")?;
    }
    load_status(&connection)
}

pub(crate) fn load_status(connection: &Connection) -> Result<RelayAssignmentStatus> {
    let consented_at = connection
        .query_row(
            "SELECT accepted_at FROM relay_provider_consent WHERE singleton = 1",
            [],
            |row| row.get::<_, i64>(0),
        )
        .optional()?
        .map(timestamp_from_unix)
        .transpose()?;
    let row = connection
        .query_row(
            "SELECT state, endpoint_id, public_address, public_port, expires_at
             FROM relay_assignment WHERE singleton = 1",
            [],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, i64>(4)?,
                ))
            },
        )
        .optional()?;
    let Some((state, endpoint_id, address, port, expires_at)) = row else {
        return Ok(RelayAssignmentStatus {
            state: RelayAssignmentState::NotConfigured,
            endpoint_id: None,
            public_address: None,
            public_port: None,
            expires_at: None,
            consented_at,
        });
    };
    let expires_at = timestamp_from_unix(expires_at)?;
    let state = if state == "revoked" {
        RelayAssignmentState::Revoked
    } else if expires_at.as_datetime() <= OffsetDateTime::now_utc() {
        RelayAssignmentState::Expired
    } else {
        RelayAssignmentState::Configured
    };
    Ok(RelayAssignmentStatus {
        state,
        endpoint_id: Some(
            endpoint_id
                .parse()
                .context("stored relay endpoint ID is invalid")?,
        ),
        public_address: Some(address),
        public_port: Some(u16::try_from(port).context("stored relay public port is invalid")?),
        expires_at: Some(expires_at),
        consented_at,
    })
}

fn load_active_assignment(connection: &Connection) -> Result<Option<StoredAssignment>> {
    let assignment = load_assignment_material(connection)?;
    Ok(assignment.filter(|value| value.expires_at.as_datetime() > OffsetDateTime::now_utc()))
}

fn load_assignment_material(connection: &Connection) -> Result<Option<StoredAssignment>> {
    connection
        .query_row(
            "SELECT endpoint_id, route_id, relay_address, relay_server_name, public_address,
                    public_port, expires_at, material_generation, material_digest
             FROM relay_assignment
             WHERE singleton = 1 AND state = 'active'",
            [],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, i64>(5)?,
                    row.get::<_, i64>(6)?,
                    row.get::<_, String>(7)?,
                    row.get::<_, String>(8)?,
                ))
            },
        )
        .optional()?
        .map(|row| {
            Ok(StoredAssignment {
                endpoint_id: row
                    .0
                    .parse()
                    .context("stored relay endpoint ID is invalid")?,
                route_id: row.1,
                relay_address: row.2.parse().context("stored relay address is invalid")?,
                relay_server_name: row.3,
                public_address: row.4,
                public_port: u16::try_from(row.5).context("stored relay port is invalid")?,
                expires_at: timestamp_from_unix(row.6)?,
                material_generation: row.7,
                material_digest: row.8,
            })
        })
        .transpose()
}

fn connector_config(
    data_dir: &Path,
    assignment: &StoredAssignment,
    target: RelayTarget,
) -> Result<NodeConnectorConfig> {
    if target.admission_port == 0 {
        bail!("relay target admission port cannot be zero");
    }
    let material = data_dir
        .join(MATERIAL_DIRECTORY)
        .join(&assignment.material_generation);
    let config = NodeConnectorConfig {
        relay_address: assignment.relay_address,
        relay_server_name: assignment.relay_server_name.clone(),
        route_id: assignment.route_id.clone(),
        route_token_path: material.join("route-token"),
        tls_cert_path: material.join("node-cert.pem"),
        tls_key_path: material.join("node-key.pem"),
        relay_ca_path: material.join("relay-ca.pem"),
        local_target: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), target.admission_port),
        max_frame_bytes: 64 * 1024,
        command_queue_frames: 64,
        stream_buffer_frames: 16,
        initial_window_bytes: 256 * 1024,
        max_streams: 128,
        connect_timeout_secs: 10,
        idle_timeout_secs: 120,
        heartbeat_interval_secs: 15,
        heartbeat_timeout_secs: 45,
        reconnect_initial_ms: 500,
        reconnect_max_secs: 60,
    };
    config.validate().context("relay assignment is unsafe")?;
    Ok(config)
}

struct Material {
    route_token: Vec<u8>,
    certificate: Vec<u8>,
    private_key: Vec<u8>,
    ca: Vec<u8>,
}

fn read_material(assignment_path: &Path, assignment: &RelayAssignmentFile) -> Result<Material> {
    let base = assignment_path.parent().unwrap_or_else(|| Path::new("."));
    let token_path = resolve_path(base, &assignment.route_token_path);
    let certificate_path = resolve_path(base, &assignment.tls_certificate_path);
    let key_path = resolve_path(base, &assignment.tls_private_key_path);
    let ca_path = resolve_path(base, &assignment.relay_ca_path);
    ensure_regular_owner_only(&token_path)?;
    ensure_regular_owner_only(&key_path)?;
    Ok(Material {
        route_token: read_bounded(&token_path, MAX_MATERIAL_BYTES)?,
        certificate: read_bounded(&certificate_path, MAX_MATERIAL_BYTES)?,
        private_key: read_bounded(&key_path, MAX_MATERIAL_BYTES)?,
        ca: read_bounded(&ca_path, MAX_MATERIAL_BYTES)?,
    })
}

fn persist_material(directory: &Path, material: &Material) -> Result<()> {
    let root = directory.parent().context("relay generation has no root")?;
    fs::create_dir_all(root)?;
    set_directory_owner_only(root)?;
    fs::create_dir_all(directory)?;
    set_directory_owner_only(directory)?;
    let result = (|| -> Result<()> {
        atomic_write_owner_only(&directory.join("route-token"), &material.route_token)?;
        atomic_write_owner_only(&directory.join("node-cert.pem"), &material.certificate)?;
        atomic_write_owner_only(&directory.join("node-key.pem"), &material.private_key)?;
        atomic_write_owner_only(&directory.join("relay-ca.pem"), &material.ca)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_dir_all(directory);
    }
    result
}

fn load_assignment_file(path: &Path) -> Result<RelayAssignmentFile> {
    let bytes = read_bounded(path, MAX_ASSIGNMENT_BYTES)?;
    serde_json::from_slice(&bytes).context("relay assignment file is invalid JSON")
}

fn validate_assignment(assignment: &RelayAssignmentFile) -> Result<()> {
    if assignment.schema_version != ASSIGNMENT_SCHEMA_VERSION {
        bail!("relay assignment schema version is unsupported");
    }
    if assignment.public_port == 0
        || assignment.public_address.is_empty()
        || assignment.public_address.len() > 253
        || assignment.public_address.contains('/')
        || assignment.public_address.contains(char::is_whitespace)
    {
        bail!("relay public endpoint is invalid");
    }
    if assignment.expires_at.as_datetime() <= OffsetDateTime::now_utc() {
        bail!("relay assignment is expired");
    }
    Ok(())
}

fn require_enrolled_provider_consent(connection: &Connection) -> Result<()> {
    let enrolled: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM enrollment_registration WHERE singleton = 1)",
        [],
        |row| row.get(0),
    )?;
    if !enrolled {
        bail!("node host must be enrolled before configuring relay");
    }
    let consent: Option<(bool, bool)> = connection
        .query_row(
            "SELECT host_owner_consented, exit_ip_disclosure_accepted
             FROM provider_consent_receipt WHERE singleton = 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    if consent != Some((true, true)) {
        bail!("durable provider host-owner and exit-IP consent is missing");
    }
    Ok(())
}

fn stored_assignment(
    value: &RelayAssignmentFile,
    material_generation: String,
    material_digest: String,
) -> StoredAssignment {
    StoredAssignment {
        endpoint_id: value.endpoint_id,
        route_id: value.route_id.clone(),
        relay_address: value.relay_address,
        relay_server_name: value.relay_server_name.clone(),
        public_address: value.public_address.clone(),
        public_port: value.public_port,
        expires_at: value.expires_at,
        material_generation,
        material_digest,
    }
}

fn same_assignment(left: &StoredAssignment, right: &StoredAssignment) -> bool {
    left.endpoint_id == right.endpoint_id
        && left.route_id == right.route_id
        && left.relay_address == right.relay_address
        && left.relay_server_name == right.relay_server_name
        && left.public_address == right.public_address
        && left.public_port == right.public_port
        && left.expires_at == right.expires_at
        && left.material_digest == right.material_digest
}

fn material_digest(material: &Material) -> String {
    let mut hasher = Sha256::new();
    for value in [
        material.route_token.as_slice(),
        material.certificate.as_slice(),
        material.private_key.as_slice(),
        material.ca.as_slice(),
    ] {
        hasher.update((value.len() as u64).to_be_bytes());
        hasher.update(value);
    }
    format!("sha256:{:x}", hasher.finalize())
}

fn resolve_path(base: &Path, value: &Path) -> PathBuf {
    if value.is_absolute() {
        value.to_path_buf()
    } else {
        base.join(value)
    }
}

fn read_bounded(path: &Path, max_bytes: u64) -> Result<Vec<u8>> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("failed to inspect {}", path.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.len() > max_bytes {
        bail!(
            "{} must be a bounded regular non-symlink file",
            path.display()
        );
    }
    fs::read(path).with_context(|| format!("failed to read {}", path.display()))
}

fn ensure_regular_owner_only(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("failed to inspect {}", path.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        bail!("{} must be a regular non-symlink file", path.display());
    }
    ensure_owner_only(path)
}

fn timestamp_from_unix(value: i64) -> Result<Timestamp> {
    Ok(Timestamp::from_datetime(
        OffsetDateTime::from_unix_timestamp(value).context("stored relay timestamp is invalid")?,
    ))
}

fn now() -> Timestamp {
    Timestamp::from_datetime(OffsetDateTime::now_utc())
}

#[cfg(test)]
mod tests {
    use super::{
        configure_relay, connector_config, revoke_relay, RelayAssignmentState, RelaySupervisor,
        RelayTarget, StoredAssignment,
    };
    use crate::{initialize, open_database, set_owner_only, unix_timestamp};
    use control_protocol::id::{EndpointId, Revision, SequenceNumber, Timestamp};
    use control_protocol::node::{NodeHeartbeat, NodeRuntimeState, RevisionProgress};
    use rcgen::{
        BasicConstraints, CertificateParams, CertifiedIssuer, ExtendedKeyUsagePurpose, IsCa,
        KeyPair,
    };
    use relay_server::{RelayConfig, RelayServer, RouteConfig, ServerConfig};
    use rusqlite::params;
    use sha2::{Digest as _, Sha256};
    use std::fs;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::path::Path;
    use time::{Duration, OffsetDateTime};
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    use tokio::net::{TcpListener, TcpStream};
    use uuid::Uuid;

    const ROUTE_ID: &str = "route_0123456789abcdef";
    const ROUTE_TOKEN: &[u8] = b"test-route-token-with-256-bits-000";

    #[test]
    fn connector_target_is_always_fixed_loopback_admission() {
        let assignment = StoredAssignment {
            endpoint_id: EndpointId::new(),
            route_id: "route_0123456789abcdef".to_owned(),
            relay_address: "203.0.113.1:9443".parse().unwrap(),
            relay_server_name: "relay.example".to_owned(),
            public_address: "relay.example".to_owned(),
            public_port: 443,
            expires_at: Timestamp::from_datetime(OffsetDateTime::now_utc() + Duration::hours(1)),
            material_generation: "generation".to_owned(),
            material_digest: "sha256:unused".to_owned(),
        };
        let config = connector_config(
            std::path::Path::new("/private/node"),
            &assignment,
            RelayTarget {
                revision: Revision::new(7).unwrap(),
                admission_port: 18443,
            },
        )
        .unwrap();
        assert_eq!(
            config.local_target,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 18443)
        );
    }

    #[tokio::test]
    async fn real_server_node_host_connector_and_heartbeat_candidate_e2e() {
        let directory = tempfile::tempdir().unwrap();
        let data_dir = directory.path().join("node-state");
        initialize(&data_dir, "https://controller.example").unwrap();
        seed_enrollment(&data_dir);

        let pki = TestPki::new(directory.path());
        let relay_config = pki.server_config();
        let relay = RelayServer::start(relay_config).await.unwrap();
        let route_address = relay.route_address(ROUTE_ID).await.unwrap();
        let backend = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let backend_address = backend.local_addr().unwrap();
        let backend_task = tokio::spawn(async move {
            let (mut stream, _) = backend.accept().await.unwrap();
            let (mut reader, mut writer) = stream.split();
            tokio::io::copy(&mut reader, &mut writer).await.unwrap();
        });

        let endpoint_id = EndpointId::new();
        let expiry = Timestamp::from_datetime(OffsetDateTime::now_utc() + Duration::hours(1));
        let assignment_path =
            pki.write_assignment(endpoint_id, relay.node_address(), route_address, expiry);
        let configured = configure_relay(&data_dir, &assignment_path, true, false)
            .await
            .unwrap();
        assert_eq!(configured.state, RelayAssignmentState::Configured);
        assert_eq!(configured.endpoint_id, Some(endpoint_id));

        let database = fs::read(data_dir.join("node-host.sqlite3")).unwrap();
        assert!(!contains_bytes(&database, ROUTE_TOKEN));
        assert!(!contains_bytes(&database, &pki.client_key_bytes));
        assert!(!contains_bytes(&database, &pki.client_cert_bytes));

        let revision = Revision::new(1).unwrap();
        let mut supervisor = RelaySupervisor::new();
        supervisor
            .reconcile(
                &data_dir,
                Some(RelayTarget {
                    revision,
                    admission_port: backend_address.port(),
                }),
            )
            .await
            .unwrap();
        assert!(supervisor.candidate().unwrap().is_none());
        let candidate = wait_for_candidate(&mut supervisor).await;
        assert_eq!(candidate.endpoint_id, endpoint_id);
        assert_eq!(candidate.applied_revision, revision);
        assert_eq!(candidate.address, route_address.ip().to_string());
        assert_eq!(candidate.port, route_address.port());

        let heartbeat = NodeHeartbeat {
            heartbeat_generation: SequenceNumber::new(1).unwrap(),
            agent_version: "0.1.0".to_owned(),
            xray_version: Some("test".to_owned()),
            state: NodeRuntimeState::Serving,
            revisions: RevisionProgress {
                desired_revision: Some(revision),
                received_revision: Some(revision),
                validated_revision: Some(revision),
                applied_revision: Some(revision),
            },
            provider_paused: false,
            endpoints: vec![candidate],
            telemetry_cursor: SequenceNumber::new(1).unwrap(),
        };
        heartbeat.validate().unwrap();

        let payload = b"opaque-vless-reality-through-node-host";
        let mut member = TcpStream::connect(route_address).await.unwrap();
        member.write_all(payload).await.unwrap();
        let mut response = vec![0_u8; payload.len()];
        member.read_exact(&mut response).await.unwrap();
        assert_eq!(response, payload);

        supervisor.shutdown().await;
        let mut restarted = RelaySupervisor::new();
        restarted
            .reconcile(
                &data_dir,
                Some(RelayTarget {
                    revision,
                    admission_port: backend_address.port(),
                }),
            )
            .await
            .unwrap();
        assert_eq!(
            wait_for_candidate(&mut restarted).await.endpoint_id,
            endpoint_id
        );
        restarted.shutdown().await;
        relay.shutdown().await;
        backend_task.abort();
        let revoked = revoke_relay(&data_dir, endpoint_id).unwrap();
        assert_eq!(revoked.state, RelayAssignmentState::Revoked);
        assert!(revoked.consented_at.is_some());
        assert!(fs::read_dir(data_dir.join("relay-material"))
            .unwrap()
            .next()
            .is_none());
    }

    struct TestPki {
        root: std::path::PathBuf,
        server_cert_path: std::path::PathBuf,
        server_key_path: std::path::PathBuf,
        ca_path: std::path::PathBuf,
        client_cert_path: std::path::PathBuf,
        client_key_path: std::path::PathBuf,
        token_path: std::path::PathBuf,
        client_cert_digest: String,
        client_cert_bytes: Vec<u8>,
        client_key_bytes: Vec<u8>,
    }

    impl TestPki {
        fn new(root: &Path) -> Self {
            let pki = root.join("pki");
            fs::create_dir(&pki).unwrap();
            let ca_key = KeyPair::generate().unwrap();
            let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
            ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
            let ca = CertifiedIssuer::self_signed(ca_params, ca_key).unwrap();

            let server_key = KeyPair::generate().unwrap();
            let mut server_params = CertificateParams::new(vec!["localhost".to_owned()]).unwrap();
            server_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
            let server_cert = server_params.signed_by(&server_key, &ca).unwrap();
            let client_key = KeyPair::generate().unwrap();
            let mut client_params = CertificateParams::new(Vec::<String>::new()).unwrap();
            client_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
            let client_cert = client_params.signed_by(&client_key, &ca).unwrap();

            let server_cert_path = pki.join("server.pem");
            let server_key_path = pki.join("server-key.pem");
            let ca_path = pki.join("ca.pem");
            let client_cert_path = pki.join("node.pem");
            let client_key_path = pki.join("node-key.pem");
            let token_path = pki.join("route-token");
            let client_cert_bytes = client_cert.pem().into_bytes();
            let client_key_bytes = client_key.serialize_pem().into_bytes();
            fs::write(&server_cert_path, server_cert.pem()).unwrap();
            fs::write(&server_key_path, server_key.serialize_pem()).unwrap();
            fs::write(&ca_path, ca.pem()).unwrap();
            fs::write(&client_cert_path, &client_cert_bytes).unwrap();
            fs::write(&client_key_path, &client_key_bytes).unwrap();
            fs::write(&token_path, ROUTE_TOKEN).unwrap();
            for path in [
                &server_key_path,
                &client_cert_path,
                &client_key_path,
                &token_path,
            ] {
                set_owner_only(path).unwrap();
            }
            Self {
                root: root.to_path_buf(),
                server_cert_path,
                server_key_path,
                ca_path,
                client_cert_path,
                client_key_path,
                token_path,
                client_cert_digest: hex::encode(Sha256::digest(client_cert.der().as_ref())),
                client_cert_bytes,
                client_key_bytes,
            }
        }

        fn server_config(&self) -> RelayConfig {
            RelayConfig {
                server: ServerConfig {
                    node_listen: "127.0.0.1:0".parse().unwrap(),
                    metrics_listen: "127.0.0.1:0".parse().unwrap(),
                    tls_cert_path: self.server_cert_path.clone(),
                    tls_key_path: self.server_key_path.clone(),
                    client_ca_path: self.ca_path.clone(),
                    max_frame_bytes: 64 * 1024,
                    command_queue_frames: 64,
                    stream_buffer_frames: 16,
                    initial_window_bytes: 256 * 1024,
                    open_timeout_secs: 2,
                    no_payload_timeout_secs: 2,
                    idle_timeout_secs: 10,
                    heartbeat_interval_secs: 1,
                    heartbeat_timeout_secs: 4,
                    reload_interval_secs: 1,
                    max_routes: 4,
                    max_node_connections: 4,
                },
                routes: vec![RouteConfig {
                    route_id: ROUTE_ID.to_owned(),
                    public_listen: "127.0.0.1:0".parse().unwrap(),
                    node_token_sha256: hex::encode(Sha256::digest(ROUTE_TOKEN)),
                    node_cert_sha256: self.client_cert_digest.clone(),
                    expires_at: OffsetDateTime::now_utc() + Duration::hours(1),
                    enabled: true,
                    max_concurrent_streams: 4,
                    max_bytes_per_second: 1_000_000,
                    max_bytes_per_connection: 1_000_000,
                }],
            }
        }

        fn write_assignment(
            &self,
            endpoint_id: EndpointId,
            relay_address: SocketAddr,
            public_address: SocketAddr,
            expires_at: Timestamp,
        ) -> std::path::PathBuf {
            let path = self.root.join("relay-assignment.json");
            fs::write(
                &path,
                serde_json::to_vec(&serde_json::json!({
                    "schemaVersion": 1,
                    "endpointId": endpoint_id,
                    "routeId": ROUTE_ID,
                    "relayAddress": relay_address,
                    "relayServerName": "localhost",
                    "publicAddress": public_address.ip().to_string(),
                    "publicPort": public_address.port(),
                    "expiresAt": expires_at,
                    "routeTokenPath": self.token_path,
                    "tlsCertificatePath": self.client_cert_path,
                    "tlsPrivateKeyPath": self.client_key_path,
                    "relayCaPath": self.ca_path,
                }))
                .unwrap(),
            )
            .unwrap();
            set_owner_only(&path).unwrap();
            path
        }
    }

    fn seed_enrollment(data_dir: &Path) {
        let connection = open_database(data_dir, false).unwrap();
        let invitation_id = Uuid::new_v4().to_string();
        connection
            .execute(
                "INSERT INTO enrollment_registration(
                    singleton, invitation_id, network_id, node_id, controller_instance_id,
                    controller_fingerprint, controller_signing_public_key, credential_key_id,
                    credential_mode, credential_expires_at, enrolled_at
                 ) VALUES (1, ?1, ?2, ?3, ?4, 'fingerprint', 'public-key', ?5,
                    'signedRequest', ?6, ?7)",
                params![
                    invitation_id,
                    Uuid::new_v4().to_string(),
                    Uuid::new_v4().to_string(),
                    Uuid::new_v4().to_string(),
                    Uuid::new_v4().to_string(),
                    Timestamp::from_datetime(OffsetDateTime::now_utc() + Duration::hours(2))
                        .to_string(),
                    unix_timestamp().unwrap(),
                ],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO provider_consent_receipt(
                    singleton, invitation_id, policy_version, host_owner_consented,
                    exit_ip_disclosure_accepted, router_mapping_accepted, accepted_at
                 ) VALUES (1, ?1, 'test', 1, 1, 0, ?2)",
                params![invitation_id, unix_timestamp().unwrap()],
            )
            .unwrap();
    }

    fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
        !needle.is_empty()
            && haystack
                .windows(needle.len())
                .any(|window| window == needle)
    }

    async fn wait_for_candidate(
        supervisor: &mut RelaySupervisor,
    ) -> control_protocol::node::EndpointCandidate {
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            loop {
                if let Some(candidate) = supervisor.candidate().unwrap() {
                    break candidate;
                }
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("Node Host connector did not register")
    }
}
