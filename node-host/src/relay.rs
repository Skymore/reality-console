use crate::{
    atomic_write_owner_only, ensure_owner_only, migrate, open_database, set_directory_owner_only,
    unix_timestamp, DataDirLock, Identity, SyncRegistration,
};
use anyhow::{bail, Context as _, Result};
use control_protocol::crypto::ed25519_signing_key_id;
use control_protocol::id::{
    EndpointId, RelayGeneration, RelayGrantId, RelayRouteId, Revision, Timestamp,
};
use control_protocol::node::{EndpointCandidate, EndpointMode, EndpointSource};
use control_protocol::relay::{
    decrypt_relay_material, verify_relay_assignment_signature, AcknowledgeRelayAssignmentRequest,
    RelayAssignmentMaterial, RelayLimits, SignedRelayAssignment,
};
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
const MANAGED_STATE_FILE: &str = "relay-managed-state.json";
const MANAGED_ASSIGNMENT_FILE: &str = "controller-assignment.json";
const MANAGED_STATE_SCHEMA_VERSION: u16 = 1;
const MAX_ASSIGNMENT_BYTES: u64 = 128 * 1024;
const MAX_MATERIAL_BYTES: u64 = 128 * 1024;
const MAX_MANAGED_ASSIGNMENT_BYTES: u64 = 256 * 1024;

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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    grant_id: Option<RelayGrantId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    logical_route_id: Option<RelayRouteId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    generation: Option<RelayGeneration>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    artifact_digest: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    limits: Option<RelayLimits>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ManagedRelayState {
    #[serde(default = "managed_state_schema_version")]
    schema_version: u16,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    current: Option<StoredAssignment>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    successor: Option<StoredAssignment>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    blocked_consent_at: Option<i64>,
}

impl Default for ManagedRelayState {
    fn default() -> Self {
        Self {
            schema_version: MANAGED_STATE_SCHEMA_VERSION,
            current: None,
            successor: None,
            blocked_consent_at: None,
        }
    }
}

const fn managed_state_schema_version() -> u16 {
    MANAGED_STATE_SCHEMA_VERSION
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

/// Owns the current and, during bounded rotation, successor relay connectors.
pub(crate) struct RelaySupervisor {
    running: Vec<RunningRelay>,
    state: RelayRuntimeState,
}

impl RelaySupervisor {
    pub(crate) fn new() -> Self {
        Self {
            running: Vec::with_capacity(2),
            state: RelayRuntimeState::NotConfigured,
        }
    }

    pub(crate) fn runtime_state(&mut self) -> RelayRuntimeState {
        self.refresh_status();
        self.state
    }

    pub(crate) fn poll_status_change(&mut self) -> bool {
        let now = OffsetDateTime::now_utc();
        let changed = self.running.iter().any(|running| {
            running.status.has_changed().unwrap_or(true)
                || running.assignment.expires_at.as_datetime() <= now
        });
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
        let assignments = match load_runtime_assignments(&connection, data_dir) {
            Ok(assignments) => assignments,
            Err(error) => {
                self.stop_all().await;
                self.state = RelayRuntimeState::Stopped;
                return Err(error);
            }
        };
        if assignments.is_empty() {
            self.stop_all().await;
            self.state = if load_status(&connection)?.state == RelayAssignmentState::NotConfigured {
                RelayRuntimeState::NotConfigured
            } else {
                RelayRuntimeState::Stopped
            };
            return Ok(());
        }
        let Some(target) = target else {
            self.stop_all().await;
            self.state = RelayRuntimeState::WaitingForRuntime;
            return Ok(());
        };

        let mut retained = Vec::with_capacity(2);
        for running in self.running.drain(..) {
            if assignments.contains(&running.assignment) && running.target == target {
                retained.push(running);
            } else {
                stop_running(running).await;
            }
        }
        self.running = retained;

        for assignment in assignments {
            if self
                .running
                .iter()
                .any(|running| running.assignment == assignment)
            {
                continue;
            }
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
            self.running.push(RunningRelay {
                assignment,
                target,
                status,
                registered_at: None,
                cancellation,
                task,
            });
        }
        self.refresh_status();
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn candidate(&mut self) -> Result<Option<EndpointCandidate>> {
        self.candidate_from(None)
    }

    pub(crate) fn candidate_for_state(
        &mut self,
        data_dir: &Path,
    ) -> Result<Option<EndpointCandidate>> {
        let connection = open_database(data_dir, false)?;
        let assignments = load_runtime_assignments(&connection, data_dir)?;
        self.candidate_from(Some(&assignments))
    }

    fn candidate_from(
        &mut self,
        allowed: Option<&[StoredAssignment]>,
    ) -> Result<Option<EndpointCandidate>> {
        self.refresh_status();
        if self.state != RelayRuntimeState::Registered {
            return Ok(None);
        }
        let Some(running) = self
            .running
            .iter()
            .filter(|running| {
                running.assignment.expires_at.as_datetime() > OffsetDateTime::now_utc()
                    && allowed.is_none_or(|assignments| assignments.contains(&running.assignment))
                    && matches!(&*running.status.borrow(), ConnectorStatus::Registered)
            })
            .max_by_key(|running| assignment_generation(&running.assignment))
        else {
            return Ok(None);
        };
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
        self.stop_all().await;
        self.state = RelayRuntimeState::Stopped;
    }

    pub(crate) fn acknowledgement_candidate(
        &mut self,
        data_dir: &Path,
    ) -> Result<Option<AcknowledgeRelayAssignmentRequest>> {
        self.refresh_status();
        let Some(state) = load_managed_state(data_dir)? else {
            return Ok(None);
        };
        let Some(successor) = state.successor else {
            return Ok(None);
        };
        if successor.expires_at.as_datetime() <= OffsetDateTime::now_utc() {
            return Ok(None);
        }
        let registered = self.running.iter().any(|running| {
            running.assignment == successor
                && matches!(&*running.status.borrow(), ConnectorStatus::Registered)
        });
        if !registered {
            return Ok(None);
        }
        Ok(Some(managed_acknowledgement(&successor)?))
    }

    pub(crate) fn acknowledgement_succeeded(
        data_dir: &Path,
        acknowledgement: AcknowledgeRelayAssignmentRequest,
    ) -> Result<()> {
        promote_managed_successor(data_dir, acknowledgement)
    }

    fn refresh_status(&mut self) {
        if self.running.is_empty() {
            return;
        }
        let mut aggregate = RelayRuntimeState::Stopped;
        for running in &mut self.running {
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
                aggregate = RelayRuntimeState::Registered;
            } else {
                running.registered_at = None;
                if aggregate != RelayRuntimeState::Registered {
                    aggregate = match (aggregate, state) {
                        (_, RelayRuntimeState::Connecting) => RelayRuntimeState::Connecting,
                        (RelayRuntimeState::Stopped, RelayRuntimeState::Backoff) => {
                            RelayRuntimeState::Backoff
                        }
                        (current, _) => current,
                    };
                }
            }
        }
        self.state = aggregate;
    }

    async fn stop_all(&mut self) {
        for running in self.running.drain(..) {
            stop_running(running).await;
        }
    }
}

async fn stop_running(running: RunningRelay) {
    running.cancellation.cancel();
    let _ = running.task.await;
}

fn assignment_generation(assignment: &StoredAssignment) -> i64 {
    assignment.generation.map_or(0, RelayGeneration::get)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ManagedAssignmentInstall {
    Installed,
    Unchanged,
    Stale,
}

pub(crate) fn provider_relay_consent(connection: &Connection) -> Result<Option<i64>> {
    connection
        .query_row(
            "SELECT accepted_at FROM relay_provider_consent
             WHERE singleton = 1 AND policy_version = ?1",
            [RELAY_CONSENT_POLICY_VERSION],
            |row| row.get(0),
        )
        .optional()
        .map_err(Into::into)
}

pub(crate) fn provider_relay_consented(data_dir: &Path) -> Result<bool> {
    let connection = open_database(data_dir, false)?;
    Ok(provider_relay_consent_for_data_dir(data_dir, &connection)?.is_some())
}

pub(crate) fn provider_relay_consent_for_data_dir(
    data_dir: &Path,
    connection: &Connection,
) -> Result<Option<i64>> {
    let Some(accepted) = crate::system_setup::provider_relay_consent(data_dir)? else {
        return provider_relay_consent(connection);
    };
    if !accepted {
        connection.execute("DELETE FROM relay_provider_consent WHERE singleton = 1", [])?;
        if has_managed_assignment(data_dir)? {
            withdraw_managed_assignments(data_dir, connection, None)?;
        }
        return Ok(None);
    }
    let path = data_dir.join(crate::system_setup::PROVIDER_SETUP_FILE);
    let accepted_at = fs::metadata(&path)?
        .modified()?
        .duration_since(std::time::UNIX_EPOCH)
        .context("provider setup consent timestamp is before the Unix epoch")?
        .as_secs();
    let accepted_at = i64::try_from(accepted_at).context("provider consent timestamp overflow")?;
    connection.execute(
        "INSERT INTO relay_provider_consent(singleton, policy_version, accepted_at)
         VALUES (1, ?1, ?2)
         ON CONFLICT(singleton) DO UPDATE SET
            policy_version = excluded.policy_version,
            accepted_at = excluded.accepted_at",
        params![RELAY_CONSENT_POLICY_VERSION, accepted_at],
    )?;
    Ok(Some(accepted_at))
}

pub(crate) fn provider_relay_limits(connection: &Connection) -> Result<RelayLimits> {
    let policy = crate::policy::load_status_readonly(connection)?.policy;
    let maximum_byte_limit = 10_u64 * 1_024 * 1_024 * 1_024 * 1_024 * 1_024;
    let monthly_byte_limit = policy
        .monthly_transfer_cap_bytes
        .unwrap_or(maximum_byte_limit);
    let max_bytes_per_second = policy
        .bandwidth_limit_bps
        .map_or(10_000_000_000, |bits| bits.div_ceil(8).max(1_024));
    let limits = RelayLimits {
        max_concurrent_streams: policy.max_concurrent_sessions,
        max_bytes_per_second,
        max_bytes_per_connection: monthly_byte_limit,
        monthly_byte_limit,
    };
    limits
        .validate()
        .context("provider policy cannot be represented as relay limits")?;
    Ok(limits)
}

pub(crate) fn managed_ensure_allowed(data_dir: &Path, consent_at: i64) -> Result<bool> {
    let Some(state) = load_managed_state(data_dir)? else {
        return Ok(true);
    };
    Ok(state
        .blocked_consent_at
        .is_none_or(|blocked| consent_at > blocked))
}

pub(crate) fn has_managed_assignment(data_dir: &Path) -> Result<bool> {
    Ok(load_managed_state(data_dir)?
        .is_some_and(|state| state.current.is_some() || state.successor.is_some()))
}

pub(crate) async fn install_controller_assignment(
    data_dir: &Path,
    connection: &mut Connection,
    registration: &SyncRegistration,
    identity: &Identity,
    assignment: &SignedRelayAssignment,
) -> Result<ManagedAssignmentInstall> {
    verify_controller_assignment(registration, assignment)?;
    let mut state = load_managed_state(data_dir)?.unwrap_or_default();
    let incoming_generation = assignment.header.generation;
    let artifact =
        serde_json::to_vec(assignment).context("failed to encode verified relay assignment")?;
    let artifact_digest = sha256_prefixed(&artifact);
    if let Some(outcome) = reconcile_existing_controller_assignment(
        data_dir,
        connection,
        registration,
        &mut state,
        assignment,
        &artifact_digest,
    )? {
        return Ok(outcome);
    }
    let highest_generation = [state.current.as_ref(), state.successor.as_ref()]
        .into_iter()
        .flatten()
        .filter_map(|stored| stored.generation)
        .max();
    if highest_generation.is_some_and(|highest| incoming_generation < highest) {
        return Ok(ManagedAssignmentInstall::Stale);
    }

    let material = decrypt_relay_material(
        &identity.encryption.0,
        &assignment.header,
        &assignment.encrypted_material,
    )
    .context("controller relay assignment cannot be decrypted by this installation")?;
    let relay_address = resolve_relay_address(
        &assignment.header.tunnel_host,
        assignment.header.tunnel_port,
    )
    .await?;
    let material = Material::from_controller(material);
    let material_digest = material_digest(&material);
    let generation = assignment.header.grant_id.to_string();
    let candidate = StoredAssignment {
        endpoint_id: assignment.header.endpoint_id,
        route_id: assignment.header.registration_route_id(),
        relay_address,
        relay_server_name: assignment.header.tls_server_name.clone(),
        public_address: assignment.header.public_host.clone(),
        public_port: assignment.header.public_port,
        expires_at: assignment.header.expires_at,
        material_generation: generation.clone(),
        material_digest,
        grant_id: Some(assignment.header.grant_id),
        logical_route_id: Some(assignment.header.route_id),
        generation: Some(incoming_generation),
        artifact_digest: Some(artifact_digest),
        limits: Some(assignment.header.limits),
    };
    let generation_dir = data_dir.join(MATERIAL_DIRECTORY).join(&generation);
    if generation_dir.exists() {
        fs::remove_dir_all(&generation_dir)
            .context("failed to replace an incomplete relay generation")?;
    }
    persist_material(&generation_dir, &material)?;
    if let Err(error) =
        atomic_write_owner_only(&generation_dir.join(MANAGED_ASSIGNMENT_FILE), &artifact)
    {
        let _ = fs::remove_dir_all(&generation_dir);
        return Err(error).context("failed to persist verified relay assignment artifact");
    }
    let validation_revision =
        Revision::new(1).context("relay validation revision could not be constructed")?;
    if let Err(error) = RelayNodeConnector::new(connector_config(
        data_dir,
        &candidate,
        RelayTarget {
            revision: validation_revision,
            admission_port: 1,
        },
    )?)
    .await
    {
        let _ = fs::remove_dir_all(&generation_dir);
        return Err(error).context("controller relay credentials failed local validation");
    }

    let replaced_successor = state.successor.replace(candidate.clone());
    state.blocked_consent_at = None;
    if let Err(error) = persist_managed_state(data_dir, &state) {
        let _ = fs::remove_dir_all(&generation_dir);
        return Err(error).context("relay generation could not be committed atomically");
    }
    persist_assignment_metadata(connection, &candidate)?;
    if let Some(replaced) = replaced_successor {
        if replaced.material_generation != generation {
            remove_material_generation(data_dir, &replaced);
        }
    }
    Ok(ManagedAssignmentInstall::Installed)
}

fn reconcile_existing_controller_assignment(
    data_dir: &Path,
    connection: &Connection,
    registration: &SyncRegistration,
    state: &mut ManagedRelayState,
    assignment: &SignedRelayAssignment,
    artifact_digest: &str,
) -> Result<Option<ManagedAssignmentInstall>> {
    let existing = [state.current.as_ref(), state.successor.as_ref()]
        .into_iter()
        .flatten()
        .find(|stored| stored.generation == Some(assignment.header.generation))
        .cloned();
    let Some(existing) = existing else {
        return Ok(None);
    };
    if existing.grant_id != Some(assignment.header.grant_id)
        || existing.artifact_digest.as_deref() != Some(artifact_digest)
    {
        bail!("controller reused a relay generation with different assignment material");
    }
    verify_persisted_managed_assignment(data_dir, registration, &existing)?;
    persist_assignment_metadata(connection, &existing)?;
    if state.current.as_ref() == Some(&existing)
        && state.successor.as_ref().is_some_and(|successor| {
            assignment_generation(successor) > assignment_generation(&existing)
        })
    {
        let withdrawn = state.successor.take();
        persist_managed_state(data_dir, state)?;
        if let Some(withdrawn) = withdrawn {
            remove_material_generation(data_dir, &withdrawn);
        }
    }
    Ok(Some(ManagedAssignmentInstall::Unchanged))
}

pub(crate) fn controller_withdrew_assignment(
    data_dir: &Path,
    connection: &Connection,
    consent_at: i64,
) -> Result<()> {
    withdraw_managed_assignments(data_dir, connection, Some(consent_at))
}

fn withdraw_managed_assignments(
    data_dir: &Path,
    connection: &Connection,
    blocked_consent_at: Option<i64>,
) -> Result<()> {
    let mut state = load_managed_state(data_dir)?.unwrap_or_default();
    let assignments = [state.current.take(), state.successor.take()];
    state.blocked_consent_at = blocked_consent_at.or(state.blocked_consent_at);
    persist_managed_state(data_dir, &state)?;
    let metadata_result = mark_assignment_metadata_revoked(connection);
    for assignment in assignments.into_iter().flatten() {
        remove_material_generation(data_dir, &assignment);
    }
    metadata_result
}

fn promote_managed_successor(
    data_dir: &Path,
    acknowledgement: AcknowledgeRelayAssignmentRequest,
) -> Result<()> {
    acknowledgement.validate()?;
    let mut state = load_managed_state(data_dir)?.context("managed relay state is missing")?;
    let successor = state
        .successor
        .take()
        .context("relay acknowledgement has no installed successor")?;
    if managed_acknowledgement(&successor)? != acknowledgement {
        bail!("relay acknowledgement does not match the registered successor");
    }
    let predecessor = state.current.replace(successor.clone());
    persist_managed_state(data_dir, &state)?;
    let connection = open_database(data_dir, false)?;
    let metadata_result = persist_assignment_metadata(&connection, &successor);
    if let Some(predecessor) = predecessor {
        remove_material_generation(data_dir, &predecessor);
    }
    metadata_result
}

fn managed_acknowledgement(
    assignment: &StoredAssignment,
) -> Result<AcknowledgeRelayAssignmentRequest> {
    let acknowledgement = AcknowledgeRelayAssignmentRequest {
        grant_id: assignment
            .grant_id
            .context("managed relay assignment has no grant identity")?,
        generation: assignment
            .generation
            .context("managed relay assignment has no generation")?,
    };
    acknowledgement.validate()?;
    Ok(acknowledgement)
}

fn load_runtime_assignments(
    connection: &Connection,
    data_dir: &Path,
) -> Result<Vec<StoredAssignment>> {
    if let Some(mut state) = load_managed_state(data_dir)? {
        let now = OffsetDateTime::now_utc();
        let mut changed = false;
        for slot in [&mut state.current, &mut state.successor] {
            if slot
                .as_ref()
                .is_some_and(|assignment| assignment.expires_at.as_datetime() <= now)
            {
                if let Some(expired) = slot.take() {
                    remove_material_generation(data_dir, &expired);
                }
                changed = true;
            }
        }
        if changed {
            persist_managed_state(data_dir, &state)?;
            if state.current.is_none() && state.successor.is_none() {
                mark_assignment_metadata_revoked(connection)?;
            }
        }
        let registration = crate::load_sync_registration(connection)?;
        let mut assignments = Vec::with_capacity(2);
        for assignment in [state.current, state.successor].into_iter().flatten() {
            verify_persisted_managed_assignment(data_dir, &registration, &assignment)?;
            assignments.push(assignment);
        }
        return Ok(assignments);
    }
    Ok(load_active_assignment(connection)?.into_iter().collect())
}

fn load_managed_state(data_dir: &Path) -> Result<Option<ManagedRelayState>> {
    let path = data_dir.join(MANAGED_STATE_FILE);
    if !path.exists() {
        return Ok(None);
    }
    ensure_regular_owner_only(&path)?;
    let bytes = read_bounded(&path, MAX_ASSIGNMENT_BYTES)?;
    let state: ManagedRelayState =
        serde_json::from_slice(&bytes).context("managed relay state is invalid")?;
    if state.schema_version != MANAGED_STATE_SCHEMA_VERSION {
        bail!("managed relay state schema is unsupported");
    }
    if state.blocked_consent_at.is_some_and(|value| value < 0) {
        bail!("managed relay consent marker is invalid");
    }
    for assignment in [state.current.as_ref(), state.successor.as_ref()]
        .into_iter()
        .flatten()
    {
        validate_stored_managed_assignment_shape(assignment)?;
    }
    if let (Some(current), Some(successor)) = (&state.current, &state.successor) {
        if assignment_generation(current) >= assignment_generation(successor)
            || current.logical_route_id != successor.logical_route_id
        {
            bail!("managed relay generations are not strictly ordered");
        }
    }
    Ok(Some(state))
}

fn persist_managed_state(data_dir: &Path, state: &ManagedRelayState) -> Result<()> {
    if state.schema_version != MANAGED_STATE_SCHEMA_VERSION {
        bail!("managed relay state schema is unsupported");
    }
    let bytes = serde_json::to_vec(state).context("failed to encode managed relay state")?;
    atomic_write_owner_only(&data_dir.join(MANAGED_STATE_FILE), &bytes)
}

fn validate_stored_managed_assignment_shape(assignment: &StoredAssignment) -> Result<()> {
    let grant_id = assignment
        .grant_id
        .context("managed relay assignment has no grant identity")?;
    if assignment.generation.is_none()
        || assignment.logical_route_id.is_none()
        || assignment.limits.is_none()
        || assignment.material_generation != grant_id.to_string()
        || assignment.route_id != grant_id.to_string()
        || assignment.relay_address.port() == 0
        || !assignment
            .artifact_digest
            .as_deref()
            .is_some_and(is_sha256_digest)
        || !is_sha256_digest(&assignment.material_digest)
    {
        bail!("managed relay assignment metadata shape is invalid");
    }
    Ok(())
}

fn verify_controller_assignment(
    registration: &SyncRegistration,
    assignment: &SignedRelayAssignment,
) -> Result<()> {
    assignment
        .validate()
        .context("controller relay assignment is invalid")?;
    if assignment.header.network_id != registration.network
        || assignment.header.node_id != registration.node
    {
        bail!("controller relay assignment is bound to another node or network");
    }
    let expected_key_id = ed25519_signing_key_id(&registration.controller_signing_public_key)
        .context("pinned controller signing public key is invalid")?;
    if assignment.signing_key_id != expected_key_id {
        bail!("controller relay assignment signing key identity is invalid");
    }
    verify_relay_assignment_signature(assignment, &registration.controller_signing_public_key)
        .context("controller relay assignment signature is invalid")?;
    let now = OffsetDateTime::now_utc();
    if now < assignment.header.not_before.as_datetime()
        || now >= assignment.header.expires_at.as_datetime()
    {
        bail!("controller relay assignment is outside its strict validity window");
    }
    Ok(())
}

fn verify_persisted_managed_assignment(
    data_dir: &Path,
    registration: &SyncRegistration,
    stored: &StoredAssignment,
) -> Result<()> {
    let artifact_path = data_dir
        .join(MATERIAL_DIRECTORY)
        .join(&stored.material_generation)
        .join(MANAGED_ASSIGNMENT_FILE);
    ensure_regular_owner_only(&artifact_path)?;
    let artifact = read_bounded(&artifact_path, MAX_MANAGED_ASSIGNMENT_BYTES)?;
    if stored.artifact_digest.as_deref() != Some(sha256_prefixed(&artifact).as_str()) {
        bail!("stored relay assignment artifact digest is invalid");
    }
    let assignment: SignedRelayAssignment =
        serde_json::from_slice(&artifact).context("stored relay assignment artifact is invalid")?;
    verify_controller_assignment(registration, &assignment)?;
    if stored.grant_id != Some(assignment.header.grant_id)
        || stored.logical_route_id != Some(assignment.header.route_id)
        || stored.generation != Some(assignment.header.generation)
        || stored.endpoint_id != assignment.header.endpoint_id
        || stored.route_id != assignment.header.registration_route_id()
        || stored.relay_server_name != assignment.header.tls_server_name
        || stored.public_address != assignment.header.public_host
        || stored.public_port != assignment.header.public_port
        || stored.expires_at != assignment.header.expires_at
        || stored.limits != Some(assignment.header.limits)
        || stored.relay_address.port() != assignment.header.tunnel_port
        || assignment
            .header
            .tunnel_host
            .parse::<IpAddr>()
            .is_ok_and(|ip| stored.relay_address.ip() != ip)
    {
        bail!("stored relay assignment metadata does not match its signed artifact");
    }
    let material = read_installed_material(data_dir, stored)?;
    if material_digest(&material) != stored.material_digest {
        bail!("stored relay assignment material digest is invalid");
    }
    Ok(())
}

async fn resolve_relay_address(host: &str, port: u16) -> Result<SocketAddr> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(SocketAddr::new(ip, port));
    }
    tokio::time::timeout(
        std::time::Duration::from_secs(10),
        tokio::net::lookup_host((host, port)),
    )
    .await
    .context("relay tunnel hostname resolution timed out")?
    .context("relay tunnel hostname could not be resolved")?
    .next()
    .context("relay tunnel hostname returned no addresses")
}

fn persist_assignment_metadata(
    connection: &Connection,
    candidate: &StoredAssignment,
) -> Result<()> {
    let now = unix_timestamp()?;
    connection.execute(
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
            candidate.route_id,
            candidate.relay_address.to_string(),
            candidate.relay_server_name,
            candidate.public_address,
            i64::from(candidate.public_port),
            candidate.expires_at.as_datetime().unix_timestamp(),
            candidate.material_generation,
            candidate.material_digest,
            now,
        ],
    )?;
    Ok(())
}

fn mark_assignment_metadata_revoked(connection: &Connection) -> Result<()> {
    let now = unix_timestamp()?;
    connection.execute(
        "UPDATE relay_assignment
         SET state = 'revoked', material_generation = NULL, material_digest = NULL,
             revoked_at = ?1, updated_at = ?1
         WHERE singleton = 1 AND state = 'active'",
        [now],
    )?;
    Ok(())
}

fn read_installed_material(data_dir: &Path, assignment: &StoredAssignment) -> Result<Material> {
    let directory = data_dir
        .join(MATERIAL_DIRECTORY)
        .join(&assignment.material_generation);
    Ok(Material {
        route_token: read_private_material(&directory.join("route-token"))?,
        certificate: read_private_material(&directory.join("node-cert.pem"))?,
        private_key: read_private_material(&directory.join("node-key.pem"))?,
        ca: read_bounded(&directory.join("relay-ca.pem"), MAX_MATERIAL_BYTES)?,
    })
}

fn read_private_material(path: &Path) -> Result<Vec<u8>> {
    ensure_regular_owner_only(path)?;
    read_bounded(path, MAX_MATERIAL_BYTES)
}

fn remove_material_generation(data_dir: &Path, assignment: &StoredAssignment) {
    let _ = fs::remove_dir_all(
        data_dir
            .join(MATERIAL_DIRECTORY)
            .join(&assignment.material_generation),
    );
}

fn sha256_prefixed(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}

fn is_sha256_digest(value: &str) -> bool {
    value.len() == 71
        && value.starts_with("sha256:")
        && value[7..]
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
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
    let managed_state_present = load_managed_state(data_dir)?.is_some();
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
    if managed_state_present {
        clear_managed_state_for_manual(data_dir)?;
    }
    if let Some(previous) = previous_generation {
        if previous != generation {
            let _ = fs::remove_dir_all(data_dir.join(MATERIAL_DIRECTORY).join(previous));
        }
    }
    load_status(&connection)
}

fn clear_managed_state_for_manual(data_dir: &Path) -> Result<()> {
    let Some(state) = load_managed_state(data_dir)? else {
        return Ok(());
    };
    let path = data_dir.join(MANAGED_STATE_FILE);
    fs::remove_file(&path).context("failed to remove managed relay pointer")?;
    fs::File::open(data_dir)?.sync_all()?;
    for assignment in [state.current, state.successor].into_iter().flatten() {
        remove_material_generation(data_dir, &assignment);
    }
    Ok(())
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
                grant_id: None,
                logical_route_id: None,
                generation: None,
                artifact_digest: None,
                limits: None,
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
        max_streams: assignment
            .limits
            .map_or(128, |limits| usize::from(limits.max_concurrent_streams)),
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

impl Material {
    fn from_controller(value: RelayAssignmentMaterial) -> Self {
        Self {
            route_token: value.route_token.into_inner().into_bytes(),
            certificate: value.client_certificate_pem.into_inner().into_bytes(),
            private_key: value.client_private_key_pem.into_inner().into_bytes(),
            ca: value.relay_ca_certificate_pem.into_bytes(),
        }
    }
}

impl Drop for Material {
    fn drop(&mut self) {
        use zeroize::Zeroize as _;
        self.route_token.zeroize();
        self.certificate.zeroize();
        self.private_key.zeroize();
        self.ca.zeroize();
    }
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
        grant_id: None,
        logical_route_id: None,
        generation: None,
        artifact_digest: None,
        limits: None,
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
        configure_relay, connector_config, controller_withdrew_assignment, has_managed_assignment,
        install_controller_assignment, load_managed_state, managed_acknowledgement,
        promote_managed_successor, provider_relay_consent_for_data_dir, revoke_relay,
        validate_stored_managed_assignment_shape, ManagedAssignmentInstall, RelayAssignmentState,
        RelaySupervisor, RelayTarget, RunningRelay, StoredAssignment, MANAGED_ASSIGNMENT_FILE,
        MATERIAL_DIRECTORY,
    };
    use crate::{
        initialize, load_sync_registration, open_database, set_owner_only, unix_timestamp, Identity,
    };
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine as _;
    use control_protocol::crypto::{
        ed25519_signing_key_id, Ed25519PublicKey, Ed25519Signature, X25519PublicKey,
    };
    use control_protocol::id::{
        ControllerInstanceId, EndpointId, NetworkId, NodeId, NodeInvitationId, NodeKeyId,
        RelayGeneration, RelayGrantId, RelayId, RelayRouteId, Revision, SequenceNumber, Timestamp,
    };
    use control_protocol::node::{NodeHeartbeat, NodeRuntimeState, RevisionProgress};
    use control_protocol::relay::{
        encrypt_relay_material, relay_assignment_transcript, RelayAssignmentHeader,
        RelayAssignmentMaterial, RelayLimits, SignedRelayAssignment, RELAY_SCHEMA_VERSION,
    };
    use control_protocol::secret::Secret;
    use ed25519_dalek::{Signer as _, SigningKey};
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
    use tokio::sync::watch;
    use tokio_util::sync::CancellationToken;
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
            grant_id: None,
            logical_route_id: None,
            generation: None,
            artifact_digest: None,
            limits: None,
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

    #[test]
    fn managed_generation_paths_are_exact_grant_ids() {
        let grant_id = RelayGrantId::new();
        let assignment = StoredAssignment {
            endpoint_id: EndpointId::new(),
            route_id: grant_id.to_string(),
            relay_address: "203.0.113.1:9443".parse().unwrap(),
            relay_server_name: "relay.example".to_owned(),
            public_address: "relay.example".to_owned(),
            public_port: 443,
            expires_at: Timestamp::from_datetime(OffsetDateTime::now_utc() + Duration::hours(1)),
            material_generation: "../outside".to_owned(),
            material_digest: format!("sha256:{}", "1".repeat(64)),
            grant_id: Some(grant_id),
            logical_route_id: Some(RelayRouteId::new()),
            generation: Some(RelayGeneration::new(1).unwrap()),
            artifact_digest: Some(format!("sha256:{}", "2".repeat(64))),
            limits: Some(RelayLimits {
                max_concurrent_streams: 1,
                max_bytes_per_second: 1_024,
                max_bytes_per_connection: 1_048_576,
                monthly_byte_limit: 1_048_576,
            }),
        };
        assert!(validate_stored_managed_assignment_shape(&assignment).is_err());
    }

    #[tokio::test]
    async fn controller_assignment_rejects_wrong_binding_and_wrong_installation_hpke() {
        let directory = tempfile::tempdir().unwrap();
        let data_dir = directory.path().join("node-state");
        let controller_key = SigningKey::from_bytes(&[31_u8; 32]);
        let fixture = seed_controller_enrollment(&data_dir, &controller_key);
        let pki = TestPki::new(directory.path());
        let connection = open_database(&data_dir, false).unwrap();
        let registration = load_sync_registration(&connection).unwrap();
        let identity = Identity::load(&connection, &data_dir).unwrap();
        let route_id = RelayRouteId::new();

        let mut wrong_node = signed_controller_assignment(
            &identity.x25519_public().unwrap(),
            &controller_key,
            fixture.network,
            NodeId::new(),
            route_id,
            1,
            &pki,
        );
        resign_assignment(&controller_key, &mut wrong_node);
        let mut connection = connection;
        let error = install_controller_assignment(
            &data_dir,
            &mut connection,
            &registration,
            &identity,
            &wrong_node,
        )
        .await
        .unwrap_err();
        assert!(error.to_string().contains("another node or network"));

        let wrong_recipient: X25519PublicKey = URL_SAFE_NO_PAD.encode([47_u8; 32]).parse().unwrap();
        let wrong_hpke = signed_controller_assignment(
            &wrong_recipient,
            &controller_key,
            fixture.network,
            fixture.node,
            route_id,
            1,
            &pki,
        );
        let error = install_controller_assignment(
            &data_dir,
            &mut connection,
            &registration,
            &identity,
            &wrong_hpke,
        )
        .await
        .unwrap_err();
        assert!(error.to_string().contains("cannot be decrypted"));
        assert!(!has_managed_assignment(&data_dir).unwrap());
    }

    #[allow(clippy::too_many_lines)]
    #[tokio::test]
    async fn managed_rotation_coexists_until_registered_ack_then_cuts_over_atomically() {
        let directory = tempfile::tempdir().unwrap();
        let data_dir = directory.path().join("node-state");
        let controller_key = SigningKey::from_bytes(&[41_u8; 32]);
        let fixture = seed_controller_enrollment(&data_dir, &controller_key);
        let pki = TestPki::new(directory.path());
        let mut connection = open_database(&data_dir, false).unwrap();
        let registration = load_sync_registration(&connection).unwrap();
        let identity = Identity::load(&connection, &data_dir).unwrap();
        let route_id = RelayRouteId::new();
        let first = signed_controller_assignment(
            &identity.x25519_public().unwrap(),
            &controller_key,
            fixture.network,
            fixture.node,
            route_id,
            1,
            &pki,
        );
        assert_eq!(
            install_controller_assignment(
                &data_dir,
                &mut connection,
                &registration,
                &identity,
                &first,
            )
            .await
            .unwrap(),
            ManagedAssignmentInstall::Installed
        );
        let first_stored = load_managed_state(&data_dir)
            .unwrap()
            .unwrap()
            .successor
            .unwrap();
        promote_managed_successor(&data_dir, managed_acknowledgement(&first_stored).unwrap())
            .unwrap();

        let second = signed_controller_assignment(
            &identity.x25519_public().unwrap(),
            &controller_key,
            fixture.network,
            fixture.node,
            route_id,
            2,
            &pki,
        );
        install_controller_assignment(
            &data_dir,
            &mut connection,
            &registration,
            &identity,
            &second,
        )
        .await
        .unwrap();
        let state = load_managed_state(&data_dir).unwrap().unwrap();
        let current = state.current.unwrap();
        let successor = state.successor.unwrap();
        let database = fs::read(data_dir.join("node-host.sqlite3")).unwrap();
        assert!(!contains_bytes(
            &database,
            URL_SAFE_NO_PAD.encode([7_u8; 32]).as_bytes()
        ));
        assert!(!contains_bytes(&database, &pki.client_key_bytes));
        assert_eq!(current.generation.unwrap().get(), 1);
        assert_eq!(successor.generation.unwrap().get(), 2);
        for assignment in [&current, &successor] {
            assert!(data_dir
                .join(MATERIAL_DIRECTORY)
                .join(&assignment.material_generation)
                .join(MANAGED_ASSIGNMENT_FILE)
                .is_file());
        }

        let mut supervisor = RelaySupervisor::new();
        assert!(supervisor
            .acknowledgement_candidate(&data_dir)
            .unwrap()
            .is_none());
        let (status_tx, status_rx) = watch::channel(relay_server::ConnectorStatus::Registered);
        let cancellation = CancellationToken::new();
        let task_cancellation = cancellation.clone();
        let task = tokio::spawn(async move {
            task_cancellation.cancelled().await;
        });
        supervisor.running.push(RunningRelay {
            assignment: successor.clone(),
            target: RelayTarget {
                revision: Revision::new(1).unwrap(),
                admission_port: 1,
            },
            status: status_rx,
            registered_at: None,
            cancellation,
            task,
        });
        let acknowledgement = supervisor
            .acknowledgement_candidate(&data_dir)
            .unwrap()
            .unwrap();
        assert_eq!(acknowledgement.grant_id, second.header.grant_id);
        drop(status_tx);
        RelaySupervisor::acknowledgement_succeeded(&data_dir, acknowledgement).unwrap();
        supervisor.shutdown().await;

        let state = load_managed_state(&data_dir).unwrap().unwrap();
        assert!(state.successor.is_none());
        assert_eq!(state.current.as_ref().unwrap().generation.unwrap().get(), 2);
        assert!(!data_dir
            .join(MATERIAL_DIRECTORY)
            .join(&current.material_generation)
            .exists());

        let stale_assignment = signed_controller_assignment(
            &identity.x25519_public().unwrap(),
            &controller_key,
            fixture.network,
            fixture.node,
            route_id,
            1,
            &pki,
        );
        assert_eq!(
            install_controller_assignment(
                &data_dir,
                &mut connection,
                &registration,
                &identity,
                &stale_assignment,
            )
            .await
            .unwrap(),
            ManagedAssignmentInstall::Stale
        );

        let mut restarted = RelaySupervisor::new();
        restarted
            .reconcile(
                &data_dir,
                Some(RelayTarget {
                    revision: Revision::new(1).unwrap(),
                    admission_port: 1,
                }),
            )
            .await
            .unwrap();
        assert_eq!(restarted.running.len(), 1);
        restarted.shutdown().await;

        controller_withdrew_assignment(
            &data_dir,
            &connection,
            provider_relay_consent_for_data_dir(&data_dir, &connection)
                .unwrap()
                .unwrap(),
        )
        .unwrap();
        assert!(!has_managed_assignment(&data_dir).unwrap());
        assert!(fs::read_dir(data_dir.join(MATERIAL_DIRECTORY))
            .unwrap()
            .next()
            .is_none());
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
                managed_routes: None,
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
                    monthly_byte_limit: None,
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

    #[derive(Clone, Copy)]
    struct ControllerFixture {
        network: NetworkId,
        node: NodeId,
    }

    fn seed_controller_enrollment(
        data_dir: &Path,
        controller_key: &SigningKey,
    ) -> ControllerFixture {
        initialize(data_dir, "https://controller.example").unwrap();
        let network = NetworkId::new();
        let node = NodeId::new();
        let invitation_id = NodeInvitationId::new();
        let controller_public: Ed25519PublicKey = URL_SAFE_NO_PAD
            .encode(controller_key.verifying_key().to_bytes())
            .parse()
            .unwrap();
        let connection = open_database(data_dir, false).unwrap();
        connection
            .execute(
                "INSERT INTO enrollment_registration(
                    singleton, invitation_id, network_id, node_id, controller_instance_id,
                    controller_fingerprint, controller_signing_public_key, credential_key_id,
                    credential_mode, credential_expires_at, enrolled_at
                 ) VALUES (1, ?1, ?2, ?3, ?4, ?5, ?6, ?7, 'signedRequest', ?8, ?9)",
                params![
                    invitation_id.to_string(),
                    network.to_string(),
                    node.to_string(),
                    ControllerInstanceId::new().to_string(),
                    format!("sha256:{}", "1".repeat(64)),
                    controller_public.as_str(),
                    NodeKeyId::new().to_string(),
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
                params![invitation_id.to_string(), unix_timestamp().unwrap()],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO relay_provider_consent(singleton, policy_version, accepted_at)
                 VALUES (1, '2026-07-11-relay-v1', ?1)",
                [unix_timestamp().unwrap()],
            )
            .unwrap();
        ControllerFixture { network, node }
    }

    fn signed_controller_assignment(
        recipient: &X25519PublicKey,
        controller_key: &SigningKey,
        network: NetworkId,
        node: NodeId,
        route_id: RelayRouteId,
        generation: i64,
        pki: &TestPki,
    ) -> SignedRelayAssignment {
        let issued_at = Timestamp::from_datetime(OffsetDateTime::now_utc() - Duration::seconds(1));
        let header = RelayAssignmentHeader {
            schema_version: RELAY_SCHEMA_VERSION,
            network_id: network,
            node_id: node,
            relay_id: RelayId::new(),
            route_id,
            grant_id: RelayGrantId::new(),
            generation: RelayGeneration::new(generation).unwrap(),
            endpoint_id: EndpointId::new(),
            public_host: "relay.example.test".to_string(),
            public_port: 8_443,
            tunnel_host: "127.0.0.1".to_string(),
            tunnel_port: 9_443,
            tls_server_name: "localhost".to_string(),
            issued_at,
            not_before: issued_at,
            expires_at: Timestamp::from_datetime(OffsetDateTime::now_utc() + Duration::hours(1)),
            limits: RelayLimits {
                max_concurrent_streams: 4,
                max_bytes_per_second: 1_000_000,
                max_bytes_per_connection: 10_000_000,
                monthly_byte_limit: 100_000_000,
            },
        };
        let material = RelayAssignmentMaterial {
            route_token: Secret::new(URL_SAFE_NO_PAD.encode([7_u8; 32])),
            client_certificate_pem: Secret::new(
                String::from_utf8(pki.client_cert_bytes.clone()).unwrap(),
            ),
            client_private_key_pem: Secret::new(
                String::from_utf8(pki.client_key_bytes.clone()).unwrap(),
            ),
            relay_ca_certificate_pem: fs::read_to_string(&pki.ca_path).unwrap(),
        };
        let controller_public: Ed25519PublicKey = URL_SAFE_NO_PAD
            .encode(controller_key.verifying_key().to_bytes())
            .parse()
            .unwrap();
        let mut assignment = SignedRelayAssignment {
            encrypted_material: encrypt_relay_material(recipient, &header, &material).unwrap(),
            header,
            signing_key_id: ed25519_signing_key_id(&controller_public).unwrap(),
            signature: URL_SAFE_NO_PAD.encode([0_u8; 64]).parse().unwrap(),
        };
        resign_assignment(controller_key, &mut assignment);
        assignment
    }

    fn resign_assignment(controller_key: &SigningKey, assignment: &mut SignedRelayAssignment) {
        assignment.signature = URL_SAFE_NO_PAD
            .encode(
                controller_key
                    .sign(&relay_assignment_transcript(assignment).unwrap())
                    .to_bytes(),
            )
            .parse::<Ed25519Signature>()
            .unwrap();
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
