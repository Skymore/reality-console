use crate::router_protocol::{
    CreatedMapping, DurableMapping, MappingBackend, MappingFailureCode, MappingRequest,
    SystemMappingBackend,
};
use crate::{migrate, open_database, timestamp_from_unix, unix_timestamp, DataDirLock};
use anyhow::{bail, Context as _, Result};
use control_protocol::id::{EndpointId, NodeId, Revision, Timestamp};
use control_protocol::node::{EndpointCandidate, EndpointMode, EndpointSource};
use rusqlite::{params, Connection, OptionalExtension as _, TransactionBehavior};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::path::Path;
use std::str::FromStr as _;
use std::time::{Duration, Instant};
use uuid::Uuid;

const MIN_RETRY_DELAY: Duration = Duration::from_secs(30);
const MAX_RETRY_DELAY: Duration = Duration::from_secs(15 * 60);

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RouterMappingPolicy {
    pub enabled: bool,
    pub consented_at: Option<i64>,
    pub last_error_code: Option<String>,
    pub last_attempt_at: Option<i64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct MappingTarget {
    pub revision: Revision,
    pub internal_port: u16,
}

/// Safe provider-facing router-mapping lifecycle state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum RouterMappingState {
    /// Automatic router changes were not enabled by the provider.
    Disabled,
    /// Consent exists, but no current finite lease is active.
    Waiting,
    /// A finite mapping lease is current but still requires external verification.
    Active,
    /// The last recorded lease has expired.
    Expired,
    /// The node is removing its owned mapping.
    Releasing,
    /// The last owned mapping failed and is not publishable.
    Failed,
}

/// Non-secret mapping status suitable for the local UI and CLI.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RouterMappingStatus {
    /// Whether the provider enabled automatic finite router mapping.
    pub enabled: bool,
    /// Current local lease lifecycle state.
    pub state: RouterMappingState,
    /// Protocol that owns the current or most recent mapping.
    pub source: Option<EndpointSource>,
    /// Public address returned by the router, when current.
    pub external_address: Option<String>,
    /// Public TCP port returned by the router, when current.
    pub external_port: Option<u16>,
    /// Finite lease expiry, when current.
    pub lease_expires_at: Option<Timestamp>,
    /// Stable, secret-free failure code for the most recent mapping.
    pub last_error_code: Option<String>,
}

pub(crate) fn configure_bootstrap_policy(data_dir: &Path, enabled: bool) -> Result<()> {
    let _lock = DataDirLock::acquire(data_dir, false)?;
    let mut connection = open_database(data_dir, false)?;
    migrate(&mut connection)?;
    let now = unix_timestamp()?;
    let updated = connection.execute(
        "UPDATE provider_network_policy
         SET automatic_router_mapping_enabled = ?1,
             router_mapping_consented_at = CASE
                 WHEN ?1 = 1 THEN COALESCE(router_mapping_consented_at, ?2)
                 ELSE router_mapping_consented_at
             END,
             last_mapping_error_code = NULL,
             last_mapping_attempt_at = NULL,
             updated_at = ?2
         WHERE singleton = 1",
        params![i64::from(enabled), now],
    )?;
    if updated != 1 {
        bail!("provider network policy is missing");
    }
    Ok(())
}

pub(crate) fn load_policy(connection: &Connection) -> Result<RouterMappingPolicy> {
    connection
        .query_row(
            "SELECT automatic_router_mapping_enabled, router_mapping_consented_at,
                    last_mapping_error_code,
                    last_mapping_attempt_at
             FROM provider_network_policy WHERE singleton = 1",
            [],
            |row| {
                Ok(RouterMappingPolicy {
                    enabled: row.get::<_, i64>(0)? != 0,
                    consented_at: row.get(1)?,
                    last_error_code: row.get(2)?,
                    last_attempt_at: row.get(3)?,
                })
            },
        )
        .context("provider network policy is missing")
}

pub(crate) fn load_status(connection: &Connection) -> Result<RouterMappingStatus> {
    let policy = load_policy(connection)?;
    if !policy.enabled {
        return Ok(empty_status(false, RouterMappingState::Disabled));
    }
    let row = connection
        .query_row(
            "SELECT source, external_address, external_port, lease_expires_at,
                    state, failure_code
             FROM router_mapping_leases
             ORDER BY
                CASE WHEN state IN ('active', 'releasing') THEN 0 ELSE 1 END,
                created_at DESC, mapping_id DESC
             LIMIT 1",
            [],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, Option<String>>(5)?,
                ))
            },
        )
        .optional()?;
    let Some((source, address, port, expires_at, state, failure_code)) = row else {
        let state = if policy.last_error_code.is_some() {
            RouterMappingState::Failed
        } else {
            RouterMappingState::Waiting
        };
        let mut status = empty_status(true, state);
        status.last_error_code = policy.last_error_code;
        return Ok(status);
    };
    let now = unix_timestamp()?;
    let lifecycle = match state.as_str() {
        "active" if expires_at > now => RouterMappingState::Active,
        "active" => RouterMappingState::Expired,
        "releasing" => RouterMappingState::Releasing,
        "failed" | "abandoned" => RouterMappingState::Failed,
        "released" if policy.last_error_code.is_some() => RouterMappingState::Failed,
        "released" => RouterMappingState::Waiting,
        _ => bail!("stored router mapping state is invalid"),
    };
    let current = matches!(
        lifecycle,
        RouterMappingState::Active | RouterMappingState::Releasing
    );
    Ok(RouterMappingStatus {
        enabled: true,
        state: lifecycle,
        source: current.then(|| parse_source(&source)).transpose()?,
        external_address: current.then_some(address),
        external_port: current
            .then(|| u16::try_from(port).context("stored external port is invalid"))
            .transpose()?,
        lease_expires_at: current
            .then(|| timestamp_from_unix(expires_at))
            .transpose()?,
        last_error_code: policy.last_error_code.or(failure_code),
    })
}

pub(crate) fn load_heartbeat_candidates(
    connection: &Connection,
    applied_revision: Option<Revision>,
) -> Result<Vec<EndpointCandidate>> {
    let Some(applied_revision) = applied_revision else {
        return Ok(Vec::new());
    };
    if !load_policy(connection)?.enabled {
        return Ok(Vec::new());
    }
    let now = unix_timestamp()?;
    let mut statement = connection.prepare(
        "SELECT endpoint_id, source, external_address, external_port,
                applied_revision, lease_started_at, lease_expires_at
         FROM router_mapping_leases
         WHERE state = 'active' AND applied_revision = ?1 AND lease_expires_at > ?2
         ORDER BY endpoint_id",
    )?;
    let rows = statement.query_map(params![applied_revision.get(), now], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, i64>(3)?,
            row.get::<_, i64>(4)?,
            row.get::<_, i64>(5)?,
            row.get::<_, i64>(6)?,
        ))
    })?;
    let mut candidates = Vec::new();
    for row in rows {
        let (endpoint_id, source, address, port, revision, observed_at, expires_at) = row?;
        candidates.push(EndpointCandidate {
            endpoint_id: EndpointId::from_str(&endpoint_id)
                .context("stored router endpoint identity is invalid")?,
            mode: EndpointMode::Direct,
            source: parse_source(&source)?,
            address,
            port: u16::try_from(port).context("stored router external port is invalid")?,
            applied_revision: Revision::new(revision)
                .context("stored router mapping revision is invalid")?,
            observed_at: timestamp_from_unix(observed_at)
                .context("stored router mapping observation time is invalid")?,
            expires_at: Some(
                timestamp_from_unix(expires_at)
                    .context("stored router mapping expiry is invalid")?,
            ),
        });
    }
    Ok(candidates)
}

pub(crate) type RouterMappingSupervisor = MappingSupervisor<SystemMappingBackend>;

pub(crate) struct MappingSupervisor<B> {
    backend: B,
    consecutive_failures: u32,
    next_attempt: Option<Instant>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReleaseOutcome {
    Released,
    Abandoned,
    RetryPending(MappingFailureCode),
}

impl MappingSupervisor<SystemMappingBackend> {
    pub(crate) fn new() -> Self {
        Self::with_backend(SystemMappingBackend)
    }
}

impl<B> MappingSupervisor<B>
where
    B: MappingBackend,
{
    fn with_backend(backend: B) -> Self {
        Self {
            backend,
            consecutive_failures: 0,
            next_attempt: None,
        }
    }

    pub(crate) async fn reconcile(
        &mut self,
        data_dir: &Path,
        target: Option<MappingTarget>,
    ) -> Result<()> {
        let (policy, mut current, node_id) = load_supervision_state(data_dir)?;
        if current
            .as_ref()
            .is_some_and(|mapping| !self.backend.topology_matches(&mapping.material))
        {
            let mapping = current.as_ref().expect("checked current mapping");
            abandon_without_release(
                data_dir,
                &mapping.mapping_id,
                MappingFailureCode::TopologyChanged.as_str(),
            )?;
            current = None;
            self.reset_backoff();
        }
        if let Some(current_mapping) = current.as_ref() {
            let must_release = current_mapping.releasing
                || !policy.enabled
                || target.is_none_or(|target| {
                    target.revision != current_mapping.applied_revision
                        || target.internal_port != current_mapping.material.internal_port
                })
                || current_mapping.lease_expires_at <= unix_timestamp()?;
            if must_release {
                if current_mapping.releasing && !self.attempt_is_due(&policy, unix_timestamp()?) {
                    return Ok(());
                }
                if matches!(
                    self.release_current(data_dir, current_mapping).await?,
                    ReleaseOutcome::RetryPending(_)
                ) {
                    return Ok(());
                }
                current = None;
            }
        }
        let Some(target) = target.filter(|_| policy.enabled) else {
            self.reset_backoff();
            return Ok(());
        };
        if current.is_none()
            && policy.last_error_code.as_deref() == Some(MappingFailureCode::ReleaseFailed.as_str())
        {
            return Ok(());
        }
        if !self.attempt_is_due(&policy, unix_timestamp()?) {
            return Ok(());
        }

        if let Some(current) = current.as_ref() {
            if !renewal_is_due(current, unix_timestamp()?)? {
                return Ok(());
            }
            record_attempt_started(data_dir)?;
            match self.backend.renew(&current.material).await {
                Ok(created) => {
                    if let Err(error) =
                        persist_mapping(data_dir, target, &created, Some(&current.mapping_id))
                    {
                        mark_releasing(data_dir, &current.mapping_id)?;
                        return Err(error).context(
                            "renewed router mapping could not be committed and was withdrawn",
                        );
                    }
                    self.reset_backoff();
                }
                Err(code) if renewal_failure_invalidates_candidate(code) => {
                    abandon_without_release(data_dir, &current.mapping_id, code.as_str())?;
                    self.reset_backoff();
                }
                Err(code) => self.record_failure(data_dir, code)?,
            }
            return Ok(());
        }

        let node_id = node_id.context("enrolled node identity is missing")?;
        record_attempt_started(data_dir)?;
        let request = MappingRequest {
            node_id,
            revision: target.revision,
            internal_port: target.internal_port,
        };
        match self.backend.create(&request).await {
            Ok(created) => {
                if let Err(error) = persist_mapping(data_dir, target, &created, None) {
                    let material = DurableMapping::from(&created);
                    if let Err(code) = self.backend.release(&material).await {
                        tracing::warn!(
                            error_code = code.as_str(),
                            "uncommitted router mapping cleanup failed; finite lease will expire"
                        );
                    }
                    return Err(error).context("new router mapping could not be committed");
                }
                self.reset_backoff();
            }
            Err(code) => self.record_failure(data_dir, code)?,
        }
        Ok(())
    }

    pub(crate) async fn shutdown(&mut self, data_dir: &Path) -> Result<()> {
        let (_, current, _) = load_supervision_state(data_dir)?;
        if let Some(current) = current.as_ref() {
            if !self.backend.topology_matches(&current.material) {
                abandon_without_release(
                    data_dir,
                    &current.mapping_id,
                    MappingFailureCode::TopologyChanged.as_str(),
                )?;
                return Ok(());
            }
            if let ReleaseOutcome::RetryPending(code) =
                self.release_current(data_dir, current).await?
            {
                bail!("router mapping shutdown failed: {}", code.as_str());
            }
        }
        Ok(())
    }

    async fn release_current(
        &mut self,
        data_dir: &Path,
        current: &StoredMapping,
    ) -> Result<ReleaseOutcome> {
        mark_releasing(data_dir, &current.mapping_id)?;
        record_attempt_started(data_dir)?;
        match self.backend.release(&current.material).await {
            Ok(()) => {
                finish_release(data_dir, &current.mapping_id, "released", None)?;
                self.reset_backoff();
                Ok(ReleaseOutcome::Released)
            }
            Err(code) => {
                let expired = current.lease_expires_at <= unix_timestamp()?;
                if expired || code == MappingFailureCode::TopologyChanged {
                    finish_release(
                        data_dir,
                        &current.mapping_id,
                        "abandoned",
                        Some(code.as_str()),
                    )?;
                    self.reset_backoff();
                    Ok(ReleaseOutcome::Abandoned)
                } else {
                    record_release_failure(data_dir, &current.mapping_id, code.as_str())?;
                    self.record_failure(data_dir, code)?;
                    Ok(ReleaseOutcome::RetryPending(code))
                }
            }
        }
    }

    fn attempt_is_due(&self, policy: &RouterMappingPolicy, now: i64) -> bool {
        if self
            .next_attempt
            .is_some_and(|deadline| Instant::now() < deadline)
        {
            return false;
        }
        policy.last_error_code.is_none()
            || policy
                .last_attempt_at
                .is_none_or(|last| now.saturating_sub(last) >= 30)
    }

    fn record_failure(&mut self, data_dir: &Path, code: MappingFailureCode) -> Result<()> {
        persist_mapping_error(data_dir, code.as_str())?;
        self.consecutive_failures = self.consecutive_failures.saturating_add(1);
        let shift = self.consecutive_failures.saturating_sub(1).min(10);
        let multiplier = 1_u32.checked_shl(shift).unwrap_or(u32::MAX);
        let delay = MIN_RETRY_DELAY
            .saturating_mul(multiplier)
            .min(MAX_RETRY_DELAY);
        self.next_attempt = Some(Instant::now() + delay);
        tracing::warn!(error_code = code.as_str(), "router mapping attempt failed");
        Ok(())
    }

    fn reset_backoff(&mut self) {
        self.consecutive_failures = 0;
        self.next_attempt = None;
    }
}

struct StoredMapping {
    mapping_id: String,
    applied_revision: Revision,
    material: DurableMapping,
    lease_started_at: i64,
    lease_expires_at: i64,
    releasing: bool,
}

struct RawStoredMapping {
    mapping_id: String,
    applied_revision: i64,
    source: String,
    gateway_address: String,
    internal_address: String,
    internal_port: i64,
    external_address: String,
    external_port: i64,
    pcp_nonce: Option<Vec<u8>>,
    upnp_description: Option<String>,
    gateway_epoch: Option<i64>,
    topology_fingerprint: Option<Vec<u8>>,
    lease_started_at: i64,
    lease_expires_at: i64,
    state: String,
}

fn load_supervision_state(
    data_dir: &Path,
) -> Result<(RouterMappingPolicy, Option<StoredMapping>, Option<NodeId>)> {
    let mut connection = open_database(data_dir, false)?;
    migrate(&mut connection)?;
    let policy = load_policy(&connection)?;
    let current = load_current_mapping(&connection)?;
    let node_id = connection
        .query_row(
            "SELECT node_id FROM enrollment_registration WHERE singleton = 1",
            [],
            |row| row.get::<_, String>(0),
        )
        .optional()?
        .map(|value| NodeId::from_str(&value).context("stored enrolled node identity is invalid"))
        .transpose()?;
    Ok((policy, current, node_id))
}

fn load_current_mapping(connection: &Connection) -> Result<Option<StoredMapping>> {
    let row = connection
        .query_row(
            "SELECT mapping_id, applied_revision, source, gateway_address,
                    internal_address, internal_port, external_address, external_port,
                    pcp_nonce, upnp_description, gateway_epoch, topology_fingerprint,
                    lease_started_at, lease_expires_at, state
             FROM router_mapping_leases
             WHERE state IN ('active', 'releasing')
             LIMIT 1",
            [],
            |row| {
                Ok(RawStoredMapping {
                    mapping_id: row.get(0)?,
                    applied_revision: row.get(1)?,
                    source: row.get(2)?,
                    gateway_address: row.get(3)?,
                    internal_address: row.get(4)?,
                    internal_port: row.get(5)?,
                    external_address: row.get(6)?,
                    external_port: row.get(7)?,
                    pcp_nonce: row.get(8)?,
                    upnp_description: row.get(9)?,
                    gateway_epoch: row.get(10)?,
                    topology_fingerprint: row.get(11)?,
                    lease_started_at: row.get(12)?,
                    lease_expires_at: row.get(13)?,
                    state: row.get(14)?,
                })
            },
        )
        .optional()?;
    let Some(row) = row else {
        return Ok(None);
    };
    let lifetime_seconds = row
        .lease_expires_at
        .checked_sub(row.lease_started_at)
        .and_then(|value| u32::try_from(value).ok())
        .filter(|value| *value > 0)
        .context("stored router mapping lifetime is invalid")?;
    let pcp_nonce = row
        .pcp_nonce
        .map(|value| {
            value
                .try_into()
                .map_err(|_| anyhow::anyhow!("stored PCP nonce is invalid"))
        })
        .transpose()?;
    let topology_fingerprint = row
        .topology_fingerprint
        .map(|value| {
            value
                .try_into()
                .map_err(|_| anyhow::anyhow!("stored router topology fingerprint is invalid"))
        })
        .transpose()?;
    Ok(Some(StoredMapping {
        mapping_id: row.mapping_id,
        applied_revision: Revision::new(row.applied_revision)
            .context("stored router mapping revision is invalid")?,
        material: DurableMapping {
            source: parse_source(&row.source)?,
            gateway_address: IpAddr::from_str(&row.gateway_address)
                .context("stored router gateway address is invalid")?,
            internal_address: IpAddr::from_str(&row.internal_address)
                .context("stored router internal address is invalid")?,
            internal_port: u16::try_from(row.internal_port)
                .context("stored router internal port is invalid")?,
            external_address: IpAddr::from_str(&row.external_address)
                .context("stored router external address is invalid")?,
            external_port: u16::try_from(row.external_port)
                .context("stored router external port is invalid")?,
            pcp_nonce,
            upnp_description: row.upnp_description,
            gateway_epoch: row
                .gateway_epoch
                .map(|value| u32::try_from(value).context("stored gateway epoch is invalid"))
                .transpose()?,
            lifetime_seconds,
            topology_fingerprint,
        },
        lease_started_at: row.lease_started_at,
        lease_expires_at: row.lease_expires_at,
        releasing: row.state == "releasing",
    }))
}

fn renewal_is_due(mapping: &StoredMapping, now: i64) -> Result<bool> {
    let lifetime = mapping
        .lease_expires_at
        .checked_sub(mapping.lease_started_at)
        .filter(|value| *value > 0)
        .context("stored router mapping lifetime is invalid")?;
    let renewal_at = mapping
        .lease_started_at
        .checked_add(lifetime / 2)
        .context("stored router mapping renewal time overflowed")?;
    Ok(now >= renewal_at)
}

const fn renewal_failure_invalidates_candidate(code: MappingFailureCode) -> bool {
    !matches!(
        code,
        MappingFailureCode::Timeout
            | MappingFailureCode::ProtocolUnavailable
            | MappingFailureCode::Unauthorized
    )
}

fn persist_mapping(
    data_dir: &Path,
    target: MappingTarget,
    created: &CreatedMapping,
    predecessor: Option<&str>,
) -> Result<()> {
    if created.lifetime_seconds == 0 || created.lifetime_seconds > 24 * 60 * 60 {
        bail!("router returned an invalid finite mapping lifetime");
    }
    if created.internal_port != target.internal_port {
        bail!("router returned a mapping for the wrong internal port");
    }
    let now = unix_timestamp()?;
    let expires_at = now
        .checked_add(i64::from(created.lifetime_seconds))
        .context("router mapping expiry overflowed")?;
    let mapping_id = Uuid::new_v4().hyphenated().to_string();
    let endpoint_id = EndpointId::new();
    let pcp_nonce = created.pcp_nonce.map(|value| value.to_vec());
    let mut connection = open_database(data_dir, false)?;
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let operation = (|| -> Result<()> {
        if let Some(predecessor) = predecessor {
            let updated = transaction.execute(
                "UPDATE router_mapping_leases
                 SET state = 'released', failure_code = NULL, ended_at = ?1, updated_at = ?1
                 WHERE mapping_id = ?2 AND state = 'active'",
                params![now, predecessor],
            )?;
            if updated != 1 {
                bail!("router mapping changed while its renewal was committing");
            }
        }
        transaction.execute(
            "INSERT INTO router_mapping_leases(
                mapping_id, endpoint_id, applied_revision, source, gateway_address,
                internal_address, internal_port, external_address, external_port,
                pcp_nonce, upnp_description, gateway_epoch, topology_fingerprint, lease_started_at,
                lease_expires_at, state, failure_code, ended_at, created_at, updated_at
             ) VALUES (
                ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12,
                ?13, ?14, ?15, 'active', NULL, NULL, ?14, ?14
             )",
            params![
                mapping_id,
                endpoint_id.to_string(),
                target.revision.get(),
                source_wire(created.source)?,
                created.gateway_address.to_string(),
                created.internal_address.to_string(),
                i64::from(created.internal_port),
                created.external_address.to_string(),
                i64::from(created.external_port),
                pcp_nonce,
                created.upnp_description,
                created.gateway_epoch.map(i64::from),
                created.topology_fingerprint.to_vec(),
                now,
                expires_at,
            ],
        )?;
        transaction.execute(
            "UPDATE provider_network_policy
             SET last_mapping_error_code = NULL, last_mapping_attempt_at = ?1,
                 updated_at = ?1
             WHERE singleton = 1",
            [now],
        )?;
        Ok(())
    })();
    match operation {
        Ok(()) => transaction.commit()?,
        Err(error) => {
            transaction
                .rollback()
                .context("router mapping transaction rollback failed")?;
            return Err(error);
        }
    }
    Ok(())
}

fn record_attempt_started(data_dir: &Path) -> Result<()> {
    let connection = open_database(data_dir, false)?;
    let now = unix_timestamp()?;
    let updated = connection.execute(
        "UPDATE provider_network_policy
         SET last_mapping_attempt_at = ?1, updated_at = ?1
         WHERE singleton = 1",
        [now],
    )?;
    if updated != 1 {
        bail!("provider network policy is missing");
    }
    Ok(())
}

fn persist_mapping_error(data_dir: &Path, error_code: &str) -> Result<()> {
    let connection = open_database(data_dir, false)?;
    let now = unix_timestamp()?;
    let updated = connection.execute(
        "UPDATE provider_network_policy
         SET last_mapping_error_code = ?1, last_mapping_attempt_at = ?2,
             updated_at = ?2
         WHERE singleton = 1",
        params![error_code, now],
    )?;
    if updated != 1 {
        bail!("provider network policy is missing");
    }
    Ok(())
}

fn mark_releasing(data_dir: &Path, mapping_id: &str) -> Result<()> {
    let connection = open_database(data_dir, false)?;
    let now = unix_timestamp()?;
    let updated = connection.execute(
        "UPDATE router_mapping_leases
         SET state = 'releasing', failure_code = NULL, updated_at = ?1
         WHERE mapping_id = ?2 AND state IN ('active', 'releasing')",
        params![now, mapping_id],
    )?;
    if updated != 1 {
        bail!("current router mapping is missing");
    }
    Ok(())
}

fn finish_release(
    data_dir: &Path,
    mapping_id: &str,
    terminal_state: &str,
    error_code: Option<&str>,
) -> Result<()> {
    if !matches!(terminal_state, "released" | "abandoned") {
        bail!("invalid terminal router mapping state");
    }
    let connection = open_database(data_dir, false)?;
    let now = unix_timestamp()?;
    let updated = connection.execute(
        "UPDATE router_mapping_leases
         SET state = ?1, failure_code = ?2, ended_at = ?3, updated_at = ?3
         WHERE mapping_id = ?4 AND state = 'releasing'",
        params![terminal_state, error_code, now, mapping_id],
    )?;
    if updated != 1 {
        bail!("releasing router mapping is missing");
    }
    connection.execute(
        "UPDATE provider_network_policy
         SET last_mapping_error_code = NULL, updated_at = ?1
         WHERE singleton = 1",
        [now],
    )?;
    Ok(())
}

fn abandon_without_release(data_dir: &Path, mapping_id: &str, error_code: &str) -> Result<()> {
    let connection = open_database(data_dir, false)?;
    let now = unix_timestamp()?;
    let updated = connection.execute(
        "UPDATE router_mapping_leases
         SET state = 'abandoned', failure_code = ?1, ended_at = ?2, updated_at = ?2
         WHERE mapping_id = ?3 AND state IN ('active', 'releasing')",
        params![error_code, now, mapping_id],
    )?;
    if updated != 1 {
        bail!("router mapping changed before it could be withdrawn");
    }
    Ok(())
}

fn record_release_failure(data_dir: &Path, mapping_id: &str, error_code: &str) -> Result<()> {
    let connection = open_database(data_dir, false)?;
    let updated = connection.execute(
        "UPDATE router_mapping_leases
         SET failure_code = ?1, updated_at = ?2
         WHERE mapping_id = ?3 AND state = 'releasing'",
        params![error_code, unix_timestamp()?, mapping_id],
    )?;
    if updated != 1 {
        bail!("releasing router mapping is missing");
    }
    Ok(())
}

fn source_wire(source: EndpointSource) -> Result<&'static str> {
    match source {
        EndpointSource::Pcp => Ok("pcp"),
        EndpointSource::NatPmp => Ok("natPmp"),
        EndpointSource::Upnp => Ok("upnp"),
        EndpointSource::Manual | EndpointSource::Relay => {
            bail!("router backend returned a non-mapping endpoint source")
        }
    }
}

fn parse_source(value: &str) -> Result<EndpointSource> {
    match value {
        "pcp" => Ok(EndpointSource::Pcp),
        "natPmp" => Ok(EndpointSource::NatPmp),
        "upnp" => Ok(EndpointSource::Upnp),
        _ => bail!("stored router mapping source is invalid"),
    }
}

const fn empty_status(enabled: bool, state: RouterMappingState) -> RouterMappingStatus {
    RouterMappingStatus {
        enabled,
        state,
        source: None,
        external_address: None,
        external_port: None,
        lease_expires_at: None,
        last_error_code: None,
    }
}

#[cfg(test)]
mod tests {
    use super::{
        configure_bootstrap_policy, load_heartbeat_candidates, load_policy, MappingSupervisor,
        MappingTarget, RouterMappingState,
    };
    use crate::router_protocol::{
        CreatedMapping, DurableMapping, MappingBackend, MappingFailureCode, MappingRequest,
    };
    use crate::{open_database, status};
    use async_trait::async_trait;
    use control_protocol::id::{
        ControllerInstanceId, NetworkId, NodeId, NodeInvitationId, NodeKeyId, Revision,
        SigningKeyId,
    };
    use control_protocol::node::EndpointSource;
    use rusqlite::{params, Connection};
    use std::net::{IpAddr, Ipv4Addr};
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    #[test]
    fn bootstrap_policy_requires_a_durable_consent_time() {
        let temp = tempfile::tempdir().unwrap();
        let data_dir = temp.path().join("state");
        crate::initialize(&data_dir, "https://controller.example").unwrap();

        configure_bootstrap_policy(&data_dir, true).unwrap();

        let connection = open_database(&data_dir, false).unwrap();
        let policy = load_policy(&connection).unwrap();
        assert!(policy.enabled);
        assert!(policy.consented_at.is_some());
        let permanent_allowed: i64 = connection
            .query_row(
                "SELECT allow_permanent_upnp FROM provider_network_policy WHERE singleton = 1",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(permanent_allowed, 0);
        drop(connection);
        let current = status(&data_dir).unwrap();
        assert!(current.router_mapping.enabled);
        assert_eq!(current.router_mapping.state, RouterMappingState::Waiting);
    }

    #[derive(Default)]
    struct BackendCounts {
        creates: usize,
        renewals: usize,
        releases: usize,
    }

    struct FakeBackend {
        counts: Arc<Mutex<BackendCounts>>,
        topology_matches: Arc<AtomicBool>,
        renewal_failure: Option<MappingFailureCode>,
    }

    #[async_trait]
    impl MappingBackend for FakeBackend {
        fn topology_matches(&self, _mapping: &DurableMapping) -> bool {
            self.topology_matches.load(Ordering::Acquire)
        }

        async fn create(
            &mut self,
            _request: &MappingRequest,
        ) -> std::result::Result<CreatedMapping, MappingFailureCode> {
            self.counts.lock().unwrap().creates += 1;
            Ok(fake_created_mapping())
        }

        async fn renew(
            &mut self,
            _mapping: &DurableMapping,
        ) -> std::result::Result<CreatedMapping, MappingFailureCode> {
            self.counts.lock().unwrap().renewals += 1;
            self.renewal_failure
                .map_or_else(|| Ok(fake_created_mapping()), std::result::Result::Err)
        }

        async fn release(
            &mut self,
            _mapping: &DurableMapping,
        ) -> std::result::Result<(), MappingFailureCode> {
            self.counts.lock().unwrap().releases += 1;
            Ok(())
        }
    }

    #[tokio::test]
    async fn supervisor_creates_renews_and_releases_one_owned_mapping() {
        let (temp, data_dir, revision) = mapping_fixture();
        let counts = Arc::new(Mutex::new(BackendCounts::default()));
        let topology_matches = Arc::new(AtomicBool::new(true));
        let mut supervisor = MappingSupervisor::with_backend(FakeBackend {
            counts: Arc::clone(&counts),
            topology_matches,
            renewal_failure: None,
        });
        let target = MappingTarget {
            revision,
            internal_port: 10_443,
        };

        supervisor.reconcile(&data_dir, Some(target)).await.unwrap();
        assert_eq!(counts.lock().unwrap().creates, 1);
        let connection = Connection::open(data_dir.join("node-host.sqlite3")).unwrap();
        assert_eq!(current_mapping_count(&connection), 1);
        let first_endpoint: String = connection
            .query_row(
                "SELECT endpoint_id FROM router_mapping_leases WHERE state = 'active'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(
            load_heartbeat_candidates(&connection, Some(revision))
                .unwrap()
                .len(),
            1
        );
        let now = time::OffsetDateTime::now_utc().unix_timestamp();
        connection
            .execute(
                "UPDATE router_mapping_leases
                 SET lease_started_at = ?1, lease_expires_at = ?2
                 WHERE state = 'active'",
                params![now - 100, now + 1],
            )
            .unwrap();
        drop(connection);

        supervisor.reconcile(&data_dir, Some(target)).await.unwrap();
        assert_eq!(counts.lock().unwrap().renewals, 1);
        let connection = Connection::open(data_dir.join("node-host.sqlite3")).unwrap();
        assert_eq!(current_mapping_count(&connection), 1);
        let second_endpoint: String = connection
            .query_row(
                "SELECT endpoint_id FROM router_mapping_leases WHERE state = 'active'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_ne!(first_endpoint, second_endpoint);
        drop(connection);

        supervisor.shutdown(&data_dir).await.unwrap();
        let connection = Connection::open(data_dir.join("node-host.sqlite3")).unwrap();
        assert_eq!(current_mapping_count(&connection), 0);
        assert_eq!(counts.lock().unwrap().releases, 1);
        drop(connection);
        assert_eq!(
            status(&data_dir).unwrap().router_mapping.state,
            RouterMappingState::Waiting
        );
        drop(temp);
    }

    #[tokio::test]
    async fn failed_create_commit_cleans_up_the_unrecorded_mapping() {
        let (_temp, data_dir, revision) = mapping_fixture();
        let connection = open_database(&data_dir, false).unwrap();
        connection
            .execute_batch(
                "CREATE TRIGGER reject_router_mapping_insert
                 BEFORE INSERT ON router_mapping_leases
                 BEGIN
                    SELECT RAISE(ABORT, 'simulated mapping commit failure');
                 END;",
            )
            .unwrap();
        drop(connection);
        let counts = Arc::new(Mutex::new(BackendCounts::default()));
        let mut supervisor = MappingSupervisor::with_backend(FakeBackend {
            counts: Arc::clone(&counts),
            topology_matches: Arc::new(AtomicBool::new(true)),
            renewal_failure: None,
        });

        assert!(supervisor
            .reconcile(&data_dir, Some(mapping_target(revision)))
            .await
            .is_err());

        let counts = counts.lock().unwrap();
        assert_eq!(counts.creates, 1);
        assert_eq!(counts.releases, 1);
        drop(counts);
        let connection = open_database(&data_dir, false).unwrap();
        assert_eq!(current_mapping_count(&connection), 0);
    }

    #[tokio::test]
    async fn failed_renewal_commit_withdraws_before_releasing() {
        let (_temp, data_dir, revision) = mapping_fixture();
        let counts = Arc::new(Mutex::new(BackendCounts::default()));
        let mut supervisor = MappingSupervisor::with_backend(FakeBackend {
            counts: Arc::clone(&counts),
            topology_matches: Arc::new(AtomicBool::new(true)),
            renewal_failure: None,
        });
        let target = mapping_target(revision);
        supervisor.reconcile(&data_dir, Some(target)).await.unwrap();
        let connection = open_database(&data_dir, false).unwrap();
        let now = time::OffsetDateTime::now_utc().unix_timestamp();
        connection
            .execute(
                "UPDATE router_mapping_leases
                 SET lease_started_at = ?1, lease_expires_at = ?2
                 WHERE state = 'active'",
                params![now - 100, now + 1],
            )
            .unwrap();
        connection
            .execute_batch(
                "CREATE TRIGGER reject_router_mapping_renewal
                 BEFORE INSERT ON router_mapping_leases
                 BEGIN
                    SELECT RAISE(ABORT, 'simulated renewal commit failure');
                 END;",
            )
            .unwrap();
        drop(connection);

        assert!(supervisor.reconcile(&data_dir, Some(target)).await.is_err());
        let connection = open_database(&data_dir, false).unwrap();
        assert_eq!(current_mapping_count(&connection), 1);
        let state: String = connection
            .query_row(
                "SELECT state FROM router_mapping_leases WHERE state = 'releasing'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(state, "releasing");
        assert!(load_heartbeat_candidates(&connection, Some(revision))
            .unwrap()
            .is_empty());
        drop(connection);

        supervisor.shutdown(&data_dir).await.unwrap();
        let counts = counts.lock().unwrap();
        assert_eq!(counts.renewals, 1);
        assert_eq!(counts.releases, 1);
        drop(counts);
        let connection = open_database(&data_dir, false).unwrap();
        assert_eq!(current_mapping_count(&connection), 0);
    }

    #[tokio::test]
    async fn invalidating_renewal_result_is_never_published_as_an_active_lease() {
        let (_temp, data_dir, revision) = mapping_fixture();
        let counts = Arc::new(Mutex::new(BackendCounts::default()));
        let mut supervisor = MappingSupervisor::with_backend(FakeBackend {
            counts: Arc::clone(&counts),
            topology_matches: Arc::new(AtomicBool::new(true)),
            renewal_failure: Some(MappingFailureCode::NonPublicAddress),
        });
        let target = mapping_target(revision);
        supervisor.reconcile(&data_dir, Some(target)).await.unwrap();
        make_renewal_due(&data_dir);

        supervisor.reconcile(&data_dir, Some(target)).await.unwrap();

        assert_eq!(counts.lock().unwrap().renewals, 1);
        let connection = open_database(&data_dir, false).unwrap();
        assert_eq!(current_mapping_count(&connection), 0);
        assert!(load_heartbeat_candidates(&connection, Some(revision))
            .unwrap()
            .is_empty());
        let terminal: (String, String) = connection
            .query_row(
                "SELECT state, failure_code FROM router_mapping_leases
                 ORDER BY created_at DESC, mapping_id DESC LIMIT 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(
            terminal,
            (
                "abandoned".to_string(),
                "mapping_non_public_address".to_string()
            )
        );
        drop(connection);
        let mapping = status(&data_dir).unwrap().router_mapping;
        assert_eq!(mapping.state, RouterMappingState::Failed);
        assert_eq!(
            mapping.last_error_code.as_deref(),
            Some("mapping_non_public_address")
        );
    }

    #[tokio::test]
    async fn topology_change_abandons_without_contacting_the_old_router() {
        let (_temp, data_dir, revision) = mapping_fixture();
        let counts = Arc::new(Mutex::new(BackendCounts::default()));
        let topology_matches = Arc::new(AtomicBool::new(true));
        let mut supervisor = MappingSupervisor::with_backend(FakeBackend {
            counts: Arc::clone(&counts),
            topology_matches: Arc::clone(&topology_matches),
            renewal_failure: None,
        });
        let target = mapping_target(revision);
        supervisor.reconcile(&data_dir, Some(target)).await.unwrap();
        topology_matches.store(false, Ordering::Release);

        supervisor.reconcile(&data_dir, Some(target)).await.unwrap();
        topology_matches.store(true, Ordering::Release);

        let counts = counts.lock().unwrap();
        assert_eq!(counts.creates, 2);
        assert_eq!(counts.releases, 0);
        drop(counts);
        let connection = open_database(&data_dir, false).unwrap();
        let abandoned: (i64, String) = connection
            .query_row(
                "SELECT COUNT(*), MIN(failure_code)
                 FROM router_mapping_leases WHERE state = 'abandoned'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(abandoned, (1, "mapping_topology_changed".to_string()));
        assert_eq!(current_mapping_count(&connection), 1);
        assert_eq!(
            load_heartbeat_candidates(&connection, Some(revision))
                .unwrap()
                .len(),
            1
        );
    }

    struct FailingCreateBackend {
        creates: Arc<AtomicUsize>,
        code: MappingFailureCode,
    }

    #[async_trait]
    impl MappingBackend for FailingCreateBackend {
        fn topology_matches(&self, _mapping: &DurableMapping) -> bool {
            true
        }

        async fn create(
            &mut self,
            _request: &MappingRequest,
        ) -> std::result::Result<CreatedMapping, MappingFailureCode> {
            self.creates.fetch_add(1, Ordering::AcqRel);
            Err(self.code)
        }

        async fn renew(
            &mut self,
            _mapping: &DurableMapping,
        ) -> std::result::Result<CreatedMapping, MappingFailureCode> {
            unreachable!("no mapping exists to renew")
        }

        async fn release(
            &mut self,
            _mapping: &DurableMapping,
        ) -> std::result::Result<(), MappingFailureCode> {
            unreachable!("no mapping exists to release")
        }
    }

    #[tokio::test]
    async fn repeated_mapping_failures_obey_backoff_and_expose_a_stable_code() {
        let (_temp, data_dir, revision) = mapping_fixture();
        let creates = Arc::new(AtomicUsize::new(0));
        let mut supervisor = MappingSupervisor::with_backend(FailingCreateBackend {
            creates: Arc::clone(&creates),
            code: MappingFailureCode::Timeout,
        });
        let target = mapping_target(revision);

        supervisor.reconcile(&data_dir, Some(target)).await.unwrap();
        supervisor.reconcile(&data_dir, Some(target)).await.unwrap();

        assert_eq!(creates.load(Ordering::Acquire), 1);
        let mapping = status(&data_dir).unwrap().router_mapping;
        assert_eq!(mapping.state, RouterMappingState::Failed);
        assert_eq!(mapping.last_error_code.as_deref(), Some("mapping_timeout"));
    }

    #[tokio::test]
    async fn uncertain_cleanup_trips_a_persistent_retry_fuse() {
        let (_temp, data_dir, revision) = mapping_fixture();
        let creates = Arc::new(AtomicUsize::new(0));
        let target = mapping_target(revision);
        let mut first_process = MappingSupervisor::with_backend(FailingCreateBackend {
            creates: Arc::clone(&creates),
            code: MappingFailureCode::ReleaseFailed,
        });
        first_process
            .reconcile(&data_dir, Some(target))
            .await
            .unwrap();

        let mut restarted_process = MappingSupervisor::with_backend(FailingCreateBackend {
            creates: Arc::clone(&creates),
            code: MappingFailureCode::ReleaseFailed,
        });
        restarted_process
            .reconcile(&data_dir, Some(target))
            .await
            .unwrap();

        assert_eq!(creates.load(Ordering::Acquire), 1);
        let mapping = status(&data_dir).unwrap().router_mapping;
        assert_eq!(mapping.state, RouterMappingState::Failed);
        assert_eq!(
            mapping.last_error_code.as_deref(),
            Some("mapping_release_failed")
        );
    }

    fn mapping_fixture() -> (tempfile::TempDir, PathBuf, Revision) {
        let temp = tempfile::tempdir().unwrap();
        let data_dir = temp.path().join("state");
        crate::initialize(&data_dir, "https://controller.example").unwrap();
        configure_bootstrap_policy(&data_dir, true).unwrap();
        let connection = open_database(&data_dir, false).unwrap();
        let node_id = NodeId::new();
        connection
            .execute(
                "INSERT INTO enrollment_registration(
                    singleton, invitation_id, network_id, node_id,
                    controller_instance_id, controller_fingerprint,
                    controller_signing_public_key, credential_key_id,
                    credential_mode, credential_expires_at, enrolled_at
                 ) VALUES (1, ?1, ?2, ?3, ?4, 'fingerprint', 'signing-key',
                           ?5, 'signedRequest', '2027-01-01T00:00:00Z', 1)",
                params![
                    NodeInvitationId::new().to_string(),
                    NetworkId::new().to_string(),
                    node_id.to_string(),
                    ControllerInstanceId::new().to_string(),
                    NodeKeyId::new().to_string(),
                ],
            )
            .unwrap();
        let revision = Revision::new(1).unwrap();
        let digest = format!("sha256:{}", "a".repeat(64));
        connection
            .execute(
                "INSERT INTO desired_state_artifacts(
                    revision, network_id, node_id, controller_instance_id,
                    signing_key_id, envelope_json, envelope_digest,
                    transcript_digest, received_at
                 ) VALUES (?1, ?2, ?3, ?4, ?5, '{}', ?6, ?6, 1)",
                params![
                    revision.get(),
                    NetworkId::new().to_string(),
                    node_id.to_string(),
                    ControllerInstanceId::new().to_string(),
                    SigningKeyId::new().to_string(),
                    digest,
                ],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO rendered_xray_configs(
                    revision, relative_path, config_digest, binary_digest, validated_at
                 ) VALUES (?1, 'configs/test.json', ?2, ?3, 1)",
                params![revision.get(), digest, "b".repeat(64)],
            )
            .unwrap();
        drop(connection);
        (temp, data_dir, revision)
    }

    fn fake_created_mapping() -> CreatedMapping {
        CreatedMapping {
            source: EndpointSource::NatPmp,
            gateway_address: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            internal_address: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)),
            internal_port: 10_443,
            external_address: IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            external_port: 10_443,
            pcp_nonce: None,
            upnp_description: None,
            gateway_epoch: Some(10),
            lifetime_seconds: 3_600,
            topology_fingerprint: [7; 32],
        }
    }

    fn mapping_target(revision: Revision) -> MappingTarget {
        MappingTarget {
            revision,
            internal_port: 10_443,
        }
    }

    fn make_renewal_due(data_dir: &Path) {
        let connection = open_database(data_dir, false).unwrap();
        let now = time::OffsetDateTime::now_utc().unix_timestamp();
        connection
            .execute(
                "UPDATE router_mapping_leases
                 SET lease_started_at = ?1, lease_expires_at = ?2
                 WHERE state = 'active'",
                params![now - 100, now + 1],
            )
            .unwrap();
    }

    fn current_mapping_count(connection: &Connection) -> i64 {
        connection
            .query_row(
                "SELECT COUNT(*) FROM router_mapping_leases
                 WHERE state IN ('active', 'releasing')",
                [],
                |row| row.get(0),
            )
            .unwrap()
    }
}
