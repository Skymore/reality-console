use crate::{migrate, open_database, timestamp_from_unix, unix_timestamp, DataDirLock};
use anyhow::{bail, Context as _, Result};
use control_protocol::id::{EndpointId, Revision, Timestamp};
use control_protocol::node::{EndpointCandidate, EndpointMode, EndpointSource};
use rusqlite::{params, Connection, OptionalExtension as _};
use serde::Serialize;
use std::path::Path;
use std::str::FromStr as _;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct RouterMappingPolicy {
    pub enabled: bool,
    pub consented_at: Option<i64>,
    pub allow_permanent_upnp: bool,
}

/// Safe provider-facing router-mapping lifecycle state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
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
                    allow_permanent_upnp
             FROM provider_network_policy WHERE singleton = 1",
            [],
            |row| {
                Ok(RouterMappingPolicy {
                    enabled: row.get::<_, i64>(0)? != 0,
                    consented_at: row.get(1)?,
                    allow_permanent_upnp: row.get::<_, i64>(2)? != 0,
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
             ORDER BY created_at DESC, mapping_id DESC LIMIT 1",
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
        return Ok(empty_status(true, RouterMappingState::Waiting));
    };
    let now = unix_timestamp()?;
    let lifecycle = match state.as_str() {
        "active" if expires_at > now => RouterMappingState::Active,
        "active" => RouterMappingState::Expired,
        "releasing" => RouterMappingState::Releasing,
        "failed" | "abandoned" => RouterMappingState::Failed,
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
        last_error_code: failure_code,
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
    use super::{configure_bootstrap_policy, load_policy, RouterMappingState};
    use crate::{open_database, status};

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
        assert!(!policy.allow_permanent_upnp);
        drop(connection);
        let current = status(&data_dir).unwrap();
        assert!(current.router_mapping.enabled);
        assert_eq!(current.router_mapping.state, RouterMappingState::Waiting);
    }
}
