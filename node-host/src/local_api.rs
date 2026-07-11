use crate::{HostStatus, RouterMappingStatus};
use anyhow::{Context as _, Result};
#[cfg(target_os = "macos")]
use control_protocol::id::RequestId;
use control_protocol::id::{NodeId, Revision, Timestamp};
use control_protocol::node::NodeRuntimeState;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::path::Path;
use time::OffsetDateTime;
use uuid::Uuid;

pub(crate) const LOCAL_API_SCHEMA_VERSION: u16 = 1;
#[cfg(target_os = "macos")]
pub(crate) const LOCAL_API_REQUEST_MAX_BYTES: usize = 4 * 1024;
#[cfg(target_os = "macos")]
pub(crate) const LOCAL_API_RESPONSE_MAX_BYTES: usize = 32 * 1024;
#[cfg(target_os = "macos")]
pub(crate) const LOCAL_API_SOCKET_FILE: &str = "node-host.sock";

/// Current high-level phase of the local Node Host service process.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum LocalServicePhase {
    /// Service process is recovering durable state.
    Starting,
    /// Service is reconciling with Control.
    Syncing,
    /// No healthy public data path is active.
    Idle,
    /// The managed public data path is healthy.
    Serving,
    /// A legacy or warning state is serving without the full public gate.
    Degraded,
    /// The provider locally paused new traffic.
    Paused,
    /// A local security condition prevents operation.
    Quarantined,
    /// A bounded retry is scheduled after a failed cycle.
    Retrying,
    /// The service is releasing mappings and stopping managed Xray.
    Stopping,
    /// The local runtime has been fully stopped.
    Stopped,
}

impl LocalServicePhase {
    /// Returns the stable wire value.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Starting => "starting",
            Self::Syncing => "syncing",
            Self::Idle => "idle",
            Self::Serving => "serving",
            Self::Degraded => "degraded",
            Self::Paused => "paused",
            Self::Quarantined => "quarantined",
            Self::Retrying => "retrying",
            Self::Stopping => "stopping",
            Self::Stopped => "stopped",
        }
    }
}

impl fmt::Display for LocalServicePhase {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Stable, secret-free failure categories exposed by the local service API.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LocalServiceErrorCode {
    /// Managed Xray recovery failed before the normal loop started.
    XrayRecoveryFailed,
    /// A full sync, activation, or mapping reconciliation cycle failed.
    SyncCycleFailed,
    /// A running Xray or admission-gate health check failed.
    RuntimeHealthFailed,
}

impl LocalServiceErrorCode {
    /// Returns the stable diagnostic value.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::XrayRecoveryFailed => "xray_recovery_failed",
            Self::SyncCycleFailed => "sync_cycle_failed",
            Self::RuntimeHealthFailed => "runtime_health_failed",
        }
    }
}

impl fmt::Display for LocalServiceErrorCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Last safe local service failure, without the underlying error text.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LocalServiceError {
    /// Stable UI and diagnostic contract.
    pub code: LocalServiceErrorCode,
    /// Local observation time for the failure.
    pub occurred_at: Timestamp,
}

impl LocalServiceError {
    pub(crate) fn now(code: LocalServiceErrorCode) -> Self {
        Self {
            code,
            occurred_at: now(),
        }
    }
}

/// Non-secret live Node Host state returned to the same-user owner UI.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LocalServiceStatus {
    /// Local API schema version.
    pub schema_version: u16,
    /// Random identity for this service-process lifetime.
    pub service_instance_id: Uuid,
    /// Time this complete snapshot was observed.
    pub observed_at: Timestamp,
    /// Current service-loop phase.
    pub phase: LocalServicePhase,
    /// Stable enrolled node identity.
    pub node_id: NodeId,
    /// Current managed Xray/admission state.
    pub runtime_state: NodeRuntimeState,
    /// Last heartbeat durably acknowledged by Control.
    pub last_heartbeat_at: Option<Timestamp>,
    /// Last complete synchronization cycle.
    pub last_sync_at: Option<Timestamp>,
    /// Highest desired-state revision durably accepted locally.
    pub desired_revision_cursor: i64,
    /// Last revision that passed local activation health checks.
    pub applied_revision: Option<Revision>,
    /// Latest safe activation-journal phase.
    pub activation_phase: Option<String>,
    /// Whether a checksum-pinned Xray runtime is configured.
    pub xray_configured: bool,
    /// Current provider-owned router mapping state.
    pub router_mapping: RouterMappingStatus,
    /// Last categorized service-loop failure, if it has not yet recovered.
    pub last_error: Option<LocalServiceError>,
}

impl LocalServiceStatus {
    pub(crate) fn from_host(
        service_instance_id: Uuid,
        host: &HostStatus,
        phase: LocalServicePhase,
        runtime_state: NodeRuntimeState,
        last_error: Option<LocalServiceError>,
    ) -> Result<Self> {
        let status = Self {
            schema_version: LOCAL_API_SCHEMA_VERSION,
            service_instance_id,
            observed_at: now(),
            phase,
            node_id: host
                .node_id
                .context("enrolled Node Host status has no node identity")?,
            runtime_state,
            last_heartbeat_at: host.last_heartbeat_at,
            last_sync_at: host.last_sync_at,
            desired_revision_cursor: host.desired_revision_cursor,
            applied_revision: host.applied_revision,
            activation_phase: host.xray_activation_phase.clone(),
            xray_configured: host.xray_configured,
            router_mapping: host.router_mapping.clone(),
            last_error,
        };
        status.validate()?;
        Ok(status)
    }

    pub(crate) fn validate(&self) -> Result<()> {
        if self.schema_version != LOCAL_API_SCHEMA_VERSION {
            anyhow::bail!("unsupported local service status schema");
        }
        if self.desired_revision_cursor < 0 {
            anyhow::bail!("local service desired revision cannot be negative");
        }
        if self.service_instance_id.is_nil() {
            anyhow::bail!("local service instance identity cannot be nil");
        }
        if self
            .activation_phase
            .as_ref()
            .is_some_and(|value| value.is_empty() || value.len() > 64)
            || self
                .router_mapping
                .last_error_code
                .as_ref()
                .is_some_and(|value| value.is_empty() || value.len() > 64)
            || self
                .router_mapping
                .external_address
                .as_ref()
                .is_some_and(|value| value.is_empty() || value.len() > 253)
        {
            anyhow::bail!("local service status contains invalid bounded text");
        }
        match self.phase {
            LocalServicePhase::Serving if self.runtime_state != NodeRuntimeState::Serving => {
                anyhow::bail!("serving phase requires a serving runtime");
            }
            LocalServicePhase::Degraded if self.runtime_state != NodeRuntimeState::Degraded => {
                anyhow::bail!("degraded phase requires a degraded runtime");
            }
            LocalServicePhase::Idle
                if !matches!(
                    self.runtime_state,
                    NodeRuntimeState::Idle | NodeRuntimeState::Pending
                ) =>
            {
                anyhow::bail!("idle phase requires an idle or pending runtime");
            }
            LocalServicePhase::Paused if self.runtime_state != NodeRuntimeState::ProviderPaused => {
                anyhow::bail!("paused phase requires a provider-paused runtime");
            }
            LocalServicePhase::Quarantined
                if self.runtime_state != NodeRuntimeState::Quarantined =>
            {
                anyhow::bail!("quarantined phase requires a quarantined runtime");
            }
            LocalServicePhase::Stopped if self.runtime_state != NodeRuntimeState::Stopped => {
                anyhow::bail!("stopped phase requires a stopped runtime");
            }
            _ => {}
        }
        Ok(())
    }
}

pub(crate) fn phase_for_runtime(runtime_state: NodeRuntimeState) -> LocalServicePhase {
    match runtime_state {
        NodeRuntimeState::Pending | NodeRuntimeState::Idle => LocalServicePhase::Idle,
        NodeRuntimeState::Serving => LocalServicePhase::Serving,
        NodeRuntimeState::ProviderPaused => LocalServicePhase::Paused,
        NodeRuntimeState::Degraded => LocalServicePhase::Degraded,
        NodeRuntimeState::Quarantined => LocalServicePhase::Quarantined,
        NodeRuntimeState::Stopped => LocalServicePhase::Stopped,
    }
}

#[cfg(target_os = "macos")]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) enum LocalApiMethod {
    Status,
}

#[cfg(target_os = "macos")]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct LocalApiRequest {
    pub schema_version: u16,
    pub request_id: RequestId,
    pub method: LocalApiMethod,
}

#[cfg(target_os = "macos")]
impl LocalApiRequest {
    pub(crate) fn status() -> Self {
        Self {
            schema_version: LOCAL_API_SCHEMA_VERSION,
            request_id: RequestId::new(),
            method: LocalApiMethod::Status,
        }
    }
}

#[cfg(target_os = "macos")]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct LocalApiResponse {
    pub schema_version: u16,
    pub request_id: RequestId,
    pub status: LocalServiceStatus,
}

/// Queries the live local Node Host service through its same-user IPC channel.
///
/// This reports process and local data-plane state. Endpoint verification and
/// controller approval remain authoritative at Control and are not inferred
/// from this response.
///
/// # Errors
///
/// Returns an error when the platform is unsupported, the service is not
/// running, socket ownership is unsafe, framing is invalid, the request times
/// out, or the response is not bound to this request.
pub async fn query_local_service_status(data_dir: &Path) -> Result<LocalServiceStatus> {
    #[cfg(target_os = "macos")]
    {
        crate::local_api_macos::query(data_dir).await
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = data_dir;
        anyhow::bail!("the local Node Host status API is not implemented on this platform");
    }
}

#[cfg(target_os = "macos")]
pub(crate) use crate::local_api_macos::LocalStatusServer;

#[cfg(not(target_os = "macos"))]
pub(crate) struct LocalStatusServer;

#[cfg(not(target_os = "macos"))]
impl LocalStatusServer {
    pub(crate) fn start(_data_dir: &Path, _initial: LocalServiceStatus) -> Result<Self> {
        Ok(Self)
    }

    pub(crate) fn publish(&self, status: LocalServiceStatus) -> Result<()> {
        status.validate()
    }

    pub(crate) async fn shutdown(self) -> Result<()> {
        Ok(())
    }
}

fn now() -> Timestamp {
    Timestamp::from_datetime(OffsetDateTime::now_utc())
}
